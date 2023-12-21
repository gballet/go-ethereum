// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package aura

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/misc"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

const DEBUG_LOG_FROM = 999_999_999

var (
	errOlderBlockTime = errors.New("timestamp older than parent")

	allowedFutureBlockTimeSeconds = int64(15) // Max seconds from current time allowed for blocks, before they're considered future blocks
)

/*
Not implemented features from OS:
 - two_thirds_majority_transition - because no chains in OE where this is != MaxUint64 - means 1/2 majority used everywhere
 - emptyStepsTransition - same

Repo with solidity sources: https://github.com/poanetwork/posdao-contracts
*/

type StepDurationInfo struct {
	TransitionStep      uint64
	TransitionTimestamp uint64
	StepDuration        uint64
}

// EpochTransitionProof - Holds 2 proofs inside: ValidatorSetProof and FinalityProof
type EpochTransitionProof struct {
	SignalNumber  uint64
	SetProof      []byte
	FinalityProof []byte
}

// ValidatorSetProof - validator set proof
type ValidatorSetProof struct {
	Header   *types.Header
	Receipts types.Receipts
}

// FirstValidatorSetProof state-dependent proofs for the safe contract:
// only "first" proofs are such.
type FirstValidatorSetProof struct { // TODO: whaaat? here is no state!
	ContractAddress common.Address
	Header          *types.Header
}

type EpochTransition struct {
	/// Block hash at which the transition occurred.
	BlockHash common.Hash
	/// Block number at which the transition occurred.
	BlockNumber uint64
	/// "transition/epoch" proof from the engine combined with a finality proof.
	ProofRlp []byte
}

type Step struct {
	calibrate bool // whether calibration is enabled.
	inner     atomic.Uint64
	// Planned durations of steps.
	durations []StepDurationInfo
}

func (s *Step) doCalibrate() {
	if s.calibrate {
		if !s.optCalibrate() {
			ctr := s.inner.Load()
			panic(fmt.Errorf("step counter under- or overflow: %d", ctr))
		}
	}
}

// optCalibrate Calibrates the AuRa step number according to the current time.
func (s *Step) optCalibrate() bool {
	now := time.Now().Unix()
	var info StepDurationInfo
	i := 0
	for _, d := range s.durations {
		if d.TransitionTimestamp >= uint64(now) {
			break
		}
		info = d
		i++
	}
	if i == 0 {
		panic("durations cannot be empty")
	}

	if uint64(now) < info.TransitionTimestamp {
		return false
	}

	newStep := (uint64(now)-info.TransitionTimestamp)/info.StepDuration + info.TransitionStep
	s.inner.Store(newStep)
	return true
}

type PermissionedStep struct {
	inner      *Step
	canPropose atomic.Bool
}

type ReceivedStepHashes map[uint64]map[common.Address]common.Hash //BTreeMap<(u64, Address), H256>

// nolint
func (r ReceivedStepHashes) get(step uint64, author common.Address) (common.Hash, bool) {
	res, ok := r[step]
	if !ok {
		return common.Hash{}, false
	}
	result, ok := res[author]
	return result, ok
}

// nolint
func (r ReceivedStepHashes) insert(step uint64, author common.Address, blockHash common.Hash) {
	res, ok := r[step]
	if !ok {
		res = map[common.Address]common.Hash{}
		r[step] = res
	}
	res[author] = blockHash
}

// nolint
func (r ReceivedStepHashes) dropAncient(step uint64) {
	for i := range r {
		if i < step {
			delete(r, i)
		}
	}
}

// nolint
type EpochManager struct {
	epochTransitionHash   common.Hash // H256,
	epochTransitionNumber uint64      // BlockNumber
	finalityChecker       *RollingFinality
	force                 bool
}

func NewEpochManager() *EpochManager {
	return &EpochManager{
		finalityChecker: NewRollingFinality([]common.Address{}),
		force:           true,
	}
}

func (e *EpochManager) noteNewEpoch() { e.force = true }

// zoomValidators - Zooms to the epoch after the header with the given hash. Returns true if succeeded, false otherwise.
// It's analog of zoom_to_after function in OE, but doesn't require external locking
// nolint
func (e *EpochManager) zoomToAfter(chain consensus.ChainHeaderReader, er *NonTransactionalEpochReader, validators ValidatorSet, hash common.Hash, call Syscall) (*RollingFinality, uint64, bool) {
	var lastWasParent bool
	if e.finalityChecker.lastPushed != nil {
		lastWasParent = *e.finalityChecker.lastPushed == hash
	}

	// early exit for current target == chain head, but only if the epochs are
	// the same.
	if lastWasParent && !e.force {
		return e.finalityChecker, e.epochTransitionNumber, true
	}
	e.force = false

	// epoch_transition_for can be an expensive call, but in the absence of
	// forks it will only need to be called for the block directly after
	// epoch transition, in which case it will be O(1) and require a single
	// DB lookup.
	lastTransition, ok := epochTransitionFor(chain, er, hash)
	if !ok {
		if lastTransition.BlockNumber > DEBUG_LOG_FROM {
			fmt.Printf("zoom1: %d\n", lastTransition.BlockNumber)
		}
		return e.finalityChecker, e.epochTransitionNumber, false
	}

	// extract other epoch set if it's not the same as the last.
	if lastTransition.BlockHash != e.epochTransitionHash {
		proof := &EpochTransitionProof{}
		if err := rlp.DecodeBytes(lastTransition.ProofRlp, proof); err != nil {
			panic(err)
		}
		first := proof.SignalNumber == 0
		if lastTransition.BlockNumber > DEBUG_LOG_FROM {
			fmt.Printf("zoom2: %d,%d\n", lastTransition.BlockNumber, len(proof.SetProof))
		}

		// use signal number so multi-set first calculation is correct.
		list, _, err := validators.epochSet(first, proof.SignalNumber, proof.SetProof, call)
		if err != nil {
			panic(fmt.Errorf("proof produced by this engine is invalid: %w", err))
		}
		epochSet := list.validators
		log.Trace("[aura] Updating finality checker with new validator set extracted from epoch", "num", lastTransition.BlockNumber)
		e.finalityChecker = NewRollingFinality(epochSet)
		if proof.SignalNumber >= DEBUG_LOG_FROM {
			fmt.Printf("new rolling finality: %d\n", proof.SignalNumber)
			for i := 0; i < len(epochSet); i++ {
				fmt.Printf("\t%x\n", epochSet[i])
			}
		}
	}

	e.epochTransitionHash = lastTransition.BlockHash
	e.epochTransitionNumber = lastTransition.BlockNumber
	return e.finalityChecker, e.epochTransitionNumber, true
}

// / Get the transition to the epoch the given parent hash is part of
// / or transitions to.
// / This will give the epoch that any children of this parent belong to.
// /
// / The block corresponding the the parent hash must be stored already.
// nolint
func epochTransitionFor(chain consensus.ChainHeaderReader, e *NonTransactionalEpochReader, parentHash common.Hash) (transition EpochTransition, ok bool) {
	//TODO: probably this version of func doesn't support non-canonical epoch transitions
	h := chain.GetHeaderByHash(parentHash)
	if h == nil {
		return transition, false
	}
	num, hash, transitionProof, err := e.FindBeforeOrEqualNumber(h.Number.Uint64())
	if err != nil {
		panic(err)
	}
	if transitionProof == nil {
		panic("genesis epoch transition must already be set")
	}
	return EpochTransition{BlockNumber: num, BlockHash: hash, ProofRlp: transitionProof}, true
}

type Syscall func(common.Address, []byte) ([]byte, error)

// AuRa
// nolint
type AuRa struct {
	e      *NonTransactionalEpochReader
	exitCh chan struct{}
	lock   sync.RWMutex // Protects the signer fields

	step PermissionedStep
	// History of step hashes recently received from peers.
	receivedStepHashes ReceivedStepHashes

	cfg           AuthorityRoundParams
	EmptyStepsSet *EmptyStepSet
	EpochManager  *EpochManager // Mutex<EpochManager>,

	certifier     *common.Address // certifies service transactions
	certifierLock sync.RWMutex

	Syscall Syscall

	isPos bool
}

func SortedKeys[K constraints.Ordered, V any](m map[K]V) []K {
	keys := make([]K, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	slices.Sort(keys)
	return keys
}

func NewAuRa(spec *params.AuRaConfig, db ethdb.KeyValueStore) (*AuRa, error) {
	auraParams, err := FromJson(spec)
	if err != nil {
		return nil, err
	}

	if _, ok := auraParams.StepDurations[0]; !ok {
		return nil, fmt.Errorf("authority Round step 0 duration is undefined")
	}
	for _, v := range auraParams.StepDurations {
		if v == 0 {
			return nil, fmt.Errorf("authority Round step duration cannot be 0")
		}
	}
	//shouldTimeout := auraParams.StartStep == nil
	initialStep := uint64(0)
	if auraParams.StartStep != nil {
		initialStep = *auraParams.StartStep
	}
	durations := make([]StepDurationInfo, 0, 1+len(auraParams.StepDurations))
	durInfo := StepDurationInfo{
		TransitionStep:      0,
		TransitionTimestamp: 0,
		StepDuration:        auraParams.StepDurations[0],
	}
	durations = append(durations, durInfo)
	times := SortedKeys(auraParams.StepDurations)
	for i := 1; i < len(auraParams.StepDurations); i++ { // skip first
		time := times[i]
		dur := auraParams.StepDurations[time]
		step, t, ok := nextStepTimeDuration(durInfo, time)
		if !ok {
			return nil, fmt.Errorf("timestamp overflow")
		}
		durInfo.TransitionStep = step
		durInfo.TransitionTimestamp = t
		durInfo.StepDuration = dur
		durations = append(durations, durInfo)
	}
	step := &Step{
		calibrate: auraParams.StartStep == nil,
		durations: durations,
	}
	step.inner.Store(initialStep)
	step.doCalibrate()

	exitCh := make(chan struct{})

	c := &AuRa{
		e:                  newEpochReader(db),
		exitCh:             exitCh,
		step:               PermissionedStep{inner: step},
		cfg:                auraParams,
		receivedStepHashes: ReceivedStepHashes{},
		EpochManager:       NewEpochManager(),
	}
	c.step.canPropose.Store(true)

	return c, nil
}

type epochReader interface {
	GetEpoch(blockHash common.Hash, blockN uint64) (transitionProof []byte, err error)
	GetPendingEpoch(blockHash common.Hash, blockN uint64) (transitionProof []byte, err error)
	FindBeforeOrEqualNumber(number uint64) (blockNum uint64, blockHash common.Hash, transitionProof []byte, err error)
}
type epochWriter interface {
	epochReader
	PutEpoch(blockHash common.Hash, blockN uint64, transitionProof []byte) (err error)
	PutPendingEpoch(blockHash common.Hash, blockN uint64, transitionProof []byte) (err error)
}

type NonTransactionalEpochReader struct {
	db ethdb.KeyValueStore
}

func newEpochReader(db ethdb.KeyValueStore) *NonTransactionalEpochReader {
	return &NonTransactionalEpochReader{db: db}
}

func (cr *NonTransactionalEpochReader) GetEpoch(hash common.Hash, number uint64) (v []byte, err error) {
	return rawdb.ReadEpoch(cr.db, number, hash)
}
func (cr *NonTransactionalEpochReader) PutEpoch(hash common.Hash, number uint64, proof []byte) error {
	return rawdb.WriteEpoch(cr.db, number, hash, proof)
}
func (cr *NonTransactionalEpochReader) GetPendingEpoch(hash common.Hash, number uint64) (v []byte, err error) {
	return rawdb.ReadPendingEpoch(cr.db, number, hash)
}
func (cr *NonTransactionalEpochReader) PutPendingEpoch(hash common.Hash, number uint64, proof []byte) error {
	return rawdb.WritePendingEpoch(cr.db, number, hash, proof)
}
func (cr *NonTransactionalEpochReader) FindBeforeOrEqualNumber(number uint64) (blockNum uint64, blockHash common.Hash, transitionProof []byte, err error) {
	return rawdb.FindEpochBeforeOrEqualNumber(cr.db, number)
}

// A helper accumulator function mapping a step duration and a step duration transition timestamp
// to the corresponding step number and the correct starting second of the step.
func nextStepTimeDuration(info StepDurationInfo, time uint64) (uint64, uint64, bool) {
	stepDiff := time + info.StepDuration
	if stepDiff < 1 {
		return 0, 0, false
	}
	stepDiff -= 1
	if stepDiff < info.TransitionTimestamp {
		return 0, 0, false
	}
	stepDiff -= info.TransitionTimestamp
	if info.StepDuration == 0 {
		return 0, 0, false
	}
	stepDiff /= info.StepDuration
	timeDiff := stepDiff * info.StepDuration
	return info.TransitionStep + stepDiff, info.TransitionTimestamp + timeDiff, true
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
// This is thread-safe (only access the Coinbase of the header)
func (c *AuRa) Author(header *types.Header) (common.Address, error) {
	/*
				 let message = keccak(empty_step_rlp(self.step, &self.parent_hash));
		        let public = publickey::recover(&self.signature.into(), &message)?;
		        Ok(publickey::public_to_address(&public))
	*/
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *AuRa) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	unixNow := time.Now().Unix()
	if header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
		return consensus.ErrFutureBlock
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify the block's gas usage and (if applicable) verify the base fee.

	// Verify that the block number is parent's +1

	// Verify the non-existence of withdrawalsHash.
	if header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}

	// Verify the non-existence of cancun-specific header fields
	switch {
	case header.ExcessBlobGas != nil:
		return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", header.ExcessBlobGas)
	case header.BlobGasUsed != nil:
		return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", header.BlobGasUsed)
	case header.ParentBeaconRoot != nil:
		return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", header.ParentBeaconRoot)
	}

	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	return nil

}

func (c *AuRa) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for _, header := range headers {
			err := c.VerifyHeader(chain, header)

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *AuRa) VerifyUncles(chain consensus.ChainReader, header *types.Block) error {
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *AuRa) Prepare(chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB) error {
	c.verifyGasLimitOverride(chain.Config(), chain, header, statedb)

	// func (c *AuRa) Initialize(config *params.ChainConfig, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []types.Transaction, uncles []*types.Header, syscall consensus.SystemCall) {
	blockNum := header.Number.Uint64()
	for address, rewrittenCode := range c.cfg.RewriteBytecode[blockNum] {
		statedb.SetCode(address, rewrittenCode)
	}

	c.certifierLock.Lock()
	if c.cfg.Registrar != nil && c.certifier == nil && chain.Config().IsLondon(header.Number) {
		c.certifier = getCertifier(*c.cfg.Registrar, c.Syscall)
	}
	c.certifierLock.Unlock()

	if blockNum == 1 {
		proof, err := c.GenesisEpochData(header)
		if err != nil {
			panic(err)
		}
		err = c.e.PutEpoch(header.ParentHash, 0, proof) //TODO: block 0 hardcoded - need fix it inside validators
		if err != nil {
			panic(err)
		}
	}

	// check_and_lock_block -> check_epoch_end_signal

	epoch, err := c.e.GetEpoch(header.ParentHash, blockNum-1)
	if err != nil {
		return err
	}
	isEpochBegin := epoch != nil
	if !isEpochBegin {
		return nil
	}
	return c.cfg.Validators.onEpochBegin(isEpochBegin, header, c.Syscall)
	// check_and_lock_block -> check_epoch_end_signal END (before enact)

}

func (c *AuRa) ApplyRewards(header *types.Header, state vm.StateDB) error {
	rewards, err := c.CalculateRewards(nil, header, nil)
	if err != nil {
		return err
	}
	for _, r := range rewards {
		state.AddBalance(r.Beneficiary, uint256.MustFromBig(&r.Amount), tracing.BalanceIncreaseRewardMineBlock)
	}
	return nil
}

// word `signal epoch` == word `pending epoch`
func (c *AuRa) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body, receipts []*types.Receipt) {
	if err := c.ApplyRewards(header, state); err != nil {
		panic(err)
	}

	// check_and_lock_block -> check_epoch_end_signal (after enact)
	if header.Number.Uint64() >= DEBUG_LOG_FROM {
		fmt.Printf("finalize1: %d,%d\n", header.Number.Uint64(), len(receipts))
	}
	pendingTransitionProof, err := c.cfg.Validators.signalEpochEnd(header.Number.Uint64() == 0, header, receipts)
	if err != nil {
		panic(err)
	}
	if pendingTransitionProof != nil {
		if header.Number.Uint64() >= DEBUG_LOG_FROM {
			fmt.Printf("insert_pending_transition: %d,receipts=%d, lenProof=%d\n", header.Number.Uint64(), len(receipts), len(pendingTransitionProof))
		}
		if err = c.e.PutPendingEpoch(header.Hash(), header.Number.Uint64(), pendingTransitionProof); err != nil {
			panic(err)
		}
	}
	// check_and_lock_block -> check_epoch_end_signal END

	finalized := buildFinality(c.EpochManager, chain, c.e, c.cfg.Validators, header, c.Syscall)
	c.EpochManager.finalityChecker.print(header.Number.Uint64())
	epochEndProof, err := isEpochEnd(chain, c.e, finalized, header)
	if err != nil {
		panic(err)
	}
	if epochEndProof != nil {
		c.EpochManager.noteNewEpoch()
		log.Info("[aura] epoch transition", "block_num", header.Number.Uint64())
		if err := c.e.PutEpoch(header.Hash(), header.Number.Uint64(), epochEndProof); err != nil {
			panic(err)
		}
	}
}

func buildFinality(e *EpochManager, chain consensus.ChainHeaderReader, er *NonTransactionalEpochReader, validators ValidatorSet, header *types.Header, syscall Syscall) []unAssembledHeader {
	// commit_block -> aura.build_finality
	_, _, ok := e.zoomToAfter(chain, er, validators, header.ParentHash, syscall)
	if !ok {
		return []unAssembledHeader{}
	}
	if e.finalityChecker.lastPushed == nil || *e.finalityChecker.lastPushed != header.ParentHash {
		if err := e.finalityChecker.buildAncestrySubChain(func(hash common.Hash) ([]common.Address, common.Hash, common.Hash, uint64, bool) {
			h := chain.GetHeaderByHash(hash)
			if h == nil {
				return nil, common.Hash{}, common.Hash{}, 0, false
			}
			return []common.Address{h.Coinbase}, h.Hash(), h.ParentHash, h.Number.Uint64(), true
		}, header.ParentHash, e.epochTransitionHash); err != nil {
			//log.Warn("[aura] buildAncestrySubChain", "err", err)
			return []unAssembledHeader{}
		}
	}

	res, err := e.finalityChecker.push(header.Hash(), header.Number.Uint64(), []common.Address{header.Coinbase})
	if err != nil {
		//log.Warn("[aura] finalityChecker.push", "err", err)
		return []unAssembledHeader{}
	}
	return res
}

func isEpochEnd(chain consensus.ChainHeaderReader, e *NonTransactionalEpochReader, finalized []unAssembledHeader, header *types.Header) ([]byte, error) {
	// commit_block -> aura.is_epoch_end
	for i := range finalized {
		pendingTransitionProof, err := e.GetPendingEpoch(finalized[i].hash, finalized[i].number)
		// GNOSIS: pebble returns an error when a non-existent value
		// isn't found, which is what happens at genesis.
		if err != nil && !errors.Is(err, pebble.ErrNotFound) {
			return nil, err
		}
		if pendingTransitionProof == nil {
			continue
		}
		if header.Number.Uint64() >= DEBUG_LOG_FROM {
			fmt.Printf("pending transition: %d,%x,len=%d\n", finalized[i].number, finalized[i].hash, len(pendingTransitionProof))
		}

		finalityProof := allHeadersUntil(chain, header, finalized[i].hash)
		var finalizedHeader *types.Header
		if finalized[i].hash == header.Hash() {
			finalizedHeader = header
		} else {
			finalizedHeader = chain.GetHeader(finalized[i].hash, finalized[i].number)
		}
		signalNumber := finalizedHeader.Number
		finalityProof = append(finalityProof, finalizedHeader)
		for i, j := 0, len(finalityProof)-1; i < j; i, j = i+1, j-1 { // reverse
			finalityProof[i], finalityProof[j] = finalityProof[j], finalityProof[i]
		}
		finalityProofRLP, err := rlp.EncodeToBytes(finalityProof)
		if err != nil {
			return nil, err
		}
		/*
			// We turn off can_propose here because upon validator set change there can
			// be two valid proposers for a single step: one from the old set and
			// one from the new.
			//
			// This way, upon encountering an epoch change, the proposer from the
			// new set will be forced to wait until the next step to avoid sealing a
			// block that breaks the invariant that the parent's step < the block's step.
			self.step.can_propose.store(false, AtomicOrdering::SeqCst);
		*/
		return rlp.EncodeToBytes(EpochTransitionProof{SignalNumber: signalNumber.Uint64(), SetProof: pendingTransitionProof, FinalityProof: finalityProofRLP})
	}
	return nil, nil
}

// allHeadersUntil walk the chain backwards from current head until finalized_hash
// to construct transition proof. author == ec_recover(sig) known
// since the blocks are in the DB.
func allHeadersUntil(chain consensus.ChainHeaderReader, from *types.Header, to common.Hash) (out []*types.Header) {
	var header = from
	for {
		header = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
		if header == nil {
			panic("not found header")
		}
		if header.Number.Uint64() == 0 {
			break
		}
		if to == header.Hash() {
			break
		}
		out = append(out, header)
	}
	return out
}

// FinalizeAndAssemble implements consensus.Engine
func (c *AuRa) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	c.Finalize(chain, header, state, body, receipts)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, body, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *AuRa) Authorize(signer common.Address) {
	c.lock.Lock()
	defer c.lock.Unlock()

	//c.signer = signer
	//c.signFn = signFn
}

func (c *AuRa) GenesisEpochData(header *types.Header) ([]byte, error) {
	setProof, err := c.cfg.Validators.genesisEpochData(header, c.Syscall)
	if err != nil {
		return nil, err
	}
	res, err := rlp.EncodeToBytes(EpochTransitionProof{SignalNumber: 0, SetProof: setProof, FinalityProof: []byte{}})
	if err != nil {
		panic(err)
	}
	return res, nil
}

func (c *AuRa) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
}

func (c *AuRa) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	currentStep := c.step.inner.inner.Load()
	currentEmptyStepsLen := 0
	return calculateScore(parent.Step, currentStep, uint64(currentEmptyStepsLen)).ToBig()
}

// calculateScore - analog of PoW difficulty:
//
//	sqrt(U256::max_value()) + parent_step - current_step + current_empty_steps
func calculateScore(parentStep, currentStep, currentEmptySteps uint64) *uint256.Int {
	maxU128 := uint256.NewInt(0).SetAllOne()
	maxU128 = maxU128.Rsh(maxU128, 128)
	res := maxU128.Add(maxU128, uint256.NewInt(parentStep))
	res = res.Sub(res, uint256.NewInt(currentStep))
	res = res.Add(res, uint256.NewInt(currentEmptySteps))
	return res
}

func (c *AuRa) SealHash(header *types.Header) common.Hash {
	return clique.SealHash(header)
}

// See https://openethereum.github.io/Permissioning.html#gas-price
// This is thread-safe: it only accesses the `certifier` which is used behind a RWLock
func (c *AuRa) IsServiceTransaction(sender common.Address) bool {
	c.certifierLock.RLock()
	defer c.certifierLock.RUnlock()
	if c.certifier == nil {
		return false
	}
	packed, err := certifierAbi().Pack("certified", sender)
	if err != nil {
		panic(err)
	}
	out, err := c.Syscall(*c.certifier, packed)
	if err != nil {
		panic(err)
	}
	res, err := certifierAbi().Unpack("certified", out)
	if err != nil {
		log.Warn("error while detecting service tx on AuRa", "err", err)
		return false
	}
	if len(res) == 0 {
		return false
	}
	if certified, ok := res[0].(bool); ok {
		return certified
	}
	return false
}

func SafeClose(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
		// Channel was already closed
	default:
		close(ch)
	}
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (c *AuRa) Close() error {
	SafeClose(c.exitCh)
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *AuRa) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{
		//{
		//Namespace: "clique",
		//Version:   "1.0",
		//Service:   &API{chain: chain, clique: c},
		//Public:    false,
		//}
	}
}

// nolint
func (c *AuRa) emptySteps(fromStep, toStep uint64, parentHash common.Hash) []EmptyStep {
	from := EmptyStep{step: fromStep + 1, parentHash: parentHash}
	to := EmptyStep{step: toStep}
	res := []EmptyStep{}
	if to.LessOrEqual(&from) {
		return res
	}

	c.EmptyStepsSet.Sort()
	c.EmptyStepsSet.ForEach(func(i int, step *EmptyStep) {
		if step.Less(&from) || (&to).Less(step) {
			return
		}
		if step.parentHash != parentHash {
			return
		}
		res = append(res, *step)
	})
	return res
}

func (c *AuRa) CalculateRewards(_ *params.ChainConfig, header *types.Header, _ []*types.Header) ([]consensus.Reward, error) {
	var rewardContractAddress BlockRewardContract
	var foundContract bool
	for _, c := range c.cfg.BlockRewardContractTransitions {
		if c.blockNum > header.Number.Uint64() {
			break
		}
		foundContract = true
		rewardContractAddress = c
	}
	if foundContract {
		beneficiaries := []common.Address{header.Coinbase}
		rewardKind := []consensus.RewardKind{consensus.RewardAuthor}
		var amounts []*big.Int
		beneficiaries, amounts = callBlockRewardAbi(rewardContractAddress.address, c.Syscall, beneficiaries, rewardKind)
		rewards := make([]consensus.Reward, len(amounts))
		for i, amount := range amounts {
			rewards[i].Beneficiary = beneficiaries[i]
			rewards[i].Kind = consensus.RewardExternal
			rewards[i].Amount = *amount
		}
		return rewards, nil
	}

	// block_reward.iter.rev().find(|&(block, _)| *block <= number)
	var reward BlockReward
	var found bool
	for i := range c.cfg.BlockReward {
		if c.cfg.BlockReward[i].blockNum > header.Number.Uint64() {
			break
		}
		found = true
		reward = c.cfg.BlockReward[i]
	}
	if !found {
		return nil, errors.New("Current block's reward is not found; this indicates a chain config error")
	}

	r := consensus.Reward{Beneficiary: header.Coinbase, Kind: consensus.RewardAuthor, Amount: *reward.amount.ToBig()}
	return []consensus.Reward{r}, nil
}

// See https://github.com/gnosischain/specs/blob/master/execution/withdrawals.md
func (c *AuRa) ExecuteSystemWithdrawals(withdrawals []*types.Withdrawal) error {
	if c.cfg.WithdrawalContractAddress == nil {
		return nil
	}

	maxFailedWithdrawalsToProcess := big.NewInt(4)
	amounts := make([]uint64, 0, len(withdrawals))
	addresses := make([]common.Address, 0, len(withdrawals))
	for _, w := range withdrawals {
		amounts = append(amounts, w.Amount)
		addresses = append(addresses, w.Address)
	}

	packed, err := withdrawalAbi().Pack("executeSystemWithdrawals", maxFailedWithdrawalsToProcess, amounts, addresses)
	if err != nil {
		return err
	}

	_, err = c.Syscall(*c.cfg.WithdrawalContractAddress, packed)
	if err != nil {
		log.Warn("ExecuteSystemWithdrawals", "err", err)
	}
	return err
}

func (c *AuRa) SetMerged(merged bool) {
	c.isPos = merged
}

// An empty step message that is included in a seal, the only difference is that it doesn't include
// the `parent_hash` in order to save space. The included signature is of the original empty step
// message, which can be reconstructed by using the parent hash of the block in which this sealed
// empty message is included.
// nolint
type SealedEmptyStep struct {
	signature []byte // H520
	step      uint64
}

// A message broadcast by authorities when it's their turn to seal a block but there are no
// transactions. Other authorities accumulate these messages and later include them in the seal as
// proof.
//
// An empty step message is created _instead of_ a block if there are no pending transactions.
// It cannot itself be a parent, and `parent_hash` always points to the most recent block. E.g.:
//   - Validator A creates block `bA`.
//   - Validator B has no pending transactions, so it signs an empty step message `mB`
//     instead whose hash points to block `bA`.
//   - Validator C also has no pending transactions, so it also signs an empty step message `mC`
//     instead whose hash points to block `bA`.
//   - Validator D creates block `bD`. The parent is block `bA`, and the header includes `mB` and `mC`.
type EmptyStep struct {
	// The signature of the other two fields, by the message's author.
	signature []byte // H520
	// This message's step number.
	step uint64
	// The hash of the most recent block.
	parentHash common.Hash //     H256
}

func (s *EmptyStep) Less(other *EmptyStep) bool {
	if s.step < other.step {
		return true
	}
	if bytes.Compare(s.parentHash[:], other.parentHash[:]) < 0 {
		return true
	}
	if bytes.Compare(s.signature, other.signature) < 0 {
		return true
	}
	return false
}
func (s *EmptyStep) LessOrEqual(other *EmptyStep) bool {
	if s.step <= other.step {
		return true
	}
	if bytes.Compare(s.parentHash[:], other.parentHash[:]) <= 0 {
		return true
	}
	if bytes.Compare(s.signature, other.signature) <= 0 {
		return true
	}
	return false
}

type EmptyStepSet struct {
	lock sync.Mutex
	list []*EmptyStep
}

func (s *EmptyStepSet) Less(i, j int) bool { return s.list[i].Less(s.list[j]) }
func (s *EmptyStepSet) Swap(i, j int)      { s.list[i], s.list[j] = s.list[j], s.list[i] }
func (s *EmptyStepSet) Len() int           { return len(s.list) }

func (s *EmptyStepSet) Sort() {
	s.lock.Lock()
	defer s.lock.Unlock()
	sort.Stable(s)
}

func (s *EmptyStepSet) ForEach(f func(int, *EmptyStep)) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for i, el := range s.list {
		f(i, el)
	}
}

func EmptyStepFullRlp(signature []byte, emptyStepRlp []byte) ([]byte, error) {
	type A struct {
		s []byte
		r []byte
	}

	return rlp.EncodeToBytes(A{s: signature, r: emptyStepRlp})
}

func EmptyStepRlp(step uint64, parentHash common.Hash) ([]byte, error) {
	type A struct {
		s uint64
		h common.Hash
	}
	return rlp.EncodeToBytes(A{s: step, h: parentHash})
}

// nolint
type unAssembledHeader struct {
	hash    common.Hash
	number  uint64
	signers []common.Address
}
type unAssembledHeaders struct {
	l *list.List
}

func (u unAssembledHeaders) PushBack(header *unAssembledHeader)  { u.l.PushBack(header) }
func (u unAssembledHeaders) PushFront(header *unAssembledHeader) { u.l.PushFront(header) }
func (u unAssembledHeaders) Pop() *unAssembledHeader {
	e := u.l.Front()
	if e == nil {
		return nil
	}
	u.l.Remove(e)
	return e.Value.(*unAssembledHeader)
}
func (u unAssembledHeaders) Front() *unAssembledHeader {
	e := u.l.Front()
	if e == nil {
		return nil
	}
	return e.Value.(*unAssembledHeader)
}

// RollingFinality checker for authority round consensus.
// Stores a chain of unfinalized hashes that can be pushed onto.
// nolint
type RollingFinality struct {
	headers    unAssembledHeaders //nolint
	signers    *SimpleList
	signCount  map[common.Address]uint
	lastPushed *common.Hash // Option<H256>,
}

// NewRollingFinality creates a blank finality checker under the given validator set.
func NewRollingFinality(signers []common.Address) *RollingFinality {
	return &RollingFinality{
		signers:   NewSimpleList(signers),
		headers:   unAssembledHeaders{l: list.New()},
		signCount: map[common.Address]uint{},
	}
}

// Clears the finality status, but keeps the validator set.
func (f *RollingFinality) print(num uint64) {
	if num > DEBUG_LOG_FROM {
		h := f.headers
		i := 0
		for e := h.l.Front(); e != nil; e = e.Next() {
			i++
			a := e.Value.(*unAssembledHeader)
			fmt.Printf("\t%d,%x\n", a.number, a.signers[0])
		}
		if i == 0 {
			fmt.Printf("\tempty\n")
		}
	}
}

func (f *RollingFinality) clear() {
	f.headers = unAssembledHeaders{l: list.New()}
	f.signCount = map[common.Address]uint{}
	f.lastPushed = nil
}

// Push a hash onto the rolling finality checker (implying `subchain_head` == head.parent)
//
// Fails if `signer` isn't a member of the active validator set.
// Returns a list of all newly finalized headers.
func (f *RollingFinality) push(head common.Hash, num uint64, signers []common.Address) (newlyFinalized []unAssembledHeader, err error) {
	for i := range signers {
		if !f.hasSigner(signers[i]) {
			return nil, fmt.Errorf("unknown validator")
		}
	}

	f.addSigners(signers)
	f.headers.PushBack(&unAssembledHeader{hash: head, number: num, signers: signers})

	for f.isFinalized() {
		e := f.headers.Pop()
		if e == nil {
			panic("headers length always greater than sign count length")
		}
		f.removeSigners(e.signers)
		newlyFinalized = append(newlyFinalized, *e)
	}
	f.lastPushed = &head
	return newlyFinalized, nil
}

// isFinalized returns whether the first entry in `self.headers` is finalized.
func (f *RollingFinality) isFinalized() bool {
	e := f.headers.Front()
	if e == nil {
		return false
	}
	return len(f.signCount)*2 > len(f.signers.validators)
}
func (f *RollingFinality) hasSigner(signer common.Address) bool {
	for j := range f.signers.validators {
		if f.signers.validators[j] == signer {
			return true

		}
	}
	return false
}
func (f *RollingFinality) addSigners(signers []common.Address) bool {
	for i := range signers {
		count, ok := f.signCount[signers[i]]
		if ok {
			f.signCount[signers[i]] = count + 1
		} else {
			f.signCount[signers[i]] = 1
		}
	}
	return false
}
func (f *RollingFinality) removeSigners(signers []common.Address) {
	for i := range signers {
		count, ok := f.signCount[signers[i]]
		if !ok {
			panic("all hashes in `header` should have entries in `sign_count` for their signers")
			//continue
		}
		if count <= 1 {
			delete(f.signCount, signers[i])
		} else {
			f.signCount[signers[i]] = count - 1
		}
	}
}
func (f *RollingFinality) buildAncestrySubChain(get func(hash common.Hash) ([]common.Address, common.Hash, common.Hash, uint64, bool), parentHash, epochTransitionHash common.Hash) error { // starts from chainHeadParentHash
	f.clear()

	for {
		signers, blockHash, newParentHash, blockNum, ok := get(parentHash)
		if !ok {
			return nil
		}
		if blockHash == epochTransitionHash {
			return nil
		}
		for i := range signers {
			if !f.hasSigner(signers[i]) {
				return fmt.Errorf("unknown validator: blockNum=%d", blockNum)
			}
		}
		if f.lastPushed == nil {
			copyHash := parentHash
			f.lastPushed = &copyHash
		}
		f.addSigners(signers)
		f.headers.PushFront(&unAssembledHeader{hash: blockHash, number: blockNum, signers: signers})
		// break when we've got our first finalized block.
		if f.isFinalized() {
			e := f.headers.Pop()
			if e == nil {
				panic("we just pushed a block")
			}
			f.removeSigners(e.signers)
			//log.Info("[aura] finality encountered already finalized block", "hash", e.hash.String(), "number", e.number)
			break
		}

		parentHash = newParentHash
	}
	return nil
}
