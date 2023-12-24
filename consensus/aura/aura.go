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

	// "github.com/ethereum/erigon-lib/kv"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/aura/contracts"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru/v2"
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
func (e *EpochManager) zoomToAfter(chain consensus.ChainHeaderReader, er *NonTransactionalEpochReader, validators ValidatorSet, hash common.Hash, call syscall) (*RollingFinality, uint64, bool) {
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

type syscall func(common.Address, []byte) ([]byte, error)

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

	Syscall syscall
}

type GasLimitOverride struct {
	cache *lru.Cache[common.Hash, *uint256.Int]
}

func NewGasLimitOverride() *GasLimitOverride {
	// The number of recent block hashes for which the gas limit override is memoized.
	const GasLimitOverrideCacheCapacity = 10

	cache, err := lru.New[common.Hash, *uint256.Int](GasLimitOverrideCacheCapacity)
	if err != nil {
		panic("error creating prefetching cache for blocks")
	}
	return &GasLimitOverride{cache: cache}
}

func (pb *GasLimitOverride) Pop(hash common.Hash) *uint256.Int {
	if val, ok := pb.cache.Get(hash); ok && val != nil {
		pb.cache.Remove(hash)
		return val
	}
	return nil
}

func (pb *GasLimitOverride) Add(hash common.Hash, b *uint256.Int) {
	if b == nil {
		return
	}
	pb.cache.ContainsOrAdd(hash, b)
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

	/*
		    let engine = Arc::new(AuthorityRound {
		        epoch_manager: Mutex::new(EpochManager::blank()),
		        received_step_hashes: RwLock::new(Default::default()),
		        gas_limit_override_cache: Mutex::new(LruCache::new(GAS_LIMIT_OVERRIDE_CACHE_CAPACITY)),
		    })
			// Do not initialize timeouts for tests.
		    if should_timeout {
		        let handler = TransitionHandler {
		            step: engine.step.clone(),
		            client: engine.client.clone(),
		        };
		        engine
		            .transition_service
		            .register_handler(Arc::new(handler))?;
		    }
	*/

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

// Type returns underlying consensus engine
// func (c *AuRa) Type() chain.ConsensusName {
// 	return chain.AuRaConsensus
// }

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
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		log.Error("consensus.ErrUnknownAncestor", "parentNum", number-1, "hash", header.ParentHash.String())
		return consensus.ErrUnknownAncestor
	}
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	unixNow := time.Now().Unix()
	if header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
		return consensus.ErrFutureBlock
	}
	if header.Time <= parent.Time {
		return errOlderBlockTime
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
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		// Verify that the gas limit remains within allowed bounds
		diff := int64(parent.GasLimit) - int64(header.GasLimit)
		if diff < 0 {
			diff *= -1
		}
		limit := parent.GasLimit / params.GasLimitBoundDivisor
		if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
			return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
		}
	} else if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}

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

// nolint
func (c *AuRa) hasReceivedStepHashes(step uint64, author common.Address, newHash common.Hash) bool {
	/*
		self
			       .received_step_hashes
			       .read()
			       .get(&received_step_key)
			       .map_or(false, |h| *h != new_hash)
	*/
	return false
}

// nolint
func (c *AuRa) insertReceivedStepHashes(step uint64, author common.Address, newHash common.Hash) {
	/*
	   	    self.received_step_hashes
	                      .write()
	                      .insert(received_step_key, new_hash);
	*/
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *AuRa) VerifyUncles(chain consensus.ChainReader, header *types.Block) error {
	return nil
	//if len(uncles) > 0 {
	//	return errors.New("uncles not allowed")
	//}
	//return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
// func (c *AuRa) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
// return nil
//snap, err := c.Snapshot(chain, header.Number.Uint64(), header.Hash(), nil)
//if err != nil {
//	return err
//}
//return c.verifySeal(chain, header, snap)
// }

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *AuRa) Prepare(chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB) error {
	// return nil
	/// If the block isn't a checkpoint, cast a random vote (good enough for now)
	//header.Coinbase = common.Address{}
	//header.Nonce = types.BlockNonce{}
	//
	//number := header.Number.Uint64()
	/// Assemble the voting snapshot to check which votes make sense
	//snap, err := c.Snapshot(chain, number-1, header.ParentHash, nil)
	//if err != nil {
	//	return err
	//}
	//if number%c.config.Epoch != 0 {
	//	c.lock.RLock()
	//
	//	// Gather all the proposals that make sense voting on
	//	addresses := make([]common.Address, 0, len(c.proposals))
	//	for address, authorize := range c.proposals {
	//		if snap.validVote(address, authorize) {
	//			addresses = append(addresses, address)
	//		}
	//	}
	//	// If there's pending proposals, cast a vote on them
	//	if len(addresses) > 0 {
	//		header.Coinbase = addresses[rand.Intn(len(addresses))]
	//		if c.proposals[header.Coinbase] {
	//			copy(header.Nonce[:], NonceAuthVote)
	//		} else {
	//			copy(header.Nonce[:], nonceDropVote)
	//		}
	//	}
	//	c.lock.RUnlock()
	//}
	/// Set the correct difficulty
	//header.Difficulty = calcDifficulty(snap, c.signer)
	//
	/// Ensure the extra data has all its components
	//if len(header.Extra) < ExtraVanity {
	//	header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, ExtraVanity-len(header.Extra))...)
	//}
	//header.Extra = header.Extra[:ExtraVanity]
	//
	//if number%c.config.Epoch == 0 {
	//	for _, signer := range snap.GetSigners() {
	//		header.Extra = append(header.Extra, signer[:]...)
	//	}
	//}
	//header.Extra = append(header.Extra, make([]byte, ExtraSeal)...)
	//
	/// Mix digest is reserved for now, set to empty
	//header.MixDigest = common.Hash{}
	//
	/// Ensure the timestamp has the correct delay
	//parent := chain.GetHeader(header.ParentHash, number-1)
	//if parent == nil {
	//	return consensus.ErrUnknownAncestor
	//}
	//header.Time = parent.Time + c.config.Period
	//
	//now := uint64(time.Now().Unix())
	//if header.Time < now {
	//	header.Time = now
	//}
	//
	//return nil
	// }

	// func (c *AuRa) Initialize(config *params.ChainConfig, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []types.Transaction, uncles []*types.Header, syscall consensus.SystemCall) {
	blockNum := header.Number.Uint64()
	for address, rewrittenCode := range c.cfg.RewriteBytecode[blockNum] {
		fmt.Println("for future debug: rewriting code", blockNum, address)
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

	//if err := c.verifyFamily(chain, e, header, call, syscall); err != nil { //TODO: OE has it as a separate engine call? why?
	//	panic(err)
	//}

	// check_and_lock_block -> check_epoch_end_signal

	epoch, err := c.e.GetEpoch(header.ParentHash, blockNum-1)
	if err != nil {
		log.Warn("[aura] initialize block: on epoch begin", "err", err)
		return err
	}
	isEpochBegin := epoch != nil
	if !isEpochBegin {
		return nil
	}
	return c.cfg.Validators.onEpochBegin(isEpochBegin, header, c.Syscall)
	// check_and_lock_block -> check_epoch_end_signal END (before enact)

}

func (c *AuRa) applyRewards(header *types.Header, state *state.StateDB) error {
	rewards, err := c.CalculateRewards(nil, header, nil)
	if err != nil {
		return err
	}
	for _, r := range rewards {
		state.AddBalance(r.Beneficiary, &r.Amount)
	}
	return nil
}

// word `signal epoch` == word `pending epoch`
func (c *AuRa) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal, receipts []*types.Receipt) {
	if err := c.applyRewards(header, state); err != nil {
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

func buildFinality(e *EpochManager, chain consensus.ChainHeaderReader, er *NonTransactionalEpochReader, validators ValidatorSet, header *types.Header, syscall syscall) []unAssembledHeader {
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
		if err != nil {
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

//func (c *AuRa) check_epoch_end(cc *params.ChainConfig, header *types.Header, state *state.StateDB, txs []types.Transaction, uncles []*types.Header, syscall consensus.SystemCall) {
//}

// FinalizeAndAssemble implements consensus.Engine
func (c *AuRa) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	c.Finalize(chain, header, state, txs, uncles, withdrawals, receipts)

	// Assemble and return the final block for sealing
	return types.NewBlockWithWithdrawals(header, txs, uncles, receipts, withdrawals, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *AuRa) Authorize(signer common.Address, signFn clique.SignerFn) {
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
	//fmt.Printf("reere: %x\n", res)
	//f91a84f9020da00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0fad4af258fd11939fae0c6c6eec9d340b1caac0b0196fd9a1bc3f489c5bf00b3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000830200008083663be080808080b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f91871b914c26060604052600436106100fc576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806303aca79214610101578063108552691461016457806340a141ff1461019d57806340c9cdeb146101d65780634110a489146101ff57806345199e0a1461025757806349285b58146102c15780634d238c8e14610316578063752862111461034f578063900eb5a8146103645780639a573786146103c7578063a26a47d21461041c578063ae4b1b5b14610449578063b3f05b971461049e578063b7ab4db5146104cb578063d3e848f114610535578063fa81b2001461058a578063facd743b146105df575b600080fd5b341561010c57600080fd5b6101226004808035906020019091905050610630565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561016f57600080fd5b61019b600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190505061066f565b005b34156101a857600080fd5b6101d4600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610807565b005b34156101e157600080fd5b6101e9610bb7565b6040518082815260200191505060405180910390f35b341561020a57600080fd5b610236600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610bbd565b60405180831515151581526020018281526020019250505060405180910390f35b341561026257600080fd5b61026a610bee565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156102ad578082015181840152602081019050610292565b505050509050019250505060405180910390f35b34156102cc57600080fd5b6102d4610c82565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561032157600080fd5b61034d600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610d32565b005b341561035a57600080fd5b610362610fcc565b005b341561036f57600080fd5b61038560048080359060200190919050506110fc565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156103d257600080fd5b6103da61113b565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561042757600080fd5b61042f6111eb565b604051808215151515815260200191505060405180910390f35b341561045457600080fd5b61045c6111fe565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156104a957600080fd5b6104b1611224565b604051808215151515815260200191505060405180910390f35b34156104d657600080fd5b6104de611237565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b83811015610521578082015181840152602081019050610506565b505050509050019250505060405180910390f35b341561054057600080fd5b6105486112cb565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561059557600080fd5b61059d6112f1565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156105ea57600080fd5b610616600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050611317565b604051808215151515815260200191505060405180910390f35b60078181548110151561063f57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156106cb57600080fd5b600460019054906101000a900460ff161515156106e757600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415151561072357600080fd5b80600a60006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001600460016101000a81548160ff0219169083151502179055507f600bcf04a13e752d1e3670a5a9f1c21177ca2a93c6f5391d4f1298d098097c22600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a150565b600080600061081461113b565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561084d57600080fd5b83600960008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1615156108a957600080fd5b600960008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101549350600160078054905003925060078381548110151561090857fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691508160078581548110151561094657fe5b906000526020600020900160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555083600960008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506007838154811015156109e557fe5b906000526020600020900160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556000600780549050111515610a2757600080fd5b6007805480919060019003610a3c9190611370565b506000600960008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506000600960008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548160ff0219169083151502179055506000600460006101000a81548160ff0219169083151502179055506001430340600019167f55252fa6eee4741b4e24a74a70e9c11fd2c2281df8d6ea13126ff845f7825c89600760405180806020018281038252838181548152602001915080548015610ba257602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610b58575b50509250505060405180910390a25050505050565b60085481565b60096020528060005260406000206000915090508060000160009054906101000a900460ff16908060010154905082565b610bf661139c565b6007805480602002602001604051908101604052809291908181526020018280548015610c7857602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610c2e575b5050505050905090565b6000600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166349285b586000604051602001526040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b1515610d1257600080fd5b6102c65a03f11515610d2357600080fd5b50505060405180519050905090565b610d3a61113b565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610d7357600080fd5b80600960008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff16151515610dd057600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610e0c57600080fd5b6040805190810160405280600115158152602001600780549050815250600960008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548160ff0219169083151502179055506020820151816001015590505060078054806001018281610ea991906113b0565b9160005260206000209001600084909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506000600460006101000a81548160ff0219169083151502179055506001430340600019167f55252fa6eee4741b4e24a74a70e9c11fd2c2281df8d6ea13126ff845f7825c89600760405180806020018281038252838181548152602001915080548015610fba57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610f70575b50509250505060405180910390a25050565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161480156110365750600460009054906101000a900460ff16155b151561104157600080fd5b6001600460006101000a81548160ff0219169083151502179055506007600690805461106e9291906113dc565b506006805490506008819055507f8564cd629b15f47dc310d45bcbfc9bcf5420b0d51bf0659a16c67f91d27632536110a4611237565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156110e75780820151818401526020810190506110cc565b505050509050019250505060405180910390a1565b60068181548110151561110b57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639a5737866000604051602001526040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b15156111cb57600080fd5b6102c65a03f115156111dc57600080fd5b50505060405180519050905090565b600460019054906101000a900460ff1681565b600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460009054906101000a900460ff1681565b61123f61139c565b60068054806020026020016040519081016040528092919081815260200182805480156112c157602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311611277575b5050505050905090565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600960008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff169050919050565b81548183558181151161139757818360005260206000209182019101611396919061142e565b5b505050565b602060405190810160405280600081525090565b8154818355818115116113d7578183600052602060002091820191016113d6919061142e565b5b505050565b82805482825590600052602060002090810192821561141d5760005260206000209182015b8281111561141c578254825591600101919060010190611401565b5b50905061142a9190611453565b5090565b61145091905b8082111561144c576000816000905550600101611434565b5090565b90565b61149391905b8082111561148f57600081816101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905550600101611459565b5090565b905600a165627a7a7230582036ea35935c8246b68074adece2eab70c40e69a0193c08a6277ce06e5b25188510029b8f3f8f1a08023c0d95fc2364e0bf7593f5ff32e1db8ef9f4b41c0bd474eae62d1af896e99808080a0b47b4f0b3e73b5edc8f9a9da1cbcfed562eb06bf54619b6aefeadebf5b3604c280a0da6ec08940a924cb08c947dd56cdb40076b29a6f0ea4dba4e2d02d9a9a72431b80a030cc4138c9e74b6cf79d624b4b5612c0fd888e91f55316cfee7d1694e1a90c0b80a0c5d54b915b56a888eee4e6eeb3141e778f9b674d1d322962eed900f02c29990aa017256b36ef47f907c6b1378a2636942ce894c17075e56fc054d4283f6846659e808080a03340bbaeafcda3a8672eb83099231dbbfab8dae02a1e8ec2f7180538fac207e080b86bf869a033aa5d69545785694b808840be50c182dad2ec3636dfccbe6572fb69828742c0b846f8440101a0663ce0d171e545a26aa67e4ca66f72ba96bb48287dbcc03beea282867f80d44ba01f0e7726926cb43c03a0abf48197dba78522ec8ba1b158e2aa30da7d2a2c6f9eb838f7a03868bdfa8727775661e4ccf117824a175a33f8703d728c04488fbfffcafda9f99594e8ddc5c7a2d2f0d7a9798459c0104fdf5e987acaa3e2a02052222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f01b853f851808080a07bb75cabebdcbd1dbb4331054636d0c6d7a2b08483b9e04df057395a7434c9e080808080808080a0e61e567237b49c44d8f906ceea49027260b4010c10a547b38d8b131b9d3b6f848080808080b8d3f8d1a0dc277c93a9f9dcee99aac9b8ba3cfa4c51821998522469c37715644e8fbac0bfa0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1808080a0fe137c3a474fbde41d89a59dd76da4c55bf696b86d3af64a55632f76cf30786780808080a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb80a0da5d8b08dea0c5a4799c0f44d8a24d7cdf209f9b7a5588c1ecafb5361f6b9f07a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0808080b853f851808080a0a87d9bb950836582673aa0eecc0ff64aac607870637a2dd2012b8b1b31981f698080a08da6d5c36a404670c553a2c9052df7cd604f04e3863c4c7b9e0027bfd54206d680808080808080808080b86bf869a02080c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	//f91a8c80b91a87f91a84f9020da00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0fad4af258fd11939fae0c6c6eec9d340b1caac0b0196fd9a1bc3f489c5bf00b3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000830200008083663be080808080b8410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f91871b914c26060604052600436106100fc576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806303aca79214610101578063108552691461016457806340a141ff1461019d57806340c9cdeb146101d65780634110a489146101ff57806345199e0a1461025757806349285b58146102c15780634d238c8e14610316578063752862111461034f578063900eb5a8146103645780639a573786146103c7578063a26a47d21461041c578063ae4b1b5b14610449578063b3f05b971461049e578063b7ab4db5146104cb578063d3e848f114610535578063fa81b2001461058a578063facd743b146105df575b600080fd5b341561010c57600080fd5b6101226004808035906020019091905050610630565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561016f57600080fd5b61019b600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190505061066f565b005b34156101a857600080fd5b6101d4600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610807565b005b34156101e157600080fd5b6101e9610bb7565b6040518082815260200191505060405180910390f35b341561020a57600080fd5b610236600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610bbd565b60405180831515151581526020018281526020019250505060405180910390f35b341561026257600080fd5b61026a610bee565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156102ad578082015181840152602081019050610292565b505050509050019250505060405180910390f35b34156102cc57600080fd5b6102d4610c82565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561032157600080fd5b61034d600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610d32565b005b341561035a57600080fd5b610362610fcc565b005b341561036f57600080fd5b61038560048080359060200190919050506110fc565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156103d257600080fd5b6103da61113b565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561042757600080fd5b61042f6111eb565b604051808215151515815260200191505060405180910390f35b341561045457600080fd5b61045c6111fe565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156104a957600080fd5b6104b1611224565b604051808215151515815260200191505060405180910390f35b34156104d657600080fd5b6104de611237565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b83811015610521578082015181840152602081019050610506565b505050509050019250505060405180910390f35b341561054057600080fd5b6105486112cb565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561059557600080fd5b61059d6112f1565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156105ea57600080fd5b610616600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050611317565b604051808215151515815260200191505060405180910390f35b60078181548110151561063f57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156106cb57600080fd5b600460019054906101000a900460ff161515156106e757600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415151561072357600080fd5b80600a60006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001600460016101000a81548160ff0219169083151502179055507f600bcf04a13e752d1e3670a5a9f1c21177ca2a93c6f5391d4f1298d098097c22600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a150565b600080600061081461113b565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561084d57600080fd5b83600960008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1615156108a957600080fd5b600960008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101549350600160078054905003925060078381548110151561090857fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691508160078581548110151561094657fe5b906000526020600020900160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555083600960008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506007838154811015156109e557fe5b906000526020600020900160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556000600780549050111515610a2757600080fd5b6007805480919060019003610a3c9190611370565b506000600960008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506000600960008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548160ff0219169083151502179055506000600460006101000a81548160ff0219169083151502179055506001430340600019167f55252fa6eee4741b4e24a74a70e9c11fd2c2281df8d6ea13126ff845f7825c89600760405180806020018281038252838181548152602001915080548015610ba257602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610b58575b50509250505060405180910390a25050505050565b60085481565b60096020528060005260406000206000915090508060000160009054906101000a900460ff16908060010154905082565b610bf661139c565b6007805480602002602001604051908101604052809291908181526020018280548015610c7857602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610c2e575b5050505050905090565b6000600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166349285b586000604051602001526040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b1515610d1257600080fd5b6102c65a03f11515610d2357600080fd5b50505060405180519050905090565b610d3a61113b565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610d7357600080fd5b80600960008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff16151515610dd057600080fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610e0c57600080fd5b6040805190810160405280600115158152602001600780549050815250600960008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548160ff0219169083151502179055506020820151816001015590505060078054806001018281610ea991906113b0565b9160005260206000209001600084909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506000600460006101000a81548160ff0219169083151502179055506001430340600019167f55252fa6eee4741b4e24a74a70e9c11fd2c2281df8d6ea13126ff845f7825c89600760405180806020018281038252838181548152602001915080548015610fba57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311610f70575b50509250505060405180910390a25050565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161480156110365750600460009054906101000a900460ff16155b151561104157600080fd5b6001600460006101000a81548160ff0219169083151502179055506007600690805461106e9291906113dc565b506006805490506008819055507f8564cd629b15f47dc310d45bcbfc9bcf5420b0d51bf0659a16c67f91d27632536110a4611237565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156110e75780820151818401526020810190506110cc565b505050509050019250505060405180910390a1565b60068181548110151561110b57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639a5737866000604051602001526040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b15156111cb57600080fd5b6102c65a03f115156111dc57600080fd5b50505060405180519050905090565b600460019054906101000a900460ff1681565b600a60009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460009054906101000a900460ff1681565b61123f61139c565b60068054806020026020016040519081016040528092919081815260200182805480156112c157602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311611277575b5050505050905090565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600460029054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600960008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff169050919050565b81548183558181151161139757818360005260206000209182019101611396919061142e565b5b505050565b602060405190810160405280600081525090565b8154818355818115116113d7578183600052602060002091820191016113d6919061142e565b5b505050565b82805482825590600052602060002090810192821561141d5760005260206000209182015b8281111561141c578254825591600101919060010190611401565b5b50905061142a9190611453565b5090565b61145091905b8082111561144c576000816000905550600101611434565b5090565b90565b61149391905b8082111561148f57600081816101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905550600101611459565b5090565b905600a165627a7a7230582036ea35935c8246b68074adece2eab70c40e69a0193c08a6277ce06e5b25188510029b8f3f8f1a08023c0d95fc2364e0bf7593f5ff32e1db8ef9f4b41c0bd474eae62d1af896e99808080a0b47b4f0b3e73b5edc8f9a9da1cbcfed562eb06bf54619b6aefeadebf5b3604c280a0da6ec08940a924cb08c947dd56cdb40076b29a6f0ea4dba4e2d02d9a9a72431b80a030cc4138c9e74b6cf79d624b4b5612c0fd888e91f55316cfee7d1694e1a90c0b80a0c5d54b915b56a888eee4e6eeb3141e778f9b674d1d322962eed900f02c29990aa017256b36ef47f907c6b1378a2636942ce894c17075e56fc054d4283f6846659e808080a03340bbaeafcda3a8672eb83099231dbbfab8dae02a1e8ec2f7180538fac207e080b86bf869a033aa5d69545785694b808840be50c182dad2ec3636dfccbe6572fb69828742c0b846f8440101a0663ce0d171e545a26aa67e4ca66f72ba96bb48287dbcc03beea282867f80d44ba01f0e7726926cb43c03a0abf48197dba78522ec8ba1b158e2aa30da7d2a2c6f9eb838f7a03868bdfa8727775661e4ccf117824a175a33f8703d728c04488fbfffcafda9f99594e8ddc5c7a2d2f0d7a9798459c0104fdf5e987acaa3e2a02052222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f01b853f851808080a07bb75cabebdcbd1dbb4331054636d0c6d7a2b08483b9e04df057395a7434c9e080808080808080a0e61e567237b49c44d8f906ceea49027260b4010c10a547b38d8b131b9d3b6f848080808080b8d3f8d1a0dc277c93a9f9dcee99aac9b8ba3cfa4c51821998522469c37715644e8fbac0bfa0ab8cdb808c8303bb61fb48e276217be9770fa83ecf3f90f2234d558885f5abf1808080a0fe137c3a474fbde41d89a59dd76da4c55bf696b86d3af64a55632f76cf30786780808080a06301b39b2ea8a44df8b0356120db64b788e71f52e1d7a6309d0d2e5b86fee7cb80a0da5d8b08dea0c5a4799c0f44d8a24d7cdf209f9b7a5588c1ecafb5361f6b9f07a01b7779e149cadf24d4ffb77ca7e11314b8db7097e4d70b2a173493153ca2e5a0808080b853f851808080a0a87d9bb950836582673aa0eecc0ff64aac607870637a2dd2012b8b1b31981f698080a08da6d5c36a404670c553a2c9052df7cd604f04e3863c4c7b9e0027bfd54206d680808080808080808080b86bf869a02080c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47080
	return res, nil
}

func (c *AuRa) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
	//header := block.Header()
	//
	/// Sealing the genesis block is not supported
	//number := header.Number.Uint64()
	//if number == 0 {
	//	return errUnknownBlock
	//}
	/// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	//if c.config.Period == 0 && len(block.Transactions()) == 0 {
	//	log.Info("Sealing paused, waiting for transactions")
	//	return nil
	//}
	/// Don't hold the signer fields for the entire sealing procedure
	//c.lock.RLock()
	//signer, signFn := c.signer, c.signFn
	//c.lock.RUnlock()
	//
	/// Bail out if we're unauthorized to sign a block
	//snap, err := c.Snapshot(chain, number-1, header.ParentHash, nil)
	//if err != nil {
	//	return err
	//}
	//if _, authorized := snap.Signers[signer]; !authorized {
	//	return ErrUnauthorizedSigner
	//}
	/// If we're amongst the recent signers, wait for the next block
	//for seen, recent := range snap.Recents {
	//	if recent == signer {
	//		// Signer is among RecentsRLP, only wait if the current block doesn't shift it out
	//		if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
	//			log.Info("Signed recently, must wait for others")
	//			return nil
	//		}
	//	}
	//}
	/// Sweet, the protocol permits us to sign the block, wait for our time
	//delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
	//if header.Difficulty.Cmp(diffNoTurn) == 0 {
	//	// It's not our turn explicitly to sign, delay it a bit
	//	wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
	//	delay += time.Duration(rand.Int63n(int64(wiggle)))
	//
	//	log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	//}
	/// Sign all the things!
	//sighash, err := signFn(signer, accounts.MimetypeClique, CliqueRLP(header))
	//if err != nil {
	//	return err
	//}
	//copy(header.Extra[len(header.Extra)-ExtraSeal:], sighash)
	/// Wait until sealing is terminated or delay timeout.
	//log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	//go func() {
	//	select {
	//	case <-stop:
	//		return
	//	case <-time.After(delay):
	//	}
	//
	//	select {
	//	case results <- block.WithSeal(header):
	//	default:
	//		log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
	//	}
	//}()
	//
	//return nil
}

func (c *AuRa) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	currentStep := c.step.inner.inner.Load()
	currentEmptyStepsLen := 0
	return calculateScore(parent.Step, currentStep, uint64(currentEmptyStepsLen)).ToBig()

	/* TODO: do I need gasLimit override logic here ?
	if let Some(gas_limit) = self.gas_limit_override(header) {
		trace!(target: "engine", "Setting gas limit to {} for block {}.", gas_limit, header.number());
		let parent_gas_limit = *parent.gas_limit();
		header.set_gas_limit(gas_limit);
		if parent_gas_limit != gas_limit {
			info!(target: "engine", "Block gas limit was changed from {} to {}.", parent_gas_limit, gas_limit);
		}
	}
	*/
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

	r := consensus.Reward{Beneficiary: header.Coinbase, Kind: consensus.RewardAuthor, Amount: *reward.amount}
	return []consensus.Reward{r}, nil
}

func callBlockRewardAbi(contractAddr common.Address, syscall syscall, beneficiaries []common.Address, rewardKind []consensus.RewardKind) ([]common.Address, []*big.Int) {
	castedKind := make([]uint16, len(rewardKind))
	for i := range rewardKind {
		castedKind[i] = uint16(rewardKind[i])
	}
	packed, err := blockRewardAbi().Pack("reward", beneficiaries, castedKind)
	if err != nil {
		panic(err)
	}
	out, err := syscall(contractAddr, packed)
	if err != nil {
		panic(err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	res, err := blockRewardAbi().Unpack("reward", out)
	if err != nil {
		panic(err)
	}
	beneficiariesRes := res[0].([]common.Address)
	rewardsBig := res[1].([]*big.Int)
	// rewardsU256 := make([]*big.Int, len(rewardsBig))
	// for i := 0; i < len(rewardsBig); i++ {
	// 	var overflow bool
	// 	rewards[i], overflow = uint256.FromBig(rewardsBig[i])
	// 	if overflow {
	// 		panic("Overflow in callBlockRewardAbi")
	// 	}
	// }
	return beneficiariesRes, rewardsBig
}

func blockRewardAbi() abi.ABI {
	a, err := abi.JSON(bytes.NewReader(contracts.BlockReward))
	if err != nil {
		panic(err)
	}
	return a
}

func certifierAbi() abi.ABI {
	a, err := abi.JSON(bytes.NewReader(contracts.Certifier))
	if err != nil {
		panic(err)
	}
	return a
}

func registrarAbi() abi.ABI {
	a, err := abi.JSON(bytes.NewReader(contracts.Registrar))
	if err != nil {
		panic(err)
	}
	return a
}

func withdrawalAbi() abi.ABI {
	a, err := abi.JSON(bytes.NewReader(contracts.Withdrawal))
	if err != nil {
		panic(err)
	}
	return a
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

func getCertifier(registrar common.Address, syscall syscall) *common.Address {
	hashedKey := crypto.Keccak256Hash([]byte("service_transaction_checker"))
	packed, err := registrarAbi().Pack("getAddress", hashedKey, "A")
	if err != nil {
		panic(err)
	}
	out, err := syscall(registrar, packed)
	if err != nil {
		panic(err)
	}
	if len(out) == 0 {
		return nil
	}
	res, err := registrarAbi().Unpack("getAddress", out)
	if err != nil {
		panic(err)
	}
	certifier := res[0].(common.Address)
	return &certifier
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

/*
// extracts the empty steps from the header seal. should only be called when there are 3 fields in the seal
// (i.e. header.number() >= self.empty_steps_transition).
func headerEmptySteps(header *types.Header) ([]EmptyStep, error) {
	s := headerEmptyStepsRaw(header)
	sealedSteps := []SealedEmptyStep{}
	err := rlp.DecodeBytes(s, &sealedSteps)
	if err != nil {
		return nil, err
	}
	steps := make([]EmptyStep, len(sealedSteps))
	for i := range sealedSteps {
		steps[i] = newEmptyStepFromSealed(sealedSteps[i], header.ParentHash)
	}
	return steps, nil
}

func newEmptyStepFromSealed(step SealedEmptyStep, parentHash common.Hash) EmptyStep {
	return EmptyStep{
		signature:  step.signature,
		step:       step.step,
		parentHash: parentHash,
	}
}

// extracts the raw empty steps vec from the header seal. should only be called when there are 3 fields in the seal
// (i.e. header.number() >= self.empty_steps_transition)
func headerEmptyStepsRaw(header *types.Header) []byte {
	if len(header.Seal) < 3 {
		panic("was checked with verify_block_basic; has 3 fields; qed")
	}
	return header.Seal[2]
}
*/

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

// Returns `true` if the message has a valid signature by the expected proposer in the message's step.
func (s *EmptyStep) verify(validators ValidatorSet) (bool, error) { //nolint
	//sRlp, err := EmptyStepRlp(s.step, s.parentHash)
	//if err != nil {
	//	return false, err
	//}
	//message := crypto.Keccak256(sRlp)

	/*
		let correct_proposer = step_proposer(validators, &self.parent_hash, self.step);

		publickey::verify_address(&correct_proposer, &self.signature.into(), &message)
		.map_err(|e| e.into())
	*/
	return true, nil
}

// nolint
func (s *EmptyStep) author() (common.Address, error) {
	sRlp, err := EmptyStepRlp(s.step, s.parentHash)
	if err != nil {
		return common.Address{}, err
	}
	message := crypto.Keccak256(sRlp)
	public, err := crypto.SigToPub(message, s.signature)
	// public, err := secp256k1.RecoverPubkey(message, s.signature)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*public), nil
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
		fmt.Printf("finality_heads: %d\n", num)
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