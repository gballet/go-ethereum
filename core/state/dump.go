// Copyright 2014 The go-ethereum Authors
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

package state

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/holiman/uint256"
)

// DumpConfig is a set of options to control what portions of the state will be
// iterated and collected.
type DumpConfig struct {
	SkipCode          bool
	SkipStorage       bool
	OnlyWithAddresses bool
	Start             []byte
	Max               uint64
}

// DumpCollector interface which the state trie calls during iteration
type DumpCollector interface {
	// OnRoot is called with the state root
	OnRoot(common.Hash)
	// OnAccount is called once for each account in the trie
	OnAccount(*common.Address, DumpAccount)
}

// DumpAccount represents an account in the state.
type DumpAccount struct {
	Balance     string                 `json:"balance"`
	Nonce       uint64                 `json:"nonce"`
	Root        hexutil.Bytes          `json:"root"`
	CodeHash    hexutil.Bytes          `json:"codeHash"`
	Code        hexutil.Bytes          `json:"code,omitempty"`
	Storage     map[common.Hash]string `json:"storage,omitempty"`
	Address     *common.Address        `json:"address,omitempty"` // Address only present in iterative (line-by-line) mode
	AddressHash hexutil.Bytes          `json:"key,omitempty"`     // If we don't have address, we can output the key
}

// Dump represents the full dump in a collected format, as one large map.
type Dump struct {
	Root     string                 `json:"root"`
	Accounts map[string]DumpAccount `json:"accounts"`
	// Next can be set to represent that this dump is only partial, and Next
	// is where an iterator should be positioned in order to continue the dump.
	Next []byte `json:"next,omitempty"` // nil if no more accounts
}

// OnRoot implements DumpCollector interface
func (d *Dump) OnRoot(root common.Hash) {
	d.Root = fmt.Sprintf("%x", root)
}

// OnAccount implements DumpCollector interface
func (d *Dump) OnAccount(addr *common.Address, account DumpAccount) {
	if addr == nil {
		d.Accounts[fmt.Sprintf("pre(%s)", account.AddressHash)] = account
	}
	if addr != nil {
		d.Accounts[(*addr).String()] = account
	}
}

// iterativeDump is a DumpCollector-implementation which dumps output line-by-line iteratively.
type iterativeDump struct {
	*json.Encoder
}

// OnAccount implements DumpCollector interface
func (d iterativeDump) OnAccount(addr *common.Address, account DumpAccount) {
	dumpAccount := &DumpAccount{
		Balance:     account.Balance,
		Nonce:       account.Nonce,
		Root:        account.Root,
		CodeHash:    account.CodeHash,
		Code:        account.Code,
		Storage:     account.Storage,
		AddressHash: account.AddressHash,
		Address:     addr,
	}
	d.Encode(dumpAccount)
}

// OnRoot implements DumpCollector interface
func (d iterativeDump) OnRoot(root common.Hash) {
	d.Encode(struct {
		Root common.Hash `json:"root"`
	}{root})
}

// DumpToCollector iterates the state according to the given options and inserts
// the items into a collector for aggregation or serialization.
//
// The state iterator is still trie-based and can be converted to snapshot-based
// once the state snapshot is fully integrated into database. TODO(rjl493456442).
func (s *StateDB) DumpToCollector(c DumpCollector, conf *DumpConfig) (nextKey []byte) {
	// Sanitize the input to allow nil configs
	if conf == nil {
		conf = new(DumpConfig)
	}
	var (
		missingPreimages int
		accounts         uint64
		start            = time.Now()
		logged           = time.Now()
	)
	log.Info("Trie dumping started", "root", s.originalRoot)
	c.OnRoot(s.originalRoot)

	tr, err := s.db.OpenTrie(s.originalRoot)
	if err != nil {
		return nil
	}

	// Check if this is a Binary Trie and handle it specially
	if btrie, ok := tr.(*bintrie.BinaryTrie); ok {
		return s.dumpBinaryTrieToCollector(btrie, c, conf)
	}

	trieIt, err := tr.NodeIterator(conf.Start)
	if err != nil {
		log.Error("Trie dumping error", "err", err)
		return nil
	}
	it := trie.NewIterator(trieIt)

	for it.Next() {
		var data types.StateAccount
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}
		var (
			account = DumpAccount{
				Balance:     data.Balance.String(),
				Nonce:       data.Nonce,
				Root:        data.Root[:],
				CodeHash:    data.CodeHash,
				AddressHash: it.Key,
			}
			address   *common.Address
			addr      common.Address
			addrBytes = tr.GetKey(it.Key)
		)
		if addrBytes == nil {
			missingPreimages++
			if conf.OnlyWithAddresses {
				continue
			}
		} else {
			addr = common.BytesToAddress(addrBytes)
			address = &addr
			account.Address = address
		}
		obj := newObject(s, addr, &data)
		if !conf.SkipCode {
			account.Code = obj.Code()
		}
		if !conf.SkipStorage {
			account.Storage = make(map[common.Hash]string)

			storageTr, err := s.db.OpenStorageTrie(s.originalRoot, addr, obj.Root(), tr)
			if err != nil {
				log.Error("Failed to load storage trie", "err", err)
				continue
			}
			trieIt, err := storageTr.NodeIterator(nil)
			if err != nil {
				log.Error("Failed to create trie iterator", "err", err)
				continue
			}
			storageIt := trie.NewIterator(trieIt)
			for storageIt.Next() {
				_, content, _, err := rlp.Split(storageIt.Value)
				if err != nil {
					log.Error("Failed to decode the value returned by iterator", "error", err)
					continue
				}
				key := storageTr.GetKey(storageIt.Key)
				if key == nil {
					continue
				}
				account.Storage[common.BytesToHash(key)] = common.Bytes2Hex(content)
			}
		}
		c.OnAccount(address, account)
		accounts++
		if time.Since(logged) > 8*time.Second {
			log.Info("Trie dumping in progress", "at", common.Bytes2Hex(it.Key), "accounts", accounts,
				"elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
		if conf.Max > 0 && accounts >= conf.Max {
			if it.Next() {
				nextKey = it.Key
			}
			break
		}
	}
	if missingPreimages > 0 {
		log.Warn("Dump incomplete due to missing preimages", "missing", missingPreimages)
	}
	log.Info("Trie dumping complete", "accounts", accounts,
		"elapsed", common.PrettyDuration(time.Since(start)))

	return nextKey
}

// dumpBinaryTrieToCollector handles dumping Binary Trie state to the collector.
// This is necessary because Binary Trie stores account data in a completely different format
// than MPT. While MPT uses RLP-encoded StateAccount structures, Binary Trie stores raw bytes
// with specific offsets as defined in EIP-7864.
//
// Binary Trie storage layout for account data:
// - BasicDataLeafKey (suffix byte 0): Contains nonce and balance
//   - Bytes 0-7: Code size (4 bytes) + padding
//   - Bytes 8-15: Nonce (8 bytes, big-endian)
//   - Bytes 16-31: Balance (16 bytes, big-endian)
//
// - CodeHashLeafKey (suffix byte 1): Contains the code hash (32 bytes)
// - Storage slots (suffix bytes 64+): Contains storage values
//
// This function needs to:
// 1. Iterate through Binary Trie nodes to find account data
// 2. Extract and decode account information from raw bytes
// 3. Map Binary Trie keys back to Ethereum addresses
// 4. Reconstruct the full account state for the collector
func (s *StateDB) dumpBinaryTrieToCollector(btrie *bintrie.BinaryTrie, c DumpCollector, conf *DumpConfig) (nextKey []byte) {
	var (
		accounts uint64
		// Map to track processed stems to avoid duplicate accounts
		// This prevents dumping the same account when iterating through
		// since nultiple leaves can belong to the same account (basic data, code hash, storage).
		processedStems = make(map[string]bool)
	)

	// Step 1: Create an iterator to traverse the Binary Trie
	// The iterator will visit all nodes in the trie, allowing us to find leaf nodes
	// that contain actual account data
	it, err := btrie.NodeIterator(nil)
	if err != nil {
		log.Error("Failed to create Binary Trie iterator", "err", err)
		return nil
	}

	// Step 2: Iterate through all nodes in the Binary Trie
	for it.Next(true) {
		// Skip non-leaf nodes as they don't contain account data
		if !it.Leaf() {
			continue
		}

		// Step 3: Extract the leaf's key and value
		// The key is 32 bytes: 31-byte stem + 1-byte suffix
		// The stem encodes the account address, the suffix indicates the data type
		leafKey := it.LeafKey()
		leafValue := it.LeafBlob()

		// Step 4: Parse the key structure
		// First 31 bytes: stem (encodes the account address)
		// Last byte: suffix (indicates the type of data)
		stem := string(leafKey[:31])
		suffixByte := leafKey[31]

		// Step 5: Check if this leaf contains BasicData (nonce + balance)
		// BasicDataLeafKey = 0 is the suffix for account basic data
		if suffixByte == bintrie.BasicDataLeafKey {
			// Step 6: Ensure we only process each account once
			// Multiple leaves can belong to the same account (basic data, code hash, storage)
			// We only want to dump each account once
			if processedStems[stem] {
				continue
			}
			processedStems[stem] = true

			// Step 7: Extract nonce from the Binary Trie format
			// Nonce is stored at offset 8 as an 8-byte big-endian integer
			var nonce uint64
			if len(leafValue) > bintrie.BasicDataNonceOffset+8 {
				nonce = binary.BigEndian.Uint64(leafValue[bintrie.BasicDataNonceOffset:])
			}

			// Step 8: Extract balance from the Binary Trie format
			// Balance is stored at offset 16 as a 16-byte big-endian integer
			var balance = new(uint256.Int)
			if len(leafValue) > bintrie.BasicDataBalanceOffset+16 {
				balanceBytes := make([]byte, 16)
				copy(balanceBytes, leafValue[bintrie.BasicDataBalanceOffset:bintrie.BasicDataBalanceOffset+16])
				balance.SetBytes(balanceBytes)
			}

			// Step 9: Map the Binary Trie key back to an Ethereum address
			// This is the challenging part: Binary Trie keys are hashed versions of addresses
			// We need to find which address maps to this particular key
			//
			// Current approach: (Made up by Claude) ->
			// Iterate through known addresses in stateObjects
			// and check if their Binary Trie key matches our leaf key
			var foundAddr *common.Address
			for addr := range s.stateObjects {
				// Generate the Binary Trie key for this address
				testKey := bintrie.GetBinaryTreeKeyBasicData(addr)
				if bytes.Equal(testKey, leafKey) {
					a := addr // Create a copy to avoid reference issues
					foundAddr = &a
					break
				}
			}

			// Step 10: Error if we couldn't find the corresponding address
			// This might happen for accounts not in the current state cache
			if foundAddr == nil {
				// TODO(@CPerezz): Figure out how to proceed.
				panic("Binary Trie dump error: Cannot recover address from hash.")
			}

			// Step 11: Create the dump account structure with basic data
			addr := *foundAddr
			dumpAccount := DumpAccount{
				Balance:     balance.ToBig().String(),
				Nonce:       nonce,
				Address:     &addr,
				AddressHash: crypto.Keccak256(addr[:]),
			}

			// Step 12: Fetch the code hash from a separate Binary Trie leaf
			// Code hash is stored at suffix byte 1 (CodeHashLeafKey)
			codeHashKey := bintrie.GetBinaryTreeKeyCodeHash(addr)
			if codeHashData, err := btrie.GetWithHashedKey(codeHashKey); err == nil && codeHashData != nil {
				dumpAccount.CodeHash = codeHashData
				// Step 13: Fetch the actual code if needed and not empty
				if !conf.SkipCode && !bytes.Equal(codeHashData, types.EmptyCodeHash.Bytes()) {
					dumpAccount.Code = s.GetCode(addr)
				}
			}

			// Step 14: Fetch storage values if needed
			if !conf.SkipStorage {
				dumpAccount.Storage = make(map[common.Hash]string)
				// TODO(CPerezz): Properly iterate through Binary Trie storage slots
				// Storage slots are at suffix bytes 64+ in the Binary Trie
				// Idea from Claude:
				// Use the cached dirty storage from state objects
				if obj := s.getStateObject(addr); obj != nil {
					for key, value := range obj.dirtyStorage {
						dumpAccount.Storage[key] = common.Bytes2Hex(value[:])
					}
				}
			}

			// Step 15: Send the account to the collector
			c.OnAccount(&addr, dumpAccount)
			accounts++

			// Step 17: Check if we've reached the maximum number of accounts
			if conf.Max > 0 && accounts >= conf.Max {
				// Save the next key for resumption if there are more accounts
				if it.Next(true) {
					nextKey = it.LeafKey()
				}
				break
			}
		}
	}

	return nextKey
}

// DumpBinTrieLeaves collects all binary trie leaf nodes into the provided map.
func (s *StateDB) DumpBinTrieLeaves(collector map[common.Hash]hexutil.Bytes) error {
	if s.trie == nil {
		trie, err := s.db.OpenTrie(s.originalRoot)
		if err != nil {
			return err
		}
		s.trie = trie
	}

	it, err := s.trie.(*bintrie.BinaryTrie).NodeIterator(nil)
	if err != nil {
		panic(err)
	}
	for it.Next(true) {
		if it.Leaf() {
			collector[common.BytesToHash(it.LeafKey())] = it.LeafBlob()
		}
	}
	return nil
}

// RawDump returns the state. If the processing is aborted e.g. due to options
// reaching Max, the `Next` key is set on the returned Dump.
func (s *StateDB) RawDump(opts *DumpConfig) Dump {
	dump := &Dump{
		Accounts: make(map[string]DumpAccount),
	}
	dump.Next = s.DumpToCollector(dump, opts)
	return *dump
}

// Dump returns a JSON string representing the entire state as a single json-object
func (s *StateDB) Dump(opts *DumpConfig) []byte {
	dump := s.RawDump(opts)
	json, err := json.MarshalIndent(dump, "", "    ")
	if err != nil {
		log.Error("Error dumping state", "err", err)
	}
	return json
}

// IterativeDump dumps out accounts as json-objects, delimited by linebreaks on stdout
func (s *StateDB) IterativeDump(opts *DumpConfig, output *json.Encoder) {
	s.DumpToCollector(iterativeDump{output}, opts)
}
