package kaustinenanalytics

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/kaustinenanalytics2"
	"github.com/ethereum/go-ethereum/trie"
)

func CollectTreeMetrics(blockNum uint64, state *state.StateDB, root common.Hash) error {
	tree, err := state.Database().OpenTrie(root)
	if err != nil {
		return fmt.Errorf("error opening state tree root: %w", err)
	}
	vktTree := tree.(*trie.VerkleTrie)

	now := time.Now()
	depthCount, leafNodeCount, internalNodeCount, keyValueCount, err := vktTree.TreeStats()
	if err != nil {
		return fmt.Errorf("error collecting tree metrics: %w", err)
	}
	fmt.Printf("tree stats took %v\n", time.Since(now))

	if _, err := kaustinenanalytics2.Db.Exec(`INSERT OR IGNORE INTO tree_stats values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		blockNum,
		depthCount[1],
		depthCount[2],
		depthCount[3],
		depthCount[4],
		depthCount[5],
		leafNodeCount,
		internalNodeCount,
		keyValueCount); err != nil {
		return fmt.Errorf("failed to insert tree stats: %v", err)
	}

	return nil
}
