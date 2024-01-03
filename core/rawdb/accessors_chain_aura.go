package rawdb

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

func ReadEpoch(db ethdb.KeyValueReader, blockNum uint64, blockHash common.Hash) (transitionProof []byte, err error) {
	k := make([]byte, 40 /* block num uint64 + block hash */)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return db.Get(epochKey(k))
}

// TODO use sqlite if leveldb doesn't work
func FindEpochBeforeOrEqualNumber(db ethdb.KeyValueStore, n uint64) (blockNum uint64, blockHash common.Hash, transitionProof []byte, err error) {

	it := db.NewIterator(EpochPrefix, nil)
	defer it.Release()

	blockNum = 0
	for it.Next() {
		k := it.Key()
		k = k[len(EpochPrefix):]
		num := binary.BigEndian.Uint64(k)
		if num > n {
			break
		}

		blockNum = num
		transitionProof = it.Value()
		blockHash = common.BytesToHash(k[8:])
	}

	return
}

func WriteEpoch(db ethdb.KeyValueWriter, blockNum uint64, blockHash common.Hash, transitionProof []byte) (err error) {
	k := make([]byte, 40)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return db.Put(epochKey(k), transitionProof)
}

func ReadPendingEpoch(db ethdb.KeyValueReader, blockNum uint64, blockHash common.Hash) (transitionProof []byte, err error) {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return db.Get(pendingEpochKey(k))
}

func WritePendingEpoch(db ethdb.KeyValueWriter, blockNum uint64, blockHash common.Hash, transitionProof []byte) (err error) {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return db.Put(pendingEpochKey(k), transitionProof)
}
