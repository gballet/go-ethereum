package rawdb

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
)

func DeleteNewerEpochs(tx kv.RwTx, number uint64) error {
	if err := tx.ForEach(kv.PendingEpoch, hexutility.EncodeTs(number), func(k, v []byte) error {
		return tx.Delete(kv.Epoch, k)
	}); err != nil {
		return err
	}
	return tx.ForEach(kv.Epoch, hexutility.EncodeTs(number), func(k, v []byte) error {
		return tx.Delete(kv.Epoch, k)
	})
}
func ReadEpoch(tx kv.Tx, blockNum uint64, blockHash common.Hash) (transitionProof []byte, err error) {
	k := make([]byte, dbutils.NumberLength+length.Hash)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[dbutils.NumberLength:], blockHash[:])
	return tx.GetOne(kv.Epoch, k)
}
func FindEpochBeforeOrEqualNumber(tx kv.Tx, n uint64) (blockNum uint64, blockHash common.Hash, transitionProof []byte, err error) {
	c, err := tx.Cursor(kv.Epoch)
	if err != nil {
		return 0, common.Hash{}, nil, err
	}
	defer c.Close()
	seek := hexutility.EncodeTs(n)
	k, v, err := c.Seek(seek)
	if err != nil {
		return 0, common.Hash{}, nil, err
	}
	if k != nil {
		num := binary.BigEndian.Uint64(k)
		if num == n {
			return n, common.BytesToHash(k[dbutils.NumberLength:]), v, nil
		}
	}
	k, v, err = c.Prev()
	if err != nil {
		return 0, common.Hash{}, nil, err
	}
	if k == nil {
		return 0, common.Hash{}, nil, nil
	}
	return binary.BigEndian.Uint64(k), common.BytesToHash(k[dbutils.NumberLength:]), v, nil
}

func WriteEpoch(tx kv.RwTx, blockNum uint64, blockHash common.Hash, transitionProof []byte) (err error) {
	k := make([]byte, dbutils.NumberLength+length.Hash)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[dbutils.NumberLength:], blockHash[:])
	return tx.Put(kv.Epoch, k, transitionProof)
}

func ReadPendingEpoch(tx kv.Tx, blockNum uint64, blockHash common.Hash) (transitionProof []byte, err error) {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return tx.GetOne(kv.PendingEpoch, k)
}

func WritePendingEpoch(tx kv.RwTx, blockNum uint64, blockHash common.Hash, transitionProof []byte) (err error) {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k, blockNum)
	copy(k[8:], blockHash[:])
	return tx.Put(kv.PendingEpoch, k, transitionProof)
}
