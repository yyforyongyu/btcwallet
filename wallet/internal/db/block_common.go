package db

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	// errBlockHeightConflict indicates that the database already has a block
	// height with different hash or timestamp metadata.
	errBlockHeightConflict = errors.New(
		"block height conflicts with existing block metadata",
	)
)

// buildBlock constructs a Block from the provided components that are common
// across different database backends.
func buildBlock(hash []byte, height uint32, timestamp int64) (*Block, error) {
	h, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("block hash: %w", err)
	}

	return &Block{
		Hash:      *h,
		Height:    height,
		Timestamp: time.Unix(timestamp, 0),
	}, nil
}

// ensureStoredBlockMatches rejects attempts to reuse a height row that already
// points at a different block hash or timestamp.
func ensureStoredBlockMatches(block *Block, storedHash []byte,
	storedTimestamp int64) error {

	if bytes.Equal(storedHash, block.Hash[:]) &&
		storedTimestamp == block.Timestamp.Unix() {

		return nil
	}

	return fmt.Errorf("block height %d: %w", block.Height,
		errBlockHeightConflict)
}
