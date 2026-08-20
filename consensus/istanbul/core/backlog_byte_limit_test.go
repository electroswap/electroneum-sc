package core

import (
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/core/types"
)

// makeFuturePreprepare builds a PRE-PREPARE for a future sequence whose embedded
// block proposal carries proposalBytes of payload, sourced from src. It does not
// sign the message; these tests drive addToBacklog directly to exercise the
// admission checks in isolation from signature verification.
func makeFuturePreprepare(seq, round int64, src common.Address, proposalBytes int) *qbfttypes.Preprepare {
	extra := make([]byte, proposalBytes)
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(seq), Extra: extra})
	pp := qbfttypes.NewPreprepare(big.NewInt(seq), big.NewInt(round), block)
	pp.SetSource(src)
	pp.SetSignature([]byte{0x01})
	return pp
}

// TestAddToBacklog_RejectsOversizedFuturePreprepare proves the per-message
// ceiling: a single future PRE-PREPARE whose encoded size exceeds
// MaxFuturePreprepareBytes is dropped before retention.
func TestAddToBacklog_RejectsOversizedFuturePreprepare(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	pp := makeFuturePreprepare(2, 0, src, 1024) // small proposal; size argument drives the check
	c.addToBacklog(pp, MaxFuturePreprepareBytes+1)

	if c.backlogsTotal != 0 {
		t.Fatalf("oversized future PRE-PREPARE retained: backlogsTotal=%d, want 0", c.backlogsTotal)
	}
}

// TestAddToBacklog_AcceptsRealisticFuturePreprepare proves the ceiling does not
// reject a legitimately-sized proposal. A realistic max block is ~1.9 MiB (30M
// gas / 16 gas per byte); a 1.5 MiB message must be admitted.
func TestAddToBacklog_AcceptsRealisticFuturePreprepare(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	const realistic = 1536 * 1024 // 1.5 MiB, well under MaxFuturePreprepareBytes
	pp := makeFuturePreprepare(2, 0, src, realistic)
	c.addToBacklog(pp, realistic)

	if c.backlogsTotal != 1 {
		t.Fatalf("realistic future PRE-PREPARE not retained: backlogsTotal=%d, want 1", c.backlogsTotal)
	}
}
