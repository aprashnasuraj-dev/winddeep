package core

import (
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/params"
)

// assumedNetworkGasLimit is the block gas limit MaxFuturePreprepareBytes was
// sized against (see genesis GasLimit, currently 30,000,000). It is duplicated
// here deliberately so that TestMaxFuturePreprepareBytes_CoversMaxBlock fails
// loudly if the ceiling and the gas-limit assumption ever drift apart — that is
// the review trigger to revisit the ceiling, not a value read at runtime.
const assumedNetworkGasLimit = 30_000_000

// TestMaxFuturePreprepareBytes_CoversMaxBlock pins the per-message ceiling to the
// gas-limit assumption it was derived from. The largest data-carrying block is
// bounded by gas: assumedNetworkGasLimit / TxDataNonZeroGasEIP2028 bytes of
// calldata. The ceiling must sit above that hard bound with margin, otherwise a
// legitimate near-max block would be rejected from the backlog (a liveness bug).
//
// If someone raises the assumed gas limit (e.g. as part of a network upgrade)
// without raising MaxFuturePreprepareBytes, this test goes red — forcing the two
// to be reconciled rather than silently drifting into a liveness regression.
func TestMaxFuturePreprepareBytes_CoversMaxBlock(t *testing.T) {
	// Hard upper bound on legitimate block payload: every gas unit spent on the
	// cheapest data (non-zero calldata post-EIP-2028) buys 1/16 of a byte.
	maxBlockBytes := assumedNetworkGasLimit / int(params.TxDataNonZeroGasEIP2028)

	// Require at least ~2x headroom over the hard bound to cover RLP framing,
	// PRE-PREPARE/ROUND-CHANGE justification arrays, and normal variance.
	const wantMarginNumerator, wantMarginDenominator = 2, 1
	required := maxBlockBytes * wantMarginNumerator / wantMarginDenominator

	if MaxFuturePreprepareBytes < required {
		t.Fatalf("MaxFuturePreprepareBytes=%d is below %dx the max legitimate block (%d bytes at %d gas / %d gas per byte); "+
			"either the ceiling is too low or the gas-limit assumption changed — reconcile them",
			MaxFuturePreprepareBytes, wantMarginNumerator, maxBlockBytes, assumedNetworkGasLimit, params.TxDataNonZeroGasEIP2028)
	}
}

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

// makeFutureRoundChange builds a ROUND-CHANGE for a future sequence carrying a
// PreparedBlock of proposalBytes payload, sourced from src. Like a PRE-PREPARE,
// a ROUND-CHANGE can embed a full block, so it is subject to the same per-message
// ceiling.
func makeFutureRoundChange(seq, round int64, src common.Address, proposalBytes int) *qbfttypes.RoundChange {
	extra := make([]byte, proposalBytes)
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(seq), Extra: extra})
	rc := qbfttypes.NewRoundChange(big.NewInt(seq), big.NewInt(round), big.NewInt(round), block, false)
	rc.SetSource(src)
	rc.SetSignature([]byte{0x01})
	return rc
}

// TestAddToBacklog_RejectsOversizedFutureRoundChange proves the per-message
// ceiling also covers ROUND-CHANGE, which can embed a full PreparedBlock exactly
// like a PRE-PREPARE's proposal.
func TestAddToBacklog_RejectsOversizedFutureRoundChange(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	rc := makeFutureRoundChange(2, 0, src, 1024) // size argument drives the check
	c.addToBacklog(rc, MaxFuturePreprepareBytes+1)

	if c.backlogsTotal != 0 {
		t.Fatalf("oversized future ROUND-CHANGE retained: backlogsTotal=%d, want 0", c.backlogsTotal)
	}
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
	if c.backlogsBytes[src] != realistic {
		t.Fatalf("byte charge = %d, want %d", c.backlogsBytes[src], realistic)
	}
}

// TestAddToBacklog_PerValidatorByteBudget proves that a single source cannot
// exceed MaxBacklogBytesPerValidator even while under the message-count cap.
// This is the core regression: the old code bounded count only, so 1024 large
// messages could retain multi-GB. Here the byte budget stops admission long
// before the count cap is reached.
func TestAddToBacklog_PerValidatorByteBudget(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	const per = 1024 * 1024 // 1 MiB each
	admitted := 0
	for i := 0; i < MaxBacklogBytesPerValidator/per+16; i++ {
		before := c.backlogsTotal
		// Distinct future sequence per message so none collapse.
		pp := makeFuturePreprepare(int64(2+i), 0, src, per)
		c.addToBacklog(pp, per)
		if c.backlogsTotal > before {
			admitted++
		}
	}

	if c.backlogsBytes[src] > MaxBacklogBytesPerValidator {
		t.Fatalf("per-validator bytes %d exceeded budget %d", c.backlogsBytes[src], MaxBacklogBytesPerValidator)
	}
	if admitted >= MaxBacklogPerValidator {
		t.Fatalf("byte budget did not bite before the count cap: admitted %d", admitted)
	}
	wantApprox := MaxBacklogBytesPerValidator / per
	if admitted != wantApprox {
		t.Fatalf("admitted %d messages, want %d (budget %d / per %d)", admitted, wantApprox, MaxBacklogBytesPerValidator, per)
	}
}

// TestProcessBacklog_ByteAccountingIsExact proves the byte counters return to
// zero once a full backlog is drained by chain progress. This guards against the
// accounting-drift and underflow traps in pop / requeue / whole-backlog eviction.
func TestProcessBacklog_ByteAccountingIsExact(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	const per = 512 * 1024
	const n = 8
	for i := 0; i < n; i++ {
		pp := makeFuturePreprepare(int64(2+i), 0, src, per)
		c.addToBacklog(pp, per)
	}
	if c.backlogsBytesTotal != n*per {
		t.Fatalf("after admission backlogsBytesTotal=%d, want %d", c.backlogsBytesTotal, n*per)
	}

	// Advance current view past all backlogged sequences so processBacklog drains
	// them all (they are no longer future and become deliverable, so they are
	// popped and posted rather than requeued).
	c.current = newRoundState(
		&istanbul.View{Sequence: big.NewInt(100), Round: big.NewInt(0)},
		valSet, nil, nil, nil, nil, func(common.Hash) bool { return false },
	)
	c.processBacklog()

	if c.backlogsBytesTotal != 0 {
		t.Fatalf("after drain backlogsBytesTotal=%d, want 0 (accounting drift)", c.backlogsBytesTotal)
	}
	if c.backlogsTotal != 0 {
		t.Fatalf("after drain backlogsTotal=%d, want 0", c.backlogsTotal)
	}
	if b := c.backlogsBytes[src]; b != 0 {
		t.Fatalf("after drain per-source bytes=%d, want 0", b)
	}
}
