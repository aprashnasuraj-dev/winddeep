package core

import (
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
)

// -----------------------------------------------------------------------------
// Sequence-binding regression tests for justification PREPARE messages.
//
// A PREPARE's signature covers its own Sequence, so a genuine PREPARE from an
// already-finalised PAST sequence verifies correctly. Nothing in verifySignatures
// compares that Sequence to the ROUND-CHANGE / PRE-PREPARE it is attached to, and
// before this fix neither isJustified (read side) nor
// hasMatchingRoundChangeAndPrepares (write side, via roundChangeSet.Add) checked
// it either. That let an attacker replay a quorum of real PREPAREs harvested from
// a past sequence as justification for a block in the current sequence — pinning a
// stale block into highestPreparedBlock and, on the read side, passing a forged
// re-proposal's justification check. Both paths now bind the PREPARE sequence.
// -----------------------------------------------------------------------------

const (
	sbCurrentSeq   = int64(10)
	sbPastSeq      = int64(7)
	sbTargetRound  = int64(5)
	sbPreparedRnd  = int64(2)
	sbValidatorNum = 4
	sbQuorum       = 3
)

func sbPrepares(addrs []common.Address, n int, seq int64, digest common.Hash) []*qbfttypes.Prepare {
	prepares := make([]*qbfttypes.Prepare, 0, n)
	for i := 0; i < n; i++ {
		prepares = append(prepares, qbfttypes.NewPrepareWithSigAndSource(
			big.NewInt(seq), big.NewInt(sbPreparedRnd), digest, []byte{0x01}, addrs[i]))
	}
	return prepares
}

// Write side (roundChangeSet.Add -> hasMatchingRoundChangeAndPrepares): a
// ROUND-CHANGE for the current sequence, re-proposing a real past-sequence block
// and justified by that block's genuine past-sequence PREPAREs, must NOT pin the
// stale block into highestPreparedBlock.
func TestRoundChangeSet_Add_RejectsCrossSequencePrepareReplay(t *testing.T) {
	valSet := newTestValidatorSet(sbValidatorNum)
	addrs := make([]common.Address, 0, sbValidatorNum)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	blockPast := makeProposalBlock(t, sbPastSeq)
	prepares := sbPrepares(addrs, sbQuorum, sbPastSeq, blockPast.Hash())

	rc := qbfttypes.NewRoundChange(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), big.NewInt(sbPreparedRnd), blockPast, false)
	rc.SetSource(addrs[sbQuorum])
	rc.SetSignature([]byte{0x01})

	rcs := newRoundChangeSet(valSet)
	rcs.NewRound(big.NewInt(sbTargetRound))

	if err := rcs.Add(big.NewInt(sbTargetRound), rc, big.NewInt(sbPreparedRnd), blockPast, prepares, sbQuorum); err != nil {
		t.Fatalf("Add returned unexpected error: %v", err)
	}

	if got := rcs.highestPreparedBlock[uint64(sbTargetRound)]; got != nil {
		t.Fatalf("cross-sequence PREPARE replay pinned highestPreparedBlock to block %x (number=%v); "+
			"past-sequence PREPAREs must not justify a current-sequence ROUND-CHANGE", got.Hash(), got.Number())
	}
}

// Write side, control: when the PREPAREs genuinely belong to the ROUND-CHANGE's
// own sequence, the prepared block must still be recorded.
func TestRoundChangeSet_Add_AcceptsSameSequencePrepares(t *testing.T) {
	valSet := newTestValidatorSet(sbValidatorNum)
	addrs := make([]common.Address, 0, sbValidatorNum)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	block := makeProposalBlock(t, sbCurrentSeq)
	prepares := sbPrepares(addrs, sbQuorum, sbCurrentSeq, block.Hash())

	rc := qbfttypes.NewRoundChange(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), big.NewInt(sbPreparedRnd), block, false)
	rc.SetSource(addrs[sbQuorum])
	rc.SetSignature([]byte{0x01})

	rcs := newRoundChangeSet(valSet)
	rcs.NewRound(big.NewInt(sbTargetRound))

	if err := rcs.Add(big.NewInt(sbTargetRound), rc, big.NewInt(sbPreparedRnd), block, prepares, sbQuorum); err != nil {
		t.Fatalf("Add returned unexpected error: %v", err)
	}

	got := rcs.highestPreparedBlock[uint64(sbTargetRound)]
	if got == nil || got.Hash() != block.Hash() {
		t.Fatalf("same-sequence prepared ROUND-CHANGE was not recorded correctly (got=%v)", got)
	}
}

// Read side (isJustified): a PRE-PREPARE for the current sequence justified by
// past-sequence PREPAREs must be rejected.
func TestIsJustified_RejectsCrossSequencePrepare(t *testing.T) {
	valSet := newTestValidatorSet(sbValidatorNum)
	addrs := make([]common.Address, 0, sbValidatorNum)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	blockPast := makeProposalBlock(t, sbPastSeq)

	rcPayloads := make([]*qbfttypes.SignedRoundChangePayload, 0, sbQuorum)
	for i := 0; i < sbQuorum; i++ {
		m := qbfttypes.NewRoundChange(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), big.NewInt(sbPreparedRnd), blockPast, false)
		m.SetSource(addrs[i])
		rcPayloads = append(rcPayloads, &m.SignedRoundChangePayload)
	}

	prepares := sbPrepares(addrs, sbQuorum, sbPastSeq, blockPast.Hash())

	err := isJustified(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), blockPast, rcPayloads, prepares, sbQuorum, valSet)
	if err == nil {
		t.Fatal("isJustified accepted past-sequence PREPAREs as justification for a current-sequence PRE-PREPARE")
	}
}

// Read side, control: PREPAREs from the correct (current) sequence still justify.
func TestIsJustified_AcceptsSameSequencePrepare(t *testing.T) {
	valSet := newTestValidatorSet(sbValidatorNum)
	addrs := make([]common.Address, 0, sbValidatorNum)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	block := makeProposalBlock(t, sbCurrentSeq)

	rcPayloads := make([]*qbfttypes.SignedRoundChangePayload, 0, sbQuorum)
	for i := 0; i < sbQuorum; i++ {
		m := qbfttypes.NewRoundChange(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), big.NewInt(sbPreparedRnd), block, false)
		m.SetSource(addrs[i])
		rcPayloads = append(rcPayloads, &m.SignedRoundChangePayload)
	}

	prepares := sbPrepares(addrs, sbQuorum, sbCurrentSeq, block.Hash())

	if err := isJustified(big.NewInt(sbCurrentSeq), big.NewInt(sbTargetRound), block, rcPayloads, prepares, sbQuorum, valSet); err != nil {
		t.Fatalf("isJustified rejected valid same-sequence justification: %v", err)
	}
}
