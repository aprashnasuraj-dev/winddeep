package core

import (
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
)

// makeAttackPrepares builds `n` distinct-signer PREPARE messages that all attest
// to block H (digestH) at preparedRound. These are the genuine PREPAREs an
// attacker harvests off the wire.
func makeAttackPrepares(valSet []common.Address, n int, seq, preparedRound int64, digestH common.Hash) []*qbfttypes.Prepare {
	prepares := make([]*qbfttypes.Prepare, 0, n)
	for i := 0; i < n; i++ {
		p := qbfttypes.NewPrepareWithSigAndSource(
			big.NewInt(seq), big.NewInt(preparedRound), digestH, []byte{0x01}, valSet[i])
		prepares = append(prepares, p)
	}
	return prepares
}

// TestRoundChangeSet_Add_RejectsSelfAssertedBadProposal is the regression test
// for the ROUND-CHANGE write-site bad-proposal bug.
//
// A single Byzantine validator sends a ROUND-CHANGE for a later round whose
// PreparedDigest is its own block E, but whose justifying PREPAREs are the
// genuine PREPAREs for a different block H, and sets HasBadProposal=true on its
// own message. Before the fix, Add passed that self-asserted flag into
// hasMatchingRoundChangeAndPrepares, which switched off the digest binding and
// pinned highestPreparedBlock to the attacker's block E. After the fix the flag
// is ignored at the write site (a bad-proposal exemption is only ever honoured
// once corroborated by a quorum in isJustified at read time), so the mismatched
// justification is rejected and highestPreparedBlock is left unchanged.
func TestRoundChangeSet_Add_RejectsSelfAssertedBadProposal(t *testing.T) {
	const n = 4
	quorum := 3 // ceil(2*4/3)

	valSet := newTestValidatorSet(n)
	addrs := make([]common.Address, 0, n)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	blockH := makeProposalBlock(t, 1)  // the legitimately prepared block
	blockE := makeProposalBlock(t, 42) // the attacker's chosen block (different hash)
	if blockH.Hash() == blockE.Hash() {
		t.Fatal("test setup error: blockH and blockE must have distinct hashes")
	}

	const seq, targetRound, preparedRound = int64(1), int64(5), int64(2)

	// Genuine PREPAREs for block H, from a quorum of distinct validators.
	prepares := makeAttackPrepares(addrs, quorum, seq, preparedRound, blockH.Hash())

	// Attacker's ROUND-CHANGE: claims block E as its prepared block but sets the
	// bad-proposal flag so the digest binding would be skipped.
	attacker := addrs[quorum] // the 4th validator, not among the PREPARE signers
	rc := qbfttypes.NewRoundChange(big.NewInt(seq), big.NewInt(targetRound), big.NewInt(preparedRound), blockE, true)
	// Force the digest/PREPARE mismatch: E's digest against H's PREPAREs.
	rc.PreparedDigest = blockE.Hash()
	rc.HasBadProposal = true
	rc.SetSource(attacker)
	rc.SetSignature([]byte{0x01})

	rcs := newRoundChangeSet(valSet)
	rcs.NewRound(big.NewInt(targetRound))

	err := rcs.Add(big.NewInt(targetRound), rc, big.NewInt(preparedRound), blockE, prepares, quorum)
	if err != nil {
		t.Fatalf("Add returned unexpected error: %v", err)
	}

	// The core assertion: the poisoned block must NOT have been recorded.
	if got := rcs.highestPreparedBlock[uint64(targetRound)]; got != nil {
		t.Fatalf("attacker block was pinned as highestPreparedBlock (hash=%x); "+
			"self-asserted HasBadProposal must not bypass the digest binding", got.Hash())
	}
	if got := rcs.highestPreparedRound[uint64(targetRound)]; got != nil {
		t.Fatalf("highestPreparedRound was set to %v despite mismatched justification", got)
	}
}

// TestRoundChangeSet_Add_AcceptsHonestPreparedRoundChange is the companion
// control: a ROUND-CHANGE whose PreparedDigest genuinely matches its justifying
// PREPAREs (the normal, honest path) must still be accepted and recorded. This
// guards against the fix over-rejecting.
func TestRoundChangeSet_Add_AcceptsHonestPreparedRoundChange(t *testing.T) {
	const n = 4
	quorum := 3

	valSet := newTestValidatorSet(n)
	addrs := make([]common.Address, 0, n)
	for _, v := range valSet.List() {
		addrs = append(addrs, v.Address())
	}

	blockH := makeProposalBlock(t, 1)
	const seq, targetRound, preparedRound = int64(1), int64(5), int64(2)

	// Genuine PREPAREs for H, matching the ROUND-CHANGE's prepared block.
	prepares := makeAttackPrepares(addrs, quorum, seq, preparedRound, blockH.Hash())

	rc := qbfttypes.NewRoundChange(big.NewInt(seq), big.NewInt(targetRound), big.NewInt(preparedRound), blockH, false)
	rc.SetSource(addrs[quorum])
	rc.SetSignature([]byte{0x01})

	rcs := newRoundChangeSet(valSet)
	rcs.NewRound(big.NewInt(targetRound))

	if err := rcs.Add(big.NewInt(targetRound), rc, big.NewInt(preparedRound), blockH, prepares, quorum); err != nil {
		t.Fatalf("Add returned unexpected error: %v", err)
	}

	got := rcs.highestPreparedBlock[uint64(targetRound)]
	if got == nil {
		t.Fatal("honest prepared ROUND-CHANGE was not recorded as highestPreparedBlock")
	}
	if got.Hash() != blockH.Hash() {
		t.Fatalf("recorded block %x, want honest block H %x", got.Hash(), blockH.Hash())
	}
}
