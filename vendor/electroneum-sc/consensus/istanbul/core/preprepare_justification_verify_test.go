package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
	"github.com/electroneum/electroneum-sc/log"
)

// testValSet builds a validator set for verifySignatures tests that need a non-nil
// c.valSet. The stub validateFn used by these tests does not consult the set, so the
// concrete membership is irrelevant; only Size() matters (it bounds the justification
// length cap in verifySignatures).
func testValSet(n int) istanbul.ValidatorSet {
	pp := istanbul.NewRoundRobinProposerPolicy()
	pp.Use(istanbul.ValidatorSortByByte())
	return validator.NewSet(generateValidators(n), pp)
}

func TestVerifySignatures_PreprepareRejectsBadJustificationPrepares(t *testing.T) {
	// Addresses we want validateFn to return on successful "signature validation"
	proposerAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	validatorAddr := common.HexToAddress("0x2000000000000000000000000000000000000002")

	// Stub validateFn:
	// - outer Preprepare signature 0xAA => proposerAddr
	// - good Prepare signature 0xBB     => validatorAddr
	// - anything else                   => error
	validateFn := func(_payload []byte, sig []byte) (common.Address, error) {
		if len(sig) == 0 {
			return common.Address{}, errors.New("empty signature")
		}
		switch sig[0] {
		case 0xAA:
			return proposerAddr, nil
		case 0xBB:
			return validatorAddr, nil
		default:
			return common.Address{}, errors.New("invalid signature")
		}
	}

	c := &core{
		validateFn: validateFn,
		// verifySignatures() calls c.currentLogger(), which calls c.logger.New(...)
		// so logger must be non-nil.
		logger: log.New(),
		valSet: testValSet(4),
	}

	// Build a Preprepare (round > 0 so it can carry justification)
	block := makeBlock(1)

	pp := qbfttypes.NewPreprepare(big.NewInt(1), big.NewInt(1), block)
	pp.SetSignature([]byte{0xAA}) // valid outer preprepare signature per stub validateFn

	// Add a justification PREPARE with a BAD signature (0x00)
	// If verifySignatures() correctly verifies JustificationPrepares, it must fail.
	badPrepare := qbfttypes.NewPrepareWithSigAndSource(
		big.NewInt(1),
		big.NewInt(0),
		block.Hash(),
		[]byte{0x00},     // invalid per validateFn
		common.Address{}, // source is irrelevant; verifySignatures should authenticate it
	)

	pp.JustificationPrepares = []*qbfttypes.Prepare{badPrepare}
	pp.JustificationRoundChanges = nil

	err := c.verifySignatures(pp)
	if err == nil {
		t.Fatalf("expected verifySignatures(preprepare) to fail due to bad JustificationPrepares signature, but got nil")
	}
	if !errors.Is(err, errInvalidSigner) {
		t.Fatalf("expected errInvalidSigner, got: %v", err)
	}
}

// Sanity test: with valid embedded Prepare signatures, verifySignatures should pass and set sources.
func TestVerifySignatures_PreprepareAcceptsGoodJustificationPreparesAndSetsSource(t *testing.T) {
	proposerAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	validatorAddr := common.HexToAddress("0x2000000000000000000000000000000000000002")

	validateFn := func(_payload []byte, sig []byte) (common.Address, error) {
		if len(sig) == 0 {
			return common.Address{}, errors.New("empty signature")
		}
		switch sig[0] {
		case 0xAA:
			return proposerAddr, nil
		case 0xBB:
			return validatorAddr, nil
		default:
			return common.Address{}, errors.New("invalid signature")
		}
	}

	c := &core{
		validateFn: validateFn,
		logger:     log.New(),
		valSet:     testValSet(4),
	}

	block := makeBlock(1)

	pp := qbfttypes.NewPreprepare(big.NewInt(1), big.NewInt(1), block)
	pp.SetSignature([]byte{0xAA})

	goodPrepare := qbfttypes.NewPrepareWithSigAndSource(
		big.NewInt(1),
		big.NewInt(0),
		block.Hash(),
		[]byte{0xBB},
		common.Address{}, // will be overwritten by verifySignatures via SetSource
	)

	pp.JustificationPrepares = []*qbfttypes.Prepare{goodPrepare}
	pp.JustificationRoundChanges = nil

	if err := c.verifySignatures(pp); err != nil {
		t.Fatalf("expected verifySignatures(preprepare) to succeed, got: %v", err)
	}

	// verifySignatures() must SetSource on the outer message and on embedded prepares
	if pp.Source() != proposerAddr {
		t.Fatalf("expected preprepare source %s, got %s", proposerAddr.Hex(), pp.Source().Hex())
	}
	if pp.JustificationPrepares[0].Source() != validatorAddr {
		t.Fatalf("expected embedded prepare source %s, got %s", validatorAddr.Hex(), pp.JustificationPrepares[0].Source().Hex())
	}
}

// A justification longer than the validator set must be rejected BEFORE any signature
// recovery runs. This is the DoS fix: the reporter's amplification depended on the
// per-entry ecrecover loop running on an unbounded slice. We assert both that the message
// is rejected and that validateFn (the ecrecover path) was never invoked.
func TestVerifySignatures_RejectsOversizedJustificationBeforeAnyEcrecover(t *testing.T) {
	var calls int
	validateFn := func(_payload []byte, sig []byte) (common.Address, error) {
		calls++
		return common.Address{}, nil
	}

	valSet := testValSet(4) // Size() == 4, so cap is 4
	c := &core{
		validateFn: validateFn,
		logger:     log.New(),
		valSet:     valSet,
	}

	block := makeBlock(1)
	pp := qbfttypes.NewPreprepare(big.NewInt(1), big.NewInt(1), block)
	pp.SetSignature([]byte{0xAA})

	// One more round-change payload than there are validators: malformed by definition.
	oversized := make([]*qbfttypes.SignedRoundChangePayload, valSet.Size()+1)
	for i := range oversized {
		oversized[i] = &qbfttypes.SignedRoundChangePayload{}
	}
	pp.JustificationRoundChanges = oversized

	err := c.verifySignatures(pp)
	if !errors.Is(err, errInvalidMessage) {
		t.Fatalf("expected errInvalidMessage for oversized justification, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected zero ecrecover calls (rejected before signature work), got: %d", calls)
	}
}

// The same cap applies to the RoundChange.Justification (prepares) path.
func TestVerifySignatures_RejectsOversizedRoundChangeJustification(t *testing.T) {
	var calls int
	validateFn := func(_payload []byte, sig []byte) (common.Address, error) {
		calls++
		return common.Address{}, nil
	}

	valSet := testValSet(4)
	c := &core{
		validateFn: validateFn,
		logger:     log.New(),
		valSet:     valSet,
	}

	block := makeBlock(1)
	rc := qbfttypes.NewRoundChange(big.NewInt(1), big.NewInt(1), big.NewInt(0), block, false)
	rc.SetSignature([]byte{0xAA})

	oversized := make([]*qbfttypes.Prepare, valSet.Size()+1)
	for i := range oversized {
		oversized[i] = qbfttypes.NewPrepareWithSigAndSource(big.NewInt(1), big.NewInt(0), block.Hash(), []byte{0xBB}, common.Address{})
	}
	rc.Justification = oversized

	err := c.verifySignatures(rc)
	if !errors.Is(err, errInvalidMessage) {
		t.Fatalf("expected errInvalidMessage for oversized round-change justification, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected zero ecrecover calls (rejected before signature work), got: %d", calls)
	}
}

// Within a legal-length justification, identical (payload, signature) entries must be
// verified once and reuse the recovered source. This is the dedup layer: even a
// validator-set-sized slice of duplicates should trigger a single ecrecover, not one per
// entry, and every entry must still receive the correct source.
func TestVerifySignatures_DeduplicatesIdenticalJustificationPayloads(t *testing.T) {
	proposerAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	validatorAddr := common.HexToAddress("0x2000000000000000000000000000000000000002")

	var calls int
	validateFn := func(_payload []byte, sig []byte) (common.Address, error) {
		calls++
		if len(sig) == 0 {
			return common.Address{}, errors.New("empty signature")
		}
		switch sig[0] {
		case 0xAA:
			return proposerAddr, nil
		case 0xBB:
			return validatorAddr, nil
		default:
			return common.Address{}, errors.New("invalid signature")
		}
	}

	c := &core{
		validateFn: validateFn,
		logger:     log.New(),
		valSet:     testValSet(4),
	}

	block := makeBlock(1)
	pp := qbfttypes.NewPreprepare(big.NewInt(1), big.NewInt(1), block)
	pp.SetSignature([]byte{0xAA})

	// Fill the justification to the cap with IDENTICAL prepares (same round, digest, sig),
	// which encode to the same payload and so share a memo key.
	n := c.valSet.Size()
	dupes := make([]*qbfttypes.Prepare, n)
	for i := range dupes {
		dupes[i] = qbfttypes.NewPrepareWithSigAndSource(big.NewInt(1), big.NewInt(0), block.Hash(), []byte{0xBB}, common.Address{})
	}
	pp.JustificationPrepares = dupes
	pp.JustificationRoundChanges = nil

	if err := c.verifySignatures(pp); err != nil {
		t.Fatalf("expected verifySignatures to succeed, got: %v", err)
	}

	// One call for the outer message + one for the (single distinct) duplicated payload.
	if calls != 2 {
		t.Fatalf("expected 2 ecrecover calls (outer + 1 deduped payload), got: %d", calls)
	}
	// Every duplicate must still have its source set correctly.
	for i, p := range pp.JustificationPrepares {
		if p.Source() != validatorAddr {
			t.Fatalf("prepare %d: expected source %s, got %s", i, validatorAddr.Hex(), p.Source().Hex())
		}
	}
}

// A consensus message arriving before the validator set is initialised (the startup
// window where handleEvents is running but startNewRound has not yet set c.valSet) must be
// rejected, not panic. Regression test for the nil-valSet guard.
func TestVerifySignatures_RejectsMessageWhenValSetNil(t *testing.T) {
	var calls int
	c := &core{
		validateFn: func(_payload []byte, sig []byte) (common.Address, error) {
			calls++
			return common.Address{}, nil
		},
		logger: log.New(),
		valSet: nil, // startup window
	}

	block := makeBlock(1)
	pp := qbfttypes.NewPreprepare(big.NewInt(1), big.NewInt(1), block)
	pp.SetSignature([]byte{0xAA})

	err := c.verifySignatures(pp)
	if !errors.Is(err, errInvalidMessage) {
		t.Fatalf("expected errInvalidMessage when valSet is nil, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected zero ecrecover calls when valSet is nil, got: %d", calls)
	}
}
