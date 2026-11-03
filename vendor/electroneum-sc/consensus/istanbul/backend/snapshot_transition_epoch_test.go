// Copyright 2017 The go-ethereum Authors
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

package backend

import (
	"bytes"
	"crypto/ecdsa"
	"math"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
	qbftengine "github.com/electroneum/electroneum-sc/consensus/istanbul/engine"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/params"
)

// TestSnapshotEpochTransitionResetsVotesPostFutureFork is a regression test for
// the stale-epoch snapshot bug: Snapshot.Epoch is only seeded at genesis/load and
// copied forward, so an EpochLength transition never refreshes the epoch used for
// checkpoint vote-resets in snapApplyHeader. Votes cast before the transition then
// survive past the first checkpoint of the new (shorter) epoch schedule and combine
// with later votes, authorizing a validator with fewer fresh post-transition votes
// than the transitioned rules should allow.
//
// The fix reads the effective epoch from config.GetConfig(header.Number) and is
// gated on IsFutureFork. This test runs with FutureFork active from genesis and
// asserts the corrected behavior; a control run with FutureFork disabled asserts
// the legacy (unfixed) tally is preserved for pre-fork replay compatibility.
//
// Scenario (4 validators A,B,C,D; initial epoch 10; transition at block 3 -> epoch 3):
//
//	block 1: A votes to authorize E
//	block 2: no vote
//	block 3: C votes to authorize E   (first checkpoint of epoch length 3 -> votes reset here)
//	block 4: D votes to authorize E
//
// Correct post-transition behavior: block 3 clears A's stale vote, leaving only the
// fresh votes C and D (2 of 4, not a majority of >2), so E is NOT authorized.
// Buggy behavior: A's vote survives, so A+C+D authorize E.
func TestSnapshotEpochTransitionResetsVotesPostFutureFork(t *testing.T) {
	const (
		initialEpoch    = 10
		transitionBlock = 3
		newEpoch        = 3
	)

	// futureFork==true activates the fix from genesis; the fixed node must NOT
	// authorize E. futureFork==false keeps the legacy path; E remains authorized,
	// which documents that the change is fully gated.
	for _, tc := range []struct {
		name         string
		futureFork   bool
		wantEAuthzed bool
	}{
		{name: "FutureFork active - stale vote cleared", futureFork: true, wantEAuthzed: false},
		{name: "FutureFork disabled - legacy behavior preserved", futureFork: false, wantEAuthzed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accounts := newTesterAccountPool()

			validatorNames := []string{"A", "B", "C", "D"}
			validators := make([]common.Address, len(validatorNames))
			for i, name := range validatorNames {
				validators[i] = accounts.address(name)
			}
			// Snapshot expects validators in ascending address order.
			for i := 0; i < len(validators); i++ {
				for j := i + 1; j < len(validators); j++ {
					if bytes.Compare(validators[i][:], validators[j][:]) > 0 {
						validators[i], validators[j] = validators[j], validators[i]
					}
				}
			}

			genesis := testutils.Genesis(validators)

			// Genesis assigns the shared params.TestChainConfig pointer; copy it so
			// per-test overrides (FutureForkBlock, Transitions) do not leak across tests.
			cfgCopy := *genesis.Config
			if tc.futureFork {
				cfgCopy.FutureForkBlock = big.NewInt(0)
			} else {
				cfgCopy.FutureForkBlock = big.NewInt(math.MaxInt64)
			}
			genesis.Config = &cfgCopy

			config := istanbul.Config{
				RequestTimeoutSeconds:    istanbul.DefaultConfig.RequestTimeoutSeconds,
				MaxRequestTimeoutSeconds: istanbul.DefaultConfig.MaxRequestTimeoutSeconds,
				BlockPeriod:              istanbul.DefaultConfig.BlockPeriod,
				ProposerPolicy:           istanbul.DefaultConfig.ProposerPolicy,
				Epoch:                    initialEpoch,
				AllowedFutureBlockTime:   istanbul.DefaultConfig.AllowedFutureBlockTime,
				Transitions: []params.Transition{
					{Block: big.NewInt(transitionBlock), EpochLength: newEpoch},
				},
			}

			chain, backend := newBlockchainFromConfig(
				genesis,
				[]*ecdsa.PrivateKey{accounts.accounts["A"]},
				config,
			)
			defer backend.Stop()

			votes := []testerVote{
				{validator: "A", voted: "E", auth: true},
				{validator: "B"},
				{validator: "C", voted: "E", auth: true},
				{validator: "D", voted: "E", auth: true},
			}

			headers := make([]*types.Header, len(votes))
			for j, vote := range votes {
				blockNumber := big.NewInt(int64(j) + 1)
				headers[j] = &types.Header{
					Number:     blockNumber,
					Time:       uint64(int64(j) * int64(config.GetConfig(blockNumber).BlockPeriod)),
					Coinbase:   accounts.address(vote.validator),
					Difficulty: istanbulcommon.DefaultDifficulty,
					MixDigest:  types.IstanbulDigest,
				}
				_ = qbftengine.ApplyHeaderQBFTExtra(
					headers[j],
					qbftengine.WriteValidators(validators),
				)
				if j > 0 {
					headers[j].ParentHash = headers[j-1].Hash()
				}
				copy(headers[j].Extra, genesis.ExtraData)

				if len(vote.voted) > 0 {
					if err := accounts.writeValidatorVote(headers[j], vote.validator, vote.voted, vote.auth); err != nil {
						t.Fatalf("vote %d: writeValidatorVote failed: %v", j, err)
					}
				}
			}

			head := headers[len(headers)-1]
			snap, err := backend.snapshot(chain, head.Number.Uint64(), head.Hash(), headers)
			if err != nil {
				t.Fatalf("failed to create voting snapshot: %v", err)
			}

			_, e := snap.ValSet.GetByAddress(accounts.address("E"))
			gotEAuthzed := e != nil
			if gotEAuthzed != tc.wantEAuthzed {
				t.Fatalf("E authorized = %v, want %v (validators: %x)",
					gotEAuthzed, tc.wantEAuthzed, snap.validators())
			}

			// After the transition the effective epoch must be the post-transition
			// value regardless of the gate; the gate only governs whether the reset
			// used it. Assert the config layer agrees so the scenario stays valid.
			if got := config.GetConfig(head.Number).Epoch; got != newEpoch {
				t.Fatalf("effective epoch at block %d = %d, want %d", head.Number, got, newEpoch)
			}
		})
	}
}
