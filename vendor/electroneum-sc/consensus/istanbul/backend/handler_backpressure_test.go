// Copyright 2024 The go-ethereum Authors
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
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/core/rawdb"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/p2p"
)

// newStartedBackend returns a backend whose core is flagged started but whose
// event mux has no real consensus consumer attached yet. Tests attach their own
// subscription so they control the drain rate.
func newStartedBackend(t *testing.T) *Backend {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	b := New(copyConfig(istanbul.DefaultConfig), key, rawdb.NewMemoryDatabase())
	b.coreStarted = true
	return b
}

// buildQBFTMsg builds a unique consensus-coded p2p message of the given size.
// The payload is deliberately not a valid RLP QBFT message: the point is that
// the ingress path must queue/deliver it before any decode or signature check,
// so the bytes never need to be well-formed.
func buildQBFTMsg(seed, payloadSize int) p2p.Msg {
	payload := bytes.Repeat([]byte{0x42}, payloadSize)
	if payloadSize >= 8 {
		binary.BigEndian.PutUint64(payload[:8], uint64(seed))
	}
	return p2p.Msg{
		Code:    qbfttypes.PreprepareCode,
		Size:    uint32(len(payload)),
		Payload: bytes.NewReader(payload),
	}
}

// waitForGoroutines blocks until the live goroutine count drops to at most
// target, or the deadline passes. Returns the final count.
func waitForGoroutines(target int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		n := runtime.NumGoroutine()
		if n <= target || time.Now().After(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestHandleMsgDoesNotQueueAheadOfConsumer is the inverse of the reported PoC.
// With synchronous delivery, HandleMsg must NOT return before the single
// consumer has accepted the event, so a slow consumer cannot be outrun and no
// backlog of blocked post goroutines can form. We drive one message against a
// consumer that is parked (not yet reading) and assert HandleMsg is still
// blocked — the exact opposite of the vulnerable behavior.
func TestHandleMsgDoesNotQueueAheadOfConsumer(t *testing.T) {
	backend := newStartedBackend(t)

	var releaseOnce sync.Once
	release := make(chan struct{})
	releaseConsumer := func() { releaseOnce.Do(func() { close(release) }) }

	sub := backend.EventMux().Subscribe(istanbul.MessageEvent{})
	go func() {
		// Park until released, then drain so HandleMsg can complete and the
		// test can exit cleanly.
		<-release
		for range sub.Chan() {
		}
	}()
	t.Cleanup(func() {
		releaseConsumer()
		sub.Unsubscribe()
	})

	returned := make(chan struct{})
	go func() {
		backend.HandleMsg(common.StringToAddress("attacker"), buildQBFTMsg(1, 4096))
		close(returned)
	}()

	// While the consumer is parked, a synchronous Post must keep HandleMsg
	// blocked. If it returns here, delivery is still asynchronous.
	select {
	case <-returned:
		t.Fatal("HandleMsg returned before the consumer accepted the event: delivery is not applying backpressure")
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked on the unbuffered mux
	}

	// Release the consumer; HandleMsg must now complete.
	releaseConsumer()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleMsg never returned after the consumer started draining")
	}
}

// TestHandleMsgFloodDoesNotAccumulateGoroutines reproduces the attacker model
// from the report (many unique large consensus frames) but asserts the fixed
// invariant: because each HandleMsg blocks until its event is consumed, a
// serial caller cannot build a heap-pinning backlog of blocked post
// goroutines. After the flood completes, the goroutine count must return to
// near baseline rather than growing ~linearly with the number of frames.
func TestHandleMsgFloodDoesNotAccumulateGoroutines(t *testing.T) {
	backend := newStartedBackend(t)

	sub := backend.EventMux().Subscribe(istanbul.MessageEvent{})
	var processed atomic.Int32
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range sub.Chan() {
			processed.Add(1)
			// Model a non-trivial (but not pathological) consumer cost.
			time.Sleep(2 * time.Millisecond)
		}
	}()

	baseline := runtime.NumGoroutine()

	const (
		messageCount = 40
		payloadSize  = 256 * 1024
	)

	// Emulate the real per-peer read loop: one message fully handled before the
	// next is read. With synchronous delivery each call blocks until consumed,
	// so this whole loop is naturally rate-limited by the consumer.
	for i := 0; i < messageCount; i++ {
		handled, err := backend.HandleMsg(common.StringToAddress("attacker"), buildQBFTMsg(i, payloadSize))
		if err != nil {
			t.Fatalf("message %d returned error: %v", i, err)
		}
		if !handled {
			t.Fatalf("message %d was not handled", i)
		}
		// At no point should a large backlog of post goroutines exist. Allow a
		// small constant slack for the in-flight post plus scheduler noise.
		if growth := runtime.NumGoroutine() - baseline; growth > 5 {
			t.Fatalf("goroutine backlog forming mid-flood: growth=%d after %d messages (want <=5)", growth, i+1)
		}
	}

	sub.Unsubscribe()
	<-drained

	// Every message must have been delivered. The consumer's counter increment
	// trails the mux receive by a scheduling instant, so assert after the
	// consumer goroutine has fully drained rather than the moment the last
	// HandleMsg returned.
	if processed.Load() != messageCount {
		t.Fatalf("expected all %d messages delivered synchronously, got %d", messageCount, processed.Load())
	}

	if final := waitForGoroutines(baseline+2, 2*time.Second); final > baseline+2 {
		t.Fatalf("goroutines did not return to baseline after flood: baseline=%d final=%d", baseline, final)
	}
}

// TestHandleMsgDeliversPayloadIntactAndInOrder verifies the fix did not change
// observable delivery semantics: every message's code and payload arrive
// unchanged, and (because a single serial caller now blocks per message)
// strictly in send order.
func TestHandleMsgDeliversPayloadIntactAndInOrder(t *testing.T) {
	backend := newStartedBackend(t)

	sub := backend.EventMux().Subscribe(istanbul.MessageEvent{})
	type got struct {
		code    uint64
		payload []byte
	}
	received := make(chan got, 8)
	go func() {
		for ev := range sub.Chan() {
			me := ev.Data.(istanbul.MessageEvent)
			received <- got{code: me.Code, payload: me.Payload}
		}
	}()
	t.Cleanup(func() { sub.Unsubscribe() })

	const n = 6
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 128+i)
		msg := p2p.Msg{Code: qbfttypes.PreprepareCode, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}
		handled, err := backend.HandleMsg(common.StringToAddress("peer"), msg)
		if err != nil || !handled {
			t.Fatalf("message %d not handled cleanly: handled=%v err=%v", i, handled, err)
		}
	}

	for i := 0; i < n; i++ {
		select {
		case r := <-received:
			if r.code != qbfttypes.PreprepareCode {
				t.Fatalf("message %d: unexpected code 0x%x", i, r.code)
			}
			want := bytes.Repeat([]byte{byte(i)}, 128+i)
			if !bytes.Equal(r.payload, want) {
				t.Fatalf("message %d: payload mismatch (len got=%d want=%d)", i, len(r.payload), len(want))
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for message %d", i)
		}
	}
}

// TestHandleMsgDedupSkipsPostForKnownHash confirms the pre-existing known-hash
// short-circuit is preserved and still avoids the (now synchronous) Post. A
// repeated payload must be handled but must not be delivered a second time, so
// a parked consumer can never be blocked by duplicates.
func TestHandleMsgDedupSkipsPostForKnownHash(t *testing.T) {
	backend := newStartedBackend(t)

	sub := backend.EventMux().Subscribe(istanbul.MessageEvent{})
	var delivered atomic.Int32
	go func() {
		for range sub.Chan() {
			delivered.Add(1)
		}
	}()
	t.Cleanup(func() { sub.Unsubscribe() })

	payload := bytes.Repeat([]byte{0x7}, 512)
	newMsg := func() p2p.Msg {
		return p2p.Msg{Code: qbfttypes.PreprepareCode, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}
	}

	// First delivery: handled and delivered.
	if handled, err := backend.HandleMsg(common.StringToAddress("peer"), newMsg()); err != nil || !handled {
		t.Fatalf("first message not handled: handled=%v err=%v", handled, err)
	}

	// Second, identical payload: handled true, but must NOT post again. If the
	// dedup were broken the synchronous Post would block here forever because
	// only one reader receive is outstanding; guard with a timeout goroutine.
	secondDone := make(chan struct{})
	go func() {
		handled, err := backend.HandleMsg(common.StringToAddress("peer"), newMsg())
		if err != nil || !handled {
			t.Errorf("second (duplicate) message not handled: handled=%v err=%v", handled, err)
		}
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(1 * time.Second):
		t.Fatal("duplicate message blocked in HandleMsg: dedup no longer short-circuits before the synchronous Post")
	}

	// Exactly one delivery total.
	time.Sleep(100 * time.Millisecond)
	if got := delivered.Load(); got != 1 {
		t.Fatalf("expected exactly 1 delivery for duplicate payloads, got %d", got)
	}
}

// TestHandleMsgBlockedPostDoesNotWedgeCoreMu proves the primary risk of making
// Post synchronous is not realized: while HandleMsg is parked in a synchronous
// Post it holds coreMu, but the consumer loop that drains the mux never needs
// coreMu, so (a) HandleMsg unblocks as soon as a consumer receives, and (b) a
// concurrent coreMu acquirer (e.g. Stop/Start/NewChainHead) proceeds right
// after. A regression that made the consumer path depend on coreMu, or that
// held the lock indefinitely, would deadlock this test.
func TestHandleMsgBlockedPostDoesNotWedgeCoreMu(t *testing.T) {
	backend := newStartedBackend(t)

	// Subscribe but do NOT drain yet: the first HandleMsg will park in Post
	// while holding coreMu.
	sub := backend.EventMux().Subscribe(istanbul.MessageEvent{})
	t.Cleanup(func() { sub.Unsubscribe() })

	parked := make(chan struct{})
	go func() {
		close(parked)
		backend.HandleMsg(common.StringToAddress("attacker"), buildQBFTMsg(1, 4096))
	}()
	<-parked
	// Give the goroutine a moment to actually acquire coreMu and block in Post.
	time.Sleep(50 * time.Millisecond)

	// A concurrent coreMu acquirer must not be able to proceed while HandleMsg
	// holds the lock — but it MUST proceed once we drain.
	lockFreed := make(chan struct{})
	go func() {
		// This will block until the parked HandleMsg releases coreMu.
		backend.coreMu.Lock()
		backend.coreMu.Unlock()
		close(lockFreed)
	}()

	// Before draining, the lock acquirer should still be blocked.
	select {
	case <-lockFreed:
		t.Fatal("coreMu was acquired while HandleMsg should still hold it (parked in Post)")
	case <-time.After(100 * time.Millisecond):
		// expected
	}

	// Now drain a single event: HandleMsg's Post completes, it releases coreMu,
	// and the waiting acquirer proceeds. If the consumer path needed coreMu this
	// would deadlock and the test would time out.
	go func() {
		for range sub.Chan() {
		}
	}()

	select {
	case <-lockFreed:
		// success: synchronous Post released coreMu once the consumer drained
	case <-time.After(3 * time.Second):
		t.Fatal("coreMu never freed after draining: synchronous Post wedged the lock (possible deadlock)")
	}
}

// TestHandleMsgStoppedEngineDoesNotPost ensures the not-started guard still
// returns before any delivery, so messages arriving before the consumer exists
// cannot block or leak.
func TestHandleMsgStoppedEngineDoesNotPost(t *testing.T) {
	backend := newStartedBackend(t)
	backend.coreStarted = false

	handled, err := backend.HandleMsg(common.StringToAddress("peer"), buildQBFTMsg(1, 256))
	if !handled {
		t.Fatalf("expected handled=true for consensus code even when stopped")
	}
	if err != istanbul.ErrStoppedEngine {
		t.Fatalf("expected ErrStoppedEngine, got %v", err)
	}
}
