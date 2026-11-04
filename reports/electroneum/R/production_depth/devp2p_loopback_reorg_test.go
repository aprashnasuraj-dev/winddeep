package eth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/consensus"
	"github.com/electroneum/electroneum-sc/core"
	"github.com/electroneum/electroneum-sc/core/rawdb"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/eth/downloader"
	ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
	"github.com/electroneum/electroneum-sc/ethdb"
	"github.com/electroneum/electroneum-sc/p2p"
)

type rDevP2PTrialResult struct {
	calls             int64
	oldResponses      int64
	postcheckStale    int64
	straddled         int64
	maxFlipToReturnNs int64
}

func rDevP2PHandler(t *testing.T, db ethdb.Database, chain *core.BlockChain) *handler {
	t.Helper()
	h, err := newHandler(&handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     newTestTxPool(),
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    1,
		Sync:       downloader.FullSync,
		BloomCache: 1,
		Engine:     chain.Engine(),
	})
	if err != nil {
		t.Fatalf("R_DEVP2P_HANDLER_CREATE_FAIL: %v", err)
	}
	h.Start(8)
	return h
}

func rDevP2PServer(t *testing.T, name string, h *handler, noDial bool) *p2p.Server {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("R_DEVP2P_KEYGEN_FAIL: %v", err)
	}
	srv := &p2p.Server{Config: p2p.Config{
		Name:        name,
		PrivateKey:  key,
		MaxPeers:    2,
		NoDiscovery: true,
		NoDial:      noDial,
		ListenAddr:  "127.0.0.1:0",
		Protocols:   ethproto.MakeProtocols((*ethHandler)(h), 1, nil),
	}}
	if err := srv.Start(); err != nil {
		t.Fatalf("R_DEVP2P_SERVER_START_FAIL name=%s err=%v", name, err)
	}
	return srv
}

func rWaitFor(t *testing.T, timeout time.Duration, marker string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s", marker)
}

func rDevP2PTrial(t *testing.T, oldLen int) rDevP2PTrialResult {
	t.Helper()
	f := rNewFullFixture(t, oldLen)
	remoteDB, remote := rRemoteForkChain(t, f)

	localHandler := rDevP2PHandler(t, f.backend.ChainDb(), f.chain)
	remoteHandler := rDevP2PHandler(t, remoteDB, remote)
	remoteServer := rDevP2PServer(t, "r-remote", remoteHandler, true)
	localServer := rDevP2PServer(t, "r-local", localHandler, false)

	oldHash := f.oldBlock.Hash()
	oldNumber := f.oldBlock.NumberU64()
	var flipNs atomic.Int64
	watchStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-watchStop:
				return
			default:
			}
			if f.chain.GetCanonicalHash(oldNumber) != oldHash {
				flipNs.CompareAndSwap(0, time.Now().UnixNano())
				return
			}
		}
	}()

	var result rDevP2PTrialResult
	start := make(chan struct{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	const workers = 4
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				t0 := time.Now().UnixNano()
				receipt, err := f.api.GetTransactionReceipt(context.Background(), f.oldTx.Hash())
				t1 := time.Now().UnixNano()
				if err != nil {
					return
				}
				atomic.AddInt64(&result.calls, 1)
				if receipt != nil && receipt["blockHash"] == oldHash {
					atomic.AddInt64(&result.oldResponses, 1)
					if f.chain.GetCanonicalHash(oldNumber) != oldHash {
						atomic.AddInt64(&result.postcheckStale, 1)
					}
					flip := flipNs.Load()
					if flip > 0 && t0 <= flip && flip <= t1 {
						atomic.AddInt64(&result.straddled, 1)
						delta := t1 - flip
						for {
							cur := atomic.LoadInt64(&result.maxFlipToReturnNs)
							if delta <= cur || atomic.CompareAndSwapInt64(&result.maxFlipToReturnNs, cur, delta) {
								break
							}
						}
					}
				}
			}
		}()
	}
	close(start)

	var stopOnce sync.Once
	stopQueries := func() {
		stopOnce.Do(func() {
			close(stop)
			wg.Wait()
			close(watchStop)
		})
	}
	cleanup := func() {
		stopQueries()
		localServer.Stop()
		remoteServer.Stop()
		localHandler.Stop()
		remoteHandler.Stop()
		remote.Stop()
		_ = remoteDB.Close()
		f.Close()
	}
	defer cleanup()

	localServer.AddPeer(remoteServer.Self())
	rWaitFor(t, 5*time.Second, "R_DEVP2P_TCP_RLPX_PEER_CONNECT_TIMEOUT", func() bool {
		return localServer.PeerCount() == 1 && remoteServer.PeerCount() == 1
	})
	t.Logf("R_DEVP2P_TCP_RLPX_PEER_CONNECTED local=%s remote=%s", localServer.ListenAddr, remoteServer.ListenAddr)

	rWaitFor(t, 15*time.Second, "R_DEVP2P_DOWNLOADER_SYNC_TIMEOUT", func() bool {
		return f.chain.CurrentBlock().Hash() == remote.CurrentBlock().Hash()
	})
	deadline := time.Now().Add(2 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Microsecond)
	}
	stopQueries()

	completed, err := f.api.GetTransactionReceipt(context.Background(), f.oldTx.Hash())
	if err != nil || completed != nil {
		t.Fatalf("R_DEVP2P_COMPLETED_REORG_CONTROL_FAIL err=%v receipt=%v", err, completed)
	}
	if localHandler.peers.len() == 0 {
		t.Fatal("R_DEVP2P_HANDLER_PEER_REGISTRATION_MISSING")
	}
	return result
}

func TestRDevP2PLoopbackReorgReachability(t *testing.T) {
	depths := []int{2, 4, 7, 10}
	const trialsEach = 3
	var total rDevP2PTrialResult
	for _, depth := range depths {
		for trial := 0; trial < trialsEach; trial++ {
			got := rDevP2PTrial(t, depth)
			total.calls += got.calls
			total.oldResponses += got.oldResponses
			total.postcheckStale += got.postcheckStale
			total.straddled += got.straddled
			if got.maxFlipToReturnNs > total.maxFlipToReturnNs {
				total.maxFlipToReturnNs = got.maxFlipToReturnNs
			}
		}
	}
	if total.calls == 0 || total.oldResponses == 0 {
		t.Fatalf("R_DEVP2P_RACE_NOT_EXERCISED calls=%d old=%d", total.calls, total.oldResponses)
	}
	t.Logf("R_DEVP2P_REORG_RACE_METRICS trials=%d calls=%d old_receipts=%d postcheck_stale=%d straddled=%d max_flip_to_return_ns=%d",
		len(depths)*trialsEach, total.calls, total.oldResponses, total.postcheckStale, total.straddled, total.maxFlipToReturnNs)
	if total.postcheckStale > 0 || total.straddled > 0 {
		t.Log("R_DEVP2P_TOCTOU_OBSERVED")
	} else {
		t.Log("R_DEVP2P_TOCTOU_NOT_OBSERVED_IN_BOUNDED_CAMPAIGN")
	}
	t.Log("R_DEVP2P_DOWNLOADER_REORG_CONTROL_PASS")
}
