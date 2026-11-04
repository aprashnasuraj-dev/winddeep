package eth

import (
	"context"
	"crypto/ecdsa"
	"math"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
	istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
	qbftengine "github.com/electroneum/electroneum-sc/consensus/istanbul/engine"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
	"github.com/electroneum/electroneum-sc/core"
	"github.com/electroneum/electroneum-sc/core/rawdb"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/core/vm"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/ethdb"
	"github.com/electroneum/electroneum-sc/internal/ethapi"
	"github.com/electroneum/electroneum-sc/params"
	"github.com/electroneum/electroneum-sc/rlp"
)

type rQBFTNetFixture struct {
	localDB       ethdb.Database
	remoteDB      ethdb.Database
	localChain    *core.BlockChain
	remoteChain   *core.BlockChain
	localQBFT     *istanbulbackend.Backend
	remoteQBFT    *istanbulbackend.Backend
	api           *ethapi.PublicTransactionPoolAPI
	oldTx         *types.Transaction
	oldBlock      *types.Block
	oldHead       *types.Block
	validatorKeys []*ecdsa.PrivateKey
	validators    []common.Address
}

func rQBFTBackendConfig() istanbul.Config {
	cfg := *istanbul.DefaultConfig
	cfg.ProposerPolicy = istanbul.NewRoundRobinProposerPolicy()
	return cfg
}

func rQBFTNetworkGenesis(t *testing.T, keys []*ecdsa.PrivateKey, sender common.Address) *core.Genesis {
	t.Helper()
	addrs := make([]common.Address, len(keys))
	for i, key := range keys {
		addrs[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	g := testutils.Genesis(addrs)
	cfg := *g.Config
	cfg.ChainID = big.NewInt(52014)
	cfg.FutureForkBlock = big.NewInt(math.MaxInt64)
	if cfg.IBFT != nil {
		ibft := *cfg.IBFT
		cfg.IBFT = &ibft
	}
	cfg.Ethash = nil
	g.Config = &cfg
	if g.Alloc == nil {
		g.Alloc = make(core.GenesisAlloc)
	}
	g.Alloc[sender] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))}
	return g
}

func rQBFTStartChain(t *testing.T, g *core.Genesis, key *ecdsa.PrivateKey) (ethdb.Database, *core.BlockChain, *istanbulbackend.Backend) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	be := istanbulbackend.New(rQBFTBackendConfig(), key, db)
	g.MustCommit(db)
	chain, err := core.NewBlockChain(db, nil, g.Config, be, vm.Config{}, nil, nil)
	if err != nil {
		_ = db.Close()
		t.Fatalf("R_QBFT_NET_CHAIN_CREATE_FAIL: %v", err)
	}
	if err := be.Start(chain, chain.CurrentBlock, rawdb.HasBadBlock); err != nil {
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_NET_BACKEND_START_FAIL: %v", err)
	}
	return db, chain, be
}

func rQBFTEmptyExtra(t *testing.T, addrs []common.Address) []byte {
	t.Helper()
	valset := validator.NewSet(addrs, istanbul.NewRoundRobinProposerPolicy())
	extra := &types.QBFTExtra{
		VanityData:    make([]byte, types.IstanbulExtraVanity),
		Validators:    validator.SortedAddresses(valset.List()),
		Vote:          nil,
		CommittedSeal: [][]byte{},
		Round:         0,
	}
	out, err := rlp.EncodeToBytes(extra)
	if err != nil {
		t.Fatalf("R_QBFT_NET_EXTRA_ENCODE_FAIL: %v", err)
	}
	return out
}

func rQBFTBuildAndImport(t *testing.T, chain *core.BlockChain, be *istanbulbackend.Backend, db ethdb.Database, keys []*ecdsa.PrivateKey, addrs []common.Address, tx *types.Transaction) *types.Block {
	t.Helper()
	parent := chain.CurrentBlock()
	coinbase := addrs[0]
	extra := rQBFTEmptyExtra(t, addrs)
	blocks, _ := core.GenerateChain(chain.Config(), parent, be, db, 1, func(_ int, b *core.BlockGen) {
		b.SetCoinbase(coinbase)
		b.SetExtra(extra)
		b.SetNonce(istanbulcommon.EmptyBlockNonce)
		if tx != nil {
			b.AddTx(tx)
		}
	})
	block := blocks[0]
	h := block.Header()
	h.MixDigest = types.IstanbulDigest
	h.Nonce = istanbulcommon.EmptyBlockNonce
	block = block.WithSeal(h)

	required := int(math.Ceil(float64(2*len(keys)) / 3))
	msg := qbftengine.PrepareCommittedSeal(block.Header(), 0)
	seals := make([][]byte, 0, required)
	for i := 0; i < required; i++ {
		sig, err := crypto.Sign(msg, keys[i])
		if err != nil {
			t.Fatalf("R_QBFT_NET_COMMIT_SIGN_FAIL idx=%d err=%v", i, err)
		}
		seals = append(seals, sig)
	}
	h = block.Header()
	if err := be.EngineForBlockNumber(h.Number).CommitHeader(h, seals, big.NewInt(0)); err != nil {
		t.Fatalf("R_QBFT_NET_COMMIT_HEADER_FAIL number=%d err=%v", h.Number.Uint64(), err)
	}
	block = block.WithSeal(h)
	if err := be.VerifyHeader(chain, block.Header(), false); err != nil {
		t.Fatalf("R_QBFT_NET_VERIFY_FAIL number=%d err=%v", block.NumberU64(), err)
	}
	if i, err := chain.InsertChain(types.Blocks{block}); err != nil {
		t.Fatalf("R_QBFT_NET_IMPORT_FAIL number=%d index=%d err=%v", block.NumberU64(), i, err)
	}
	return block
}

func rNewQBFTNetFixture(t *testing.T, oldLen int) *rQBFTNetFixture {
	t.Helper()
	if oldLen < 2 {
		t.Fatal("R_QBFT_NET_OLDLEN_TOO_SMALL")
	}
	keys := make([]*ecdsa.PrivateKey, 4)
	addrs := make([]common.Address, 4)
	for i := range keys {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		addrs[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	senderKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	target := common.HexToAddress("0x0000000000000000000000000000000000000042")
	genesis := rQBFTNetworkGenesis(t, keys, sender)
	localDB, localChain, localBE := rQBFTStartChain(t, genesis, keys[0])
	remoteDB, remoteChain, remoteBE := rQBFTStartChain(t, genesis, keys[0])
	if localChain.Genesis().Hash() != remoteChain.Genesis().Hash() {
		t.Fatalf("R_QBFT_NET_GENESIS_MISMATCH local=%s remote=%s", localChain.Genesis().Hash(), remoteChain.Genesis().Hash())
	}

	signer := types.LatestSigner(genesis.Config)
	var oldTx *types.Transaction
	var oldBlock *types.Block
	for i := 0; i < oldLen; i++ {
		var tx *types.Transaction
		if i == 0 {
			nonce := localChain.State().GetNonce(sender)
			gasPrice := new(big.Int)
			if localChain.CurrentBlock().BaseFee() != nil {
				gasPrice.Set(localChain.CurrentBlock().BaseFee())
			} else {
				gasPrice.SetInt64(1)
			}
			tx, err = types.SignTx(types.NewTransaction(nonce, target, big.NewInt(1), 100000, gasPrice, []byte{0x01}), signer, senderKey)
			if err != nil {
				t.Fatalf("R_QBFT_NET_TX_SIGN_FAIL: %v", err)
			}
			oldTx = tx
		}
		b := rQBFTBuildAndImport(t, localChain, localBE, localDB, keys, addrs, tx)
		if i == 0 {
			oldBlock = b
		}
	}
	for i := 0; i < oldLen+1; i++ {
		rQBFTBuildAndImport(t, remoteChain, remoteBE, remoteDB, keys, addrs, nil)
	}

	svc := &Ethereum{blockchain: localChain, chainDb: localDB}
	apiBackend := &EthAPIBackend{eth: svc}
	api := ethapi.NewPublicTransactionPoolAPI(apiBackend, new(ethapi.AddrLocker))
	before, err := api.GetTransactionReceipt(context.Background(), oldTx.Hash())
	if err != nil || before == nil || before["blockHash"] != oldBlock.Hash() {
		t.Fatalf("R_QBFT_NET_RECEIPT_CONTROL_FAIL err=%v receipt=%v", err, before)
	}
	t.Logf("R_QBFT_DEVP2P_QUORUM_BRANCH_BUILT validators=4 quorum=3 local_height=%d remote_height=%d", localChain.CurrentBlock().NumberU64(), remoteChain.CurrentBlock().NumberU64())
	return &rQBFTNetFixture{
		localDB: localDB, remoteDB: remoteDB,
		localChain: localChain, remoteChain: remoteChain,
		localQBFT: localBE, remoteQBFT: remoteBE,
		api: api, oldTx: oldTx, oldBlock: oldBlock, oldHead: localChain.CurrentBlock(),
		validatorKeys: keys, validators: addrs,
	}
}

func (f *rQBFTNetFixture) close() {
	if f.localQBFT != nil {
		_ = f.localQBFT.Stop()
	}
	if f.remoteQBFT != nil {
		_ = f.remoteQBFT.Stop()
	}
	if f.localChain != nil {
		f.localChain.Stop()
	}
	if f.remoteChain != nil {
		f.remoteChain.Stop()
	}
	if f.localDB != nil {
		_ = f.localDB.Close()
	}
	if f.remoteDB != nil {
		_ = f.remoteDB.Close()
	}
}

func TestRQBFTDevP2PQuorumReorgRace(t *testing.T) {
	depths := []int{2, 4}
	const trialsEach = 2
	var totalCalls, totalOld, totalPostcheck, totalStraddled int64
	var maxFlipToReturn int64

	for _, depth := range depths {
		for trial := 0; trial < trialsEach; trial++ {
			f := rNewQBFTNetFixture(t, depth)
			localHandler := rDevP2PHandler(t, f.localDB, f.localChain)
			remoteHandler := rDevP2PHandler(t, f.remoteDB, f.remoteChain)
			remoteServer := rDevP2PServer(t, "r-qbft-remote", remoteHandler, true)
			localServer := rDevP2PServer(t, "r-qbft-local", localHandler, false)

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
					if f.localChain.GetCanonicalHash(oldNumber) != oldHash {
						flipNs.CompareAndSwap(0, time.Now().UnixNano())
						return
					}
					runtime.Gosched()
				}
			}()

			start := make(chan struct{})
			stop := make(chan struct{})
			var stopOnce sync.Once
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
						atomic.AddInt64(&totalCalls, 1)
						if receipt != nil && receipt["blockHash"] == oldHash {
							atomic.AddInt64(&totalOld, 1)
							if f.localChain.GetCanonicalHash(oldNumber) != oldHash {
								atomic.AddInt64(&totalPostcheck, 1)
							}
							flip := flipNs.Load()
							if flip > 0 && t0 <= flip && flip <= t1 {
								atomic.AddInt64(&totalStraddled, 1)
								delta := t1 - flip
								for {
									cur := atomic.LoadInt64(&maxFlipToReturn)
									if delta <= cur || atomic.CompareAndSwapInt64(&maxFlipToReturn, cur, delta) {
										break
									}
								}
							}
						}
					}
				}()
			}
			close(start)
			stopQueries := func() {
				stopOnce.Do(func() {
					close(stop)
					wg.Wait()
					close(watchStop)
				})
			}

			localServer.AddPeer(remoteServer.Self())
			rWaitFor(t, 5*time.Second, "R_QBFT_DEVP2P_CONNECT_TIMEOUT", func() bool {
				return localServer.PeerCount() == 1 && remoteServer.PeerCount() == 1
			})
			t.Log("R_QBFT_DEVP2P_TCP_RLPX_CONNECTED")
			rWaitFor(t, 15*time.Second, "R_QBFT_DEVP2P_SYNC_TIMEOUT", func() bool {
				return f.localChain.CurrentBlock().Hash() == f.remoteChain.CurrentBlock().Hash()
			})
			deadline := time.Now().Add(2 * time.Millisecond)
			for time.Now().Before(deadline) {
				runtime.Gosched()
			}
			stopQueries()
			completed, err := f.api.GetTransactionReceipt(context.Background(), f.oldTx.Hash())
			if err != nil || completed != nil {
				t.Fatalf("R_QBFT_DEVP2P_COMPLETED_REORG_CONTROL_FAIL err=%v receipt=%v", err, completed)
			}
			t.Log("R_QBFT_DEVP2P_QUORUM_REORG_CONTROL_PASS")

			localServer.Stop()
			remoteServer.Stop()
			localHandler.Stop()
			remoteHandler.Stop()
			f.close()
		}
	}
	if totalCalls == 0 || totalOld == 0 {
		t.Fatalf("R_QBFT_DEVP2P_RACE_NOT_EXERCISED calls=%d old=%d", totalCalls, totalOld)
	}
	t.Logf("R_QBFT_DEVP2P_RACE_METRICS trials=%d calls=%d old_receipts=%d postcheck_stale=%d straddled=%d max_flip_to_return_ns=%d",
		len(depths)*trialsEach, totalCalls, totalOld, totalPostcheck, totalStraddled, maxFlipToReturn)
	if totalPostcheck > 0 || totalStraddled > 0 {
		t.Log("R_QBFT_DEVP2P_TOCTOU_OBSERVED")
	} else {
		t.Log("R_QBFT_DEVP2P_TOCTOU_NOT_OBSERVED_IN_BOUNDED_CAMPAIGN")
	}
}
