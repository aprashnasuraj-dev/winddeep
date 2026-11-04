package eth

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/core"
	"github.com/electroneum/electroneum-sc/core/forkid"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/eth/downloader"
	ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
	"github.com/electroneum/electroneum-sc/internal/ethapi"
	"github.com/electroneum/electroneum-sc/p2p"
	qbftengine "github.com/electroneum/electroneum-sc/consensus/istanbul/engine"
)

type rP1HWireState struct {
	handshakes      atomic.Int64
	headerRequests  atomic.Int64
	headerResponses atomic.Int64
	bodyRequests    atomic.Int64
	bodyResponses   atomic.Int64
	receiptRequests atomic.Int64
}

func rP1HValidators(t *testing.T) ([]*ecdsa.PrivateKey, []common.Address) {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, 4)
	addrs := make([]common.Address, 4)
	for i := range keys {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("R_P1H_VALIDATOR_KEYGEN_FAIL idx=%d err=%v", i, err)
		}
		keys[i] = key
		addrs[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	return keys, addrs
}

func rP1HRemoteHeaders(query *ethproto.GetBlockHeadersPacket, genesis, head *types.Header) []*types.Header {
	if query == nil || query.Amount == 0 {
		return nil
	}
	byNumber := map[uint64]*types.Header{
		genesis.Number.Uint64(): genesis,
		head.Number.Uint64():    head,
	}
	byHash := map[common.Hash]*types.Header{
		genesis.Hash(): genesis,
		head.Hash():    head,
	}

	var current *types.Header
	if query.Origin.Hash != (common.Hash{}) {
		current = byHash[query.Origin.Hash]
	} else {
		current = byNumber[query.Origin.Number]
	}
	if current == nil {
		return nil
	}
	out := make([]*types.Header, 0, query.Amount)
	step := query.Skip + 1
	for uint64(len(out)) < query.Amount && current != nil {
		out = append(out, current)
		n := current.Number.Uint64()
		if query.Reverse {
			if n < step {
				break
			}
			current = byNumber[n-step]
		} else {
			if n > ^uint64(0)-step {
				break
			}
			current = byNumber[n+step]
		}
	}
	return out
}

func rP1HRemoteProtocol(t *testing.T, genesis *types.Block, head *types.Block, advertisedTD *big.Int, forkID forkid.ID, state *rP1HWireState) p2p.Protocol {
	t.Helper()
	return p2p.Protocol{
		Name:    ethproto.ProtocolName,
		Version: ethproto.ETH66,
		Length:  17,
		Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
			peer := ethproto.NewPeer(ethproto.ETH66, p, rw, newTestTxPool())
			defer peer.Close()

			if err := peer.Handshake(1, advertisedTD, head.Hash(), genesis.Hash(), forkID, func(forkid.ID) error { return nil }); err != nil {
				return err
			}
			state.handshakes.Add(1)

			for {
				msg, err := rw.ReadMsg()
				if err != nil {
					return err
				}
				switch msg.Code {
				case ethproto.GetBlockHeadersMsg:
					var query ethproto.GetBlockHeadersPacket66
					if err := msg.Decode(&query); err != nil {
						msg.Discard()
						return err
					}
					msg.Discard()
					state.headerRequests.Add(1)
					headers := rP1HRemoteHeaders(query.GetBlockHeadersPacket, genesis.Header(), head.Header())
					if err := p2p.Send(rw, ethproto.BlockHeadersMsg, &ethproto.BlockHeadersPacket66{
						RequestId:          query.RequestId,
						BlockHeadersPacket: headers,
					}); err != nil {
						return err
					}
					state.headerResponses.Add(1)

				case ethproto.GetBlockBodiesMsg:
					var query ethproto.GetBlockBodiesPacket66
					if err := msg.Decode(&query); err != nil {
						msg.Discard()
						return err
					}
					msg.Discard()
					state.bodyRequests.Add(1)
					bodies := make(ethproto.BlockBodiesPacket, 0, len(query.GetBlockBodiesPacket))
					for _, hash := range query.GetBlockBodiesPacket {
						if hash == head.Hash() {
							bodies = append(bodies, &ethproto.BlockBody{
								Transactions: head.Transactions(),
								Uncles:       head.Uncles(),
							})
						}
					}
					if err := p2p.Send(rw, ethproto.BlockBodiesMsg, &ethproto.BlockBodiesPacket66{
						RequestId:         query.RequestId,
						BlockBodiesPacket: bodies,
					}); err != nil {
						return err
					}
					state.bodyResponses.Add(1)

				case ethproto.GetReceiptsMsg:
					var query ethproto.GetReceiptsPacket66
					if err := msg.Decode(&query); err != nil {
						msg.Discard()
						return err
					}
					msg.Discard()
					state.receiptRequests.Add(1)
					receipts := make(ethproto.ReceiptsPacket, 0, len(query.GetReceiptsPacket))
					for _, hash := range query.GetReceiptsPacket {
						if hash == head.Hash() {
							receipts = append(receipts, []*types.Receipt{})
						}
					}
					if err := p2p.Send(rw, ethproto.ReceiptsMsg, &ethproto.ReceiptsPacket66{
						RequestId:      query.RequestId,
						ReceiptsPacket: receipts,
					}); err != nil {
						return err
					}

				default:
					msg.Discard()
					// The lower-authority fixture is a retrieval peer only. Ignore
					// unrelated broadcasts; the downloader requests above remain the
					// evidence-bearing path for this campaign.
				}
			}
		},
	}
}

func rP1HRemoteServer(t *testing.T, name string, protocol p2p.Protocol) *p2p.Server {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("R_P1H_REMOTE_P2P_KEYGEN_FAIL: %v", err)
	}
	srv := &p2p.Server{Config: p2p.Config{
		Name:        name,
		PrivateKey:  key,
		MaxPeers:    1,
		NoDiscovery: true,
		NoDial:      true,
		ListenAddr:  "127.0.0.1:0",
		Protocols:   []p2p.Protocol{protocol},
	}}
	if err := srv.Start(); err != nil {
		t.Fatalf("R_P1H_REMOTE_SERVER_START_FAIL: %v", err)
	}
	return srv
}

func rP1HWaitRegisteredPeer(t *testing.T, h *handler, remote *p2p.Server) *ethPeer {
	t.Helper()
	id := remote.Self().ID().String()
	var peer *ethPeer
	rWaitFor(t, 5*time.Second, "R_P1H_ETH66_PEER_REGISTER_TIMEOUT", func() bool {
		peer = h.peers.peer(id)
		return peer != nil
	})
	return peer
}

func rP1HMakeSubquorum(t *testing.T, valid *types.Block, keys []*ecdsa.PrivateKey) *types.Block {
	t.Helper()
	if len(keys) != 4 {
		t.Fatalf("R_P1H_BAD_VALIDATOR_COUNT got=%d", len(keys))
	}
	header := valid.Header()
	msg := qbftengine.PrepareCommittedSeal(header, 0)
	seals := make([][]byte, 0, 2)
	for _, key := range keys[:2] {
		sig, err := crypto.Sign(msg, key)
		if err != nil {
			t.Fatalf("R_P1H_SUBQUORUM_SIGN_FAIL: %v", err)
		}
		seals = append(seals, sig)
	}
	extra, err := types.ExtractQBFTExtra(header)
	if err != nil {
		t.Fatalf("R_P1H_SUBQUORUM_EXTRA_DECODE_FAIL: %v", err)
	}
	extra.CommittedSeal = seals
	payload, err := rlp.EncodeToBytes(extra)
	if err != nil {
		t.Fatalf("R_P1H_SUBQUORUM_EXTRA_ENCODE_FAIL: %v", err)
	}
	header.Extra = payload
	invalid := valid.WithSeal(header)
	if invalid.Hash() == valid.Hash() {
		t.Fatal("R_P1H_SUBQUORUM_HASH_DID_NOT_CHANGE")
	}
	return invalid
}

func rP1HSignedTx(t *testing.T, chain *core.BlockChain, key *ecdsa.PrivateKey, marker byte) *types.Transaction {
	t.Helper()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	state, err := chain.State()
	if err != nil {
		t.Fatalf("R_P1H_TX_STATE_FAIL: %v", err)
	}
	nonce := state.GetNonce(sender)
	target := common.HexToAddress("0x0000000000000000000000000000000000000043")
	tx, err := types.SignTx(
		types.NewTransaction(nonce, target, big.NewInt(1), 100000, big.NewInt(10_000_000_000), []byte{marker}),
		types.LatestSigner(chain.Config()),
		key,
	)
	if err != nil {
		t.Fatalf("R_P1H_REMOTE_TX_SIGN_FAIL: %v", err)
	}
	return tx
}

func rP1HBaseFixture(t *testing.T) (*rQBFTNetFixture, *ecdsa.PrivateKey) {
	t.Helper()
	keys, addrs := rP1HValidators(t)
	senderKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	genesis := rQBFTNetworkGenesis(t, keys, sender)

	localDB, localChain, localBE := rQBFTStartChain(t, genesis, keys[0])
	remoteDB, remoteChain, remoteBE := rQBFTStartChain(t, genesis, keys[0])
	return &rQBFTNetFixture{
		localDB: localDB, remoteDB: remoteDB,
		localChain: localChain, remoteChain: remoteChain,
		localQBFT: localBE, remoteQBFT: remoteBE,
		validatorKeys: keys, validators: addrs,
	}, senderKey
}

func TestRP1HQuorumWirePositiveControl(t *testing.T) {
	f, senderKey := rP1HBaseFixture(t)
	defer f.close()

	remoteTx := rP1HSignedTx(t, f.remoteChain, senderKey, 0x91)
	valid := rQBFTBuildAndImport(t, f.remoteChain, f.remoteQBFT, f.remoteDB, f.validatorKeys, f.validators, remoteTx)
	remoteTD := f.remoteChain.GetTd(valid.Hash(), valid.NumberU64())
	if remoteTD == nil {
		t.Fatal("R_P1H_POSITIVE_REMOTE_TD_MISSING")
	}

	localHandler := rDevP2PHandler(t, f.localDB, f.localChain)
	defer localHandler.Stop()
	localServer := rDevP2PServer(t, "r-p1h-positive-local", localHandler, false)
	defer localServer.Stop()

	wire := new(rP1HWireState)
	remoteServer := rP1HRemoteServer(t, "r-p1h-positive-remote", rP1HRemoteProtocol(t, f.localChain.Genesis(), valid, remoteTD, forkid.NewID(f.localChain.Config(), f.localChain.Genesis().Hash(), valid.NumberU64()), wire))
	defer remoteServer.Stop()

	localServer.AddPeer(remoteServer.Self())
	peer := rP1HWaitRegisteredPeer(t, localHandler, remoteServer)
	if wire.handshakes.Load() == 0 {
		t.Fatal("R_P1H_POSITIVE_ETH66_HANDSHAKE_MISSING")
	}
	head, td := peer.Head()
	if head != valid.Hash() {
		t.Fatalf("R_P1H_POSITIVE_ADVERTISED_HEAD_MISMATCH got=%s want=%s", head, valid.Hash())
	}
	if err := localHandler.downloader.LegacySync(peer.ID(), head, td, f.localChain.Config().TerminalTotalDifficulty, downloader.FullSync); err != nil {
		t.Fatalf("R_P1H_QUORUM_WIRE_SYNC_FAIL: %v", err)
	}
	if f.localChain.CurrentBlock().Hash() != valid.Hash() {
		t.Fatalf("R_P1H_QUORUM_WIRE_HEAD_MISMATCH got=%s want=%s", f.localChain.CurrentBlock().Hash(), valid.Hash())
	}
	if wire.headerResponses.Load() == 0 || wire.bodyResponses.Load() == 0 {
		t.Fatalf("R_P1H_QUORUM_WIRE_PATH_INCOMPLETE headers=%d bodies=%d", wire.headerResponses.Load(), wire.bodyResponses.Load())
	}
	t.Logf("R_P1H_QUORUM_ETH66_DOWNLOADER_ACCEPTED validators=4 seals=3 headers=%d bodies=%d", wire.headerResponses.Load(), wire.bodyResponses.Load())
	t.Log("R_P1H_QUORUM_WIRE_POSITIVE_CONTROL_PASS")
}

func TestRP1HLowerAuthoritySubquorumRejected(t *testing.T) {
	f, senderKey := rP1HBaseFixture(t)
	defer f.close()

	// Establish a canonical receipt on the local branch.
	signer := types.LatestSigner(f.localChain.Config())
	target := common.HexToAddress("0x0000000000000000000000000000000000000042")
	oldTx, err := types.SignTx(types.NewTransaction(0, target, big.NewInt(1), 100000, big.NewInt(10_000_000_000), []byte{0x01}), signer, senderKey)
	if err != nil {
		t.Fatalf("R_P1H_OLD_TX_SIGN_FAIL: %v", err)
	}
	oldBlock := rQBFTBuildAndImport(t, f.localChain, f.localQBFT, f.localDB, f.validatorKeys, f.validators, oldTx)
	f.oldTx, f.oldBlock, f.oldHead = oldTx, oldBlock, oldBlock
	svc := &Ethereum{blockchain: f.localChain, chainDb: f.localDB}
	backend := &EthAPIBackend{eth: svc}
	f.api = ethapi.NewPublicTransactionPoolAPI(backend, new(ethapi.AddrLocker))

	before, err := f.api.GetTransactionReceipt(context.Background(), oldTx.Hash())
	if err != nil || before == nil || before["blockHash"] != oldBlock.Hash() {
		t.Fatalf("R_P1H_OLD_RECEIPT_CONTROL_FAIL err=%v receipt=%v", err, before)
	}

	// Build the same-height competing block with a valid quorum first, then
	// replace its committed-seal set with only 2-of-4. The peer will serve this
	// block directly over ETN/66 without importing the invalid block itself.
	remoteTx := rP1HSignedTx(t, f.remoteChain, senderKey, 0x92)
	validCompeting := rQBFTBuildAndImport(t, f.remoteChain, f.remoteQBFT, f.remoteDB, f.validatorKeys, f.validators, remoteTx)
	invalid := rP1HMakeSubquorum(t, validCompeting, f.validatorKeys)
	verifyErr := f.localQBFT.VerifyHeader(f.localChain, invalid.Header(), false)
	if verifyErr == nil {
		t.Fatal("R_P1H_SUBQUORUM_DIRECT_VERIFIER_UNEXPECTED_ACCEPT")
	}
	t.Logf("R_P1H_SUBQUORUM_DIRECT_VERIFIER_REJECTED validators=4 seals=2 err=%v", verifyErr)

	localTD := f.localChain.GetTd(oldBlock.Hash(), oldBlock.NumberU64())
	if localTD == nil {
		t.Fatal("R_P1H_LOCAL_TD_MISSING")
	}
	// A malicious peer may lie about TD. Advertise a better chain to force the
	// downloader to retrieve and validate the actual supplied header/body.
	advertisedTD := new(big.Int).Add(localTD, big.NewInt(1))

	localHandler := rDevP2PHandler(t, f.localDB, f.localChain)
	defer localHandler.Stop()
	localServer := rDevP2PServer(t, "r-p1h-negative-local", localHandler, false)
	defer localServer.Stop()

	wire := new(rP1HWireState)
	remoteServer := rP1HRemoteServer(t, "r-p1h-subquorum-remote", rP1HRemoteProtocol(t, f.localChain.Genesis(), invalid, advertisedTD, forkid.NewID(f.localChain.Config(), f.localChain.Genesis().Hash(), invalid.NumberU64()), wire))
	defer remoteServer.Stop()

	var receiptCalls, staleReceipts, receiptErrors atomic.Int64
	stopReceipts := make(chan struct{})
	receiptDone := make(chan struct{})
	go func() {
		defer close(receiptDone)
		for {
			select {
			case <-stopReceipts:
				return
			default:
			}
			receipt, err := f.api.GetTransactionReceipt(context.Background(), oldTx.Hash())
			if err != nil {
				receiptErrors.Add(1)
				continue
			}
			receiptCalls.Add(1)
			if receipt != nil {
				canonical := f.localChain.GetCanonicalHash(oldBlock.NumberU64())
				if got := receipt["blockHash"]; got != canonical {
					staleReceipts.Add(1)
				}
			}
		}
	}()

	localServer.AddPeer(remoteServer.Self())
	peer := rP1HWaitRegisteredPeer(t, localHandler, remoteServer)
	head, td := peer.Head()
	if head != invalid.Hash() {
		close(stopReceipts)
		<-receiptDone
		t.Fatalf("R_P1H_SUBQUORUM_ADVERTISED_HEAD_MISMATCH got=%s want=%s", head, invalid.Hash())
	}
	syncErr := localHandler.downloader.LegacySync(peer.ID(), head, td, f.localChain.Config().TerminalTotalDifficulty, downloader.FullSync)
	close(stopReceipts)
	<-receiptDone

	if syncErr == nil {
		t.Fatal("R_P1H_SUBQUORUM_DOWNLOADER_UNEXPECTED_ACCEPT")
	}
	if !strings.Contains(syncErr.Error(), "invalid") {
		t.Fatalf("R_P1H_SUBQUORUM_WRONG_SYNC_FAILURE: %v", syncErr)
	}
	if wire.handshakes.Load() == 0 || wire.headerResponses.Load() == 0 || wire.bodyResponses.Load() == 0 {
		t.Fatalf("R_P1H_SUBQUORUM_WIRE_PATH_INCOMPLETE handshakes=%d headers=%d bodies=%d",
			wire.handshakes.Load(), wire.headerResponses.Load(), wire.bodyResponses.Load())
	}
	if f.localChain.CurrentBlock().Hash() != oldBlock.Hash() {
		t.Fatalf("R_P1H_SUBQUORUM_CANONICAL_HEAD_CHANGED got=%s want=%s", f.localChain.CurrentBlock().Hash(), oldBlock.Hash())
	}
	if canonical := f.localChain.GetCanonicalHash(oldBlock.NumberU64()); canonical != oldBlock.Hash() {
		t.Fatalf("R_P1H_SUBQUORUM_CANONICAL_HASH_CHANGED got=%s want=%s", canonical, oldBlock.Hash())
	}
	after, err := f.api.GetTransactionReceipt(context.Background(), oldTx.Hash())
	if err != nil || after == nil || after["blockHash"] != oldBlock.Hash() {
		t.Fatalf("R_P1H_SUBQUORUM_POST_SYNC_RECEIPT_CHANGED err=%v receipt=%v", err, after)
	}
	if staleReceipts.Load() != 0 {
		t.Fatalf("R_P1H_SUBQUORUM_STALE_RECEIPT_OBSERVED count=%d calls=%d", staleReceipts.Load(), receiptCalls.Load())
	}
	if receiptErrors.Load() != 0 {
		t.Fatalf("R_P1H_SUBQUORUM_RECEIPT_QUERY_ERRORS count=%d", receiptErrors.Load())
	}
	t.Logf("R_P1H_SUBQUORUM_ETH66_DOWNLOADER_REJECTED validators=4 seals=2 err=%v headers=%d bodies=%d",
		syncErr, wire.headerResponses.Load(), wire.bodyResponses.Load())
	t.Logf("R_P1H_LOWER_AUTHORITY_RECEIPT_INTEGRITY_PASS calls=%d stale=0 canonical=%s",
		receiptCalls.Load(), oldBlock.Hash())
	t.Log("R_P1H_LOWER_AUTHORITY_CANNOT_REPRODUCE_RECEIPT_INCONSISTENCY_PASS")
}
