//go:build linux

// Worker R G6 escalation: measure the real filesystem ENOSPC threshold where
// an already-valid QBFT block delivered over loopback ETH/66 tips a near-full
// syncing node into the shipped LevelDB fatal-write path.
//
// Threat boundary:
//   * the receiver filesystem is deliberately pre-filled by the test;
//   * the peer only serves a block that already carries valid validator-quorum
//     signatures; no seal bypass or validator-key theft is attempted;
//   * success establishes a lower-trust trigger of a pre-existing near-full
//     storage condition, not remote creation of that storage condition.
package eth

import (
    "bytes"
    "crypto/ecdsa"
    "errors"
    "fmt"
    "math/big"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/forkid"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    "github.com/electroneum/electroneum-sc/p2p"
)

func rG6AvailBytes(t *testing.T, path string) uint64 {
    t.Helper()
    var st syscall.Statfs_t
    if err := syscall.Statfs(path, &st); err != nil {
        t.Fatalf("R_G6_ENOSPC_STATFS_FAIL path=%s err=%v", path, err)
    }
    return st.Bavail * uint64(st.Bsize)
}

func rG6FillFilesystemToMargin(t *testing.T, root string, target uint64) (uint64, uint64) {
    t.Helper()
    before := rG6AvailBytes(t, root)
    if before <= target+(8<<20) {
        t.Fatalf("R_G6_ENOSPC_NOT_ENOUGH_INITIAL_SPACE before=%d target=%d", before, target)
    }
    fillerPath := filepath.Join(root, "r-g6-filler.bin")
    f, err := os.OpenFile(fillerPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
    if err != nil {
        t.Fatal(err)
    }
    defer f.Close()

    var off int64
    for {
        avail := rG6AvailBytes(t, root)
        if avail <= target+4096 {
            break
        }
        need := avail - target
        chunk := need
        if chunk > 8<<20 {
            chunk = 8 << 20
        }
        chunk &^= 4095
        if chunk < 4096 {
            break
        }
        for chunk >= 4096 {
            err = syscall.Fallocate(int(f.Fd()), 0, off, int64(chunk))
            if err == nil {
                off += int64(chunk)
                break
            }
            if !errors.Is(err, syscall.ENOSPC) {
                t.Fatalf("R_G6_ENOSPC_FALLOCATE_FAIL chunk=%d err=%v", chunk, err)
            }
            chunk = (chunk / 2) &^ 4095
        }
        if chunk < 4096 {
            break
        }
    }
    if err := f.Sync(); err != nil && !errors.Is(err, syscall.ENOSPC) {
        t.Fatalf("R_G6_ENOSPC_FILL_SYNC_FAIL err=%v", err)
    }
    after := rG6AvailBytes(t, root)
    if after > target+(1<<20) {
        t.Fatalf("R_G6_ENOSPC_MARGIN_TOO_LOOSE target=%d actual=%d", target, after)
    }
    return before, after
}


func rG6LargeSignedTx(t *testing.T, chain *core.BlockChain, key *ecdsa.PrivateKey) *types.Transaction {
    t.Helper()
    sender := crypto.PubkeyToAddress(key.PublicKey)
    state, err := chain.State()
    if err != nil {
        t.Fatalf("R_G6_ENOSPC_TX_STATE_FAIL err=%v", err)
    }
    nonce := state.GetNonce(sender)
    target := common.HexToAddress("0x0000000000000000000000000000000000000043")
    const payloadBytes = 256 << 10
    payload := bytes.Repeat([]byte{0xB7}, payloadBytes)
    tx, err := types.SignTx(
        types.NewTransaction(
            nonce,
            target,
            big.NewInt(1),
            6_000_000,
            big.NewInt(10_000_000_000),
            payload,
        ),
        types.LatestSigner(chain.Config()),
        key,
    )
    if err != nil {
        t.Fatalf("R_G6_ENOSPC_LARGE_TX_SIGN_FAIL err=%v", err)
    }
    t.Logf("R_G6_ENOSPC_LARGE_VALID_TX payload_bytes=%d gas=%d tx_rlp_size=%v",
        payloadBytes, tx.Gas(), tx.Size())
    return tx
}

func TestRQBFTWireRealENOSPCChild(t *testing.T) {
    if os.Getenv("R_G6_ENOSPC_CHILD") != "1" {
        return
    }
    root := os.Getenv("R_G6_ENOSPC_ROOT")
    margin, err := strconv.ParseUint(os.Getenv("R_G6_ENOSPC_MARGIN"), 10, 64)
    if err != nil || root == "" {
        t.Fatalf("R_G6_ENOSPC_BAD_CHILD_ENV root=%q margin=%q err=%v", root, os.Getenv("R_G6_ENOSPC_MARGIN"), err)
    }
    if err := os.MkdirAll(root, 0700); err != nil {
        t.Fatal(err)
    }

    // Build the remote block first. The wire peer later serves the already
    // valid block; it does not create signatures after the storage condition
    // is armed.
    f, senderKey := rP1HBaseFixture(t)
    defer f.close()
    remoteTx := rG6LargeSignedTx(t, f.remoteChain, senderKey)
    block := rQBFTBuildAndImport(t, f.remoteChain, f.remoteQBFT, f.remoteDB, f.validatorKeys, f.validators, remoteTx)
    if block == nil || block.NumberU64() != 1 {
        t.Fatal("R_G6_ENOSPC_REMOTE_QUORUM_BLOCK_NOT_BUILT")
    }

    dbPath := filepath.Join(root, "chaindata")
    if err := os.MkdirAll(dbPath, 0700); err != nil {
        t.Fatal(err)
    }
    db := rQBFTOpenDisk(t, dbPath)
    genesis := rQBFTNetworkGenesis(t, f.validatorKeys, crypto.PubkeyToAddress(senderKey.PublicKey))
    g := genesis.MustCommit(db)
    if g.Hash() != block.ParentHash() {
        t.Fatalf("R_G6_ENOSPC_GENESIS_MISMATCH got=%s want=%s", g.Hash(), block.ParentHash())
    }

    tracedDB := &rQBFTObservedDB{Database: db}
    backend := istanbulbackend.New(*istanbul.DefaultConfig, f.validatorKeys[0], tracedDB)
    chain, err := core.NewBlockChain(tracedDB, nil, genesis.Config, backend, vm.Config{}, nil, nil)
    if err != nil {
        t.Fatal(err)
    }
    if err := backend.Start(chain, chain.CurrentBlock, rawdb.HasBadBlock); err != nil {
        t.Fatal(err)
    }
    if err := backend.VerifyHeader(chain, block.Header(), true); err != nil {
        t.Fatalf("R_G6_ENOSPC_REMOTE_BLOCK_NOT_QBFT_VALID err=%v", err)
    }

    localHandler := rDevP2PHandler(t, tracedDB, chain)
    defer localHandler.Stop()
    localServer := rDevP2PServer(t, "r-g6-enospc-local", localHandler, false)
    defer localServer.Stop()

    wire := new(rP1HWireState)
    remoteTD := f.remoteChain.GetTd(block.Hash(), 1)
    if remoteTD == nil {
        t.Fatal("R_G6_ENOSPC_REMOTE_TD_MISSING")
    }
    protocol := rP1HRemoteProtocol(
        t,
        chain.Genesis(),
        block,
        remoteTD,
        forkid.NewID(chain.Config(), chain.Genesis().Hash(), block.NumberU64()),
        wire,
    )
    original := protocol.Run
    protocol.Run = func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
        return original(peer, &rG6WireSpy{MsgReadWriter: rw})
    }
    remoteServer := rP1HRemoteServer(t, "r-g6-enospc-valid-block-peer", protocol)
    defer remoteServer.Stop()
    localServer.AddPeer(remoteServer.Self())
    peer := rP1HWaitRegisteredPeer(t, localHandler, remoteServer)
    peerHash, peerTD := peer.Head()
    if wire.handshakes.Load() == 0 || peerHash != block.Hash() {
        t.Fatalf("R_G6_ENOSPC_PEER_HANDSHAKE_MISSING handshakes=%d got=%s want=%s",
            wire.handshakes.Load(), peerHash, block.Hash())
    }
    fmt.Fprintf(os.Stderr, "R_G6_ENOSPC_ETH66_VALID_PEER_CONNECTED handshakes=%d block=%s body_bytes=%d role=serve_already_valid_quorum_block\n",
        wire.handshakes.Load(), block.Hash(), block.Size())

    before, actual := rG6FillFilesystemToMargin(t, root, margin)
    fmt.Fprintf(os.Stderr, "R_G6_ENOSPC_MARGIN_ARMED requested=%d actual=%d before=%d\n", margin, actual, before)
    fmt.Fprintln(os.Stderr, "R_G6_ENOSPC_DOWNLOADER_SYNC_START")

    err = localHandler.downloader.LegacySync(
        peer.ID(),
        peerHash,
        peerTD,
        chain.Config().TerminalTotalDifficulty,
        downloader.FullSync,
    )
    if err != nil {
        t.Fatalf("R_G6_ENOSPC_DOWNLOADER_RETURNED margin=%d actual=%d err=%v bodies=%d",
            margin, actual, err, wire.bodyResponses.Load())
    }

    head := chain.CurrentBlock()
    receipt, _, _, _ := rawdb.ReadReceipt(db, remoteTx.Hash(), chain.Config())
    if head == nil || head.Hash() != block.Hash() || receipt == nil ||
        receipt.TxHash != remoteTx.Hash() || receipt.Status != types.ReceiptStatusSuccessful {
        t.Fatalf("R_G6_ENOSPC_SUCCESS_STATE_BAD margin=%d actual=%d head=%v receipt=%v", margin, actual, head, receipt)
    }
    fmt.Fprintf(os.Stderr, "R_G6_ENOSPC_MARGIN_SUCCESS requested=%d actual_before_import=%d head=1 receipt=1 bodies=%d\n",
        margin, actual, wire.bodyResponses.Load())

    if err := backend.Stop(); err != nil {
        t.Fatal(err)
    }
    chain.Stop()
    if err := db.Close(); err != nil {
        t.Fatal(err)
    }
}

func TestRQBFTWireRealENOSPCThresholdSweep(t *testing.T) {
    mountRoot := os.Getenv("R_G6_ENOSPC_MOUNT")
    if mountRoot == "" {
        t.Skip("R_G6_ENOSPC_MOUNT not configured")
    }
    margins := []uint64{
        8 << 20,
        2 << 20,
        512 << 10,
        128 << 10,
        32 << 10,
        8 << 10,
        4 << 10,
    }

    successes := 0
    enospc := 0
    var smallestSuccess uint64
    var largestENOSPC uint64
    for i, margin := range margins {
        caseRoot := filepath.Join(mountRoot, fmt.Sprintf("case-%02d-%d", i, margin))
        if err := os.RemoveAll(caseRoot); err != nil {
            t.Fatal(err)
        }
        if err := os.MkdirAll(caseRoot, 0700); err != nil {
            t.Fatal(err)
        }

        child := exec.Command(os.Args[0], "-test.run=^TestRQBFTWireRealENOSPCChild$", "-test.v")
        child.Env = append(os.Environ(),
            "R_G6_ENOSPC_CHILD=1",
            "R_G6_ENOSPC_ROOT="+caseRoot,
            fmt.Sprintf("R_G6_ENOSPC_MARGIN=%d", margin),
        )
        output, err := child.CombinedOutput()
        if !bytes.Contains(output, []byte("R_G6_ENOSPC_ETH66_VALID_PEER_CONNECTED")) ||
            !bytes.Contains(output, []byte("R_G6_ENOSPC_MARGIN_ARMED")) ||
            !bytes.Contains(output, []byte("R_G6_ENOSPC_DOWNLOADER_SYNC_START")) ||
            !bytes.Contains(output, []byte("R_G6_ETH66_BODY_RESPONSE_SENT_SUCCESS")) {
            t.Fatalf("R_G6_ENOSPC_WIRE_MARKER_MISSING margin=%d err=%v output=%s", margin, err, output)
        }

        if err == nil {
            if !bytes.Contains(output, []byte("R_G6_ENOSPC_MARGIN_SUCCESS")) {
                t.Fatalf("R_G6_ENOSPC_SUCCESS_MARKER_MISSING margin=%d output=%s", margin, output)
            }
            successes++
            if smallestSuccess == 0 || margin < smallestSuccess {
                smallestSuccess = margin
            }
            t.Logf("R_G6_ENOSPC_MARGIN_RESULT requested=%d result=SUCCESS", margin)
        } else {
            exit, ok := err.(*exec.ExitError)
            if !ok || exit.ExitCode() != 1 {
                t.Fatalf("R_G6_ENOSPC_UNEXPECTED_CHILD_EXIT margin=%d err=%v output=%s", margin, err, output)
            }
            if !bytes.Contains(output, []byte("R_QBFT_REAL_LEVELDB_BATCH_WRITE_ERROR")) ||
                !bytes.Contains(bytes.ToLower(output), []byte("no space left on device")) {
                t.Fatalf("R_G6_ENOSPC_NOT_NATIVE_LEVELDB_ENOSPC margin=%d output=%s", margin, output)
            }
            if bytes.Contains(output, []byte("R_G6_ENOSPC_DOWNLOADER_RETURNED")) {
                t.Fatalf("R_G6_ENOSPC_EXPECTED_FATAL_PATH_NOT_REACHED margin=%d output=%s", margin, output)
            }
            enospc++
            if margin > largestENOSPC {
                largestENOSPC = margin
            }
            t.Logf("R_G6_ENOSPC_MARGIN_RESULT requested=%d result=ENOSPC_FATAL_EXIT", margin)
        }

        if err := os.RemoveAll(caseRoot); err != nil {
            t.Fatalf("R_G6_ENOSPC_CLEANUP_FAIL margin=%d err=%v", margin, err)
        }
    }

    if successes == 0 || enospc == 0 {
        t.Fatalf("R_G6_ENOSPC_THRESHOLD_NOT_BRACKETED successes=%d enospc=%d", successes, enospc)
    }
    t.Logf("R_G6_ENOSPC_THRESHOLD_MATRIX_PASS cases=%d success=%d enospc=%d smallest_success_margin=%d largest_enospc_margin=%d",
        len(margins), successes, enospc, smallestSuccess, largestENOSPC)
    t.Log("R_G6_ENOSPC_G6_CLASSIFICATION PARTIAL_TRIGGER_ONLY precondition=near_full_ext4 peer_role=serve_already_valid_quorum_block no_validator_bypass=true")
}
