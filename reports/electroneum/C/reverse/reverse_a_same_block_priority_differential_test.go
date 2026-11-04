// Reverse Worker R — A system differential: same-block priority-registry mutation.
// Copy ONLY to certified-source scratch core package.
//
// Hypothesis R-A-X01:
// A registry mutation in tx[0] must affect priority authorization for tx[1]
// identically in the miner construction path (ApplyTransaction) and validator
// import path (StateProcessor.Process). Divergence would be consensus-relevant.
package core

import (
    "errors"
    "math/big"
    "strings"
    "testing"

    "github.com/electroneum/electroneum-sc/accounts/abi"
    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/state"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/params"
    "github.com/electroneum/electroneum-sc/trie"
)

func reverseAPush2(code *[]byte, v int) {
    *code = append(*code, 0x61, byte(v>>8), byte(v))
}

func reverseAPush2Placeholder(code *[]byte) int {
    *code = append(*code, 0x61, 0x00, 0x00)
    return len(*code) - 2
}

func reverseAPatch2(code []byte, at, v int) {
    if v < 0 || v > 0xffff {
        panic("reverse A runtime offset exceeds PUSH2")
    }
    code[at] = byte(v >> 8)
    code[at+1] = byte(v)
}

// reverseAStatefulRegistryRuntime returns a tiny deterministic EVM registry:
//   calldata size == 4: getTransactors()-style ABI return, selected by slot 0.
//   calldata size == 0: slot0 = 1 (grant).
//   any other size:      slot0 = 0 (revoke).
// This makes the list genuinely state-dependent across transactions in one block.
func reverseAStatefulRegistryRuntime(t *testing.T, priorityPub common.PublicKey) []byte {
    t.Helper()
    parsed, err := abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI))
    if err != nil {
        t.Fatal(err)
    }
    full, err := parsed.Methods["getTransactors"].Outputs.Pack(
        []prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{{
            IsGasPriceWaiver: true,
            PublicKey:        common.Bytes2Hex(priorityPub[:]),
            Name:             "ReverseR-Stateful",
        }},
    )
    if err != nil {
        t.Fatalf("pack full registry output: %v", err)
    }
    empty, err := parsed.Methods["getTransactors"].Outputs.Pack(
        []prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{},
    )
    if err != nil {
        t.Fatalf("pack empty registry output: %v", err)
    }

    var code []byte
    // if CALLDATASIZE == 4 -> get branch
    code = append(code, 0x36, 0x60, 0x04, 0x14)
    getPatch := reverseAPush2Placeholder(&code)
    code = append(code, 0x57)

    // mutation branch: empty calldata grants, non-empty revokes.
    code = append(code, 0x36, 0x15)
    addPatch := reverseAPush2Placeholder(&code)
    code = append(code, 0x57)
    // revoke: SSTORE(0,0)
    code = append(code, 0x60, 0x00, 0x60, 0x00, 0x55, 0x00)

    addLabel := len(code)
    code = append(code, 0x5b, 0x60, 0x01, 0x60, 0x00, 0x55, 0x00)

    getLabel := len(code)
    // if SLOAD(0) == 0 -> empty return branch
    code = append(code, 0x5b, 0x60, 0x00, 0x54, 0x15)
    emptyPatch := reverseAPush2Placeholder(&code)
    code = append(code, 0x57)

    // full return
    reverseAPush2(&code, len(full))
    fullDataPatch := reverseAPush2Placeholder(&code)
    code = append(code, 0x60, 0x00, 0x39)
    reverseAPush2(&code, len(full))
    code = append(code, 0x60, 0x00, 0xf3)

    emptyLabel := len(code)
    code = append(code, 0x5b)
    reverseAPush2(&code, len(empty))
    emptyDataPatch := reverseAPush2Placeholder(&code)
    code = append(code, 0x60, 0x00, 0x39)
    reverseAPush2(&code, len(empty))
    code = append(code, 0x60, 0x00, 0xf3)

    fullData := len(code)
    code = append(code, full...)
    emptyData := len(code)
    code = append(code, empty...)

    reverseAPatch2(code, getPatch, getLabel)
    reverseAPatch2(code, addPatch, addLabel)
    reverseAPatch2(code, emptyPatch, emptyLabel)
    reverseAPatch2(code, fullDataPatch, fullData)
    reverseAPatch2(code, emptyDataPatch, emptyData)
    return code
}

type reverseAPrioritySystem struct {
    bc          *BlockChain
    cfg         *params.ChainConfig
    registry    common.Address
    coinbase    common.Address
    target      common.Address
    adminKey    string
    senderKey   string
    priorityKey string
    priorityPub common.PublicKey
}

func reverseANewPrioritySystem(t *testing.T, initialGrant bool) *reverseAPrioritySystem {
    t.Helper()
    adminHex := "0000000000000000000000000000000000000000000000000000000000000111"
    senderHex := "0000000000000000000000000000000000000000000000000000000000000222"
    priorityHex := "0000000000000000000000000000000000000000000000000000000000000333"

    admin, err := crypto.HexToECDSA(adminHex)
    if err != nil { t.Fatal(err) }
    sender, err := crypto.HexToECDSA(senderHex)
    if err != nil { t.Fatal(err) }
    priority, err := crypto.HexToECDSA(priorityHex)
    if err != nil { t.Fatal(err) }

    registry := common.HexToAddress("0x0000000000000000000000000000000000000a11")
    coinbase := common.HexToAddress("0x0000000000000000000000000000000000000c01")
    target := common.HexToAddress("0x0000000000000000000000000000000000000d01")
    var priorityPub common.PublicKey
    copy(priorityPub[:], crypto.FromECDSAPub(&priority.PublicKey))

    cfg := &params.ChainConfig{
        ChainID: big.NewInt(7070),
        HomesteadBlock: big.NewInt(0),
        EIP150Block: big.NewInt(0),
        EIP155Block: big.NewInt(0),
        EIP158Block: big.NewInt(0),
        ByzantiumBlock: big.NewInt(0),
        ConstantinopleBlock: big.NewInt(0),
        PetersburgBlock: big.NewInt(0),
        IstanbulBlock: big.NewInt(0),
        BerlinBlock: big.NewInt(0),
        LondonBlock: big.NewInt(0),
        Ethash: &params.EthashConfig{},
        PriorityTransactorsContractAddress: registry,
    }
    storage := make(map[common.Hash]common.Hash)
    if initialGrant {
        storage[common.Hash{}] = common.BigToHash(big.NewInt(1))
    }
    db := rawdb.NewMemoryDatabase()
    genesis := &Genesis{
        Config: cfg,
        GasLimit: 10_000_000,
        Difficulty: big.NewInt(1),
        BaseFee: big.NewInt(8),
        Alloc: GenesisAlloc{
            crypto.PubkeyToAddress(admin.PublicKey): {
                Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil),
            },
            crypto.PubkeyToAddress(sender.PublicKey): {
                Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil),
            },
            registry: {
                Balance: big.NewInt(0),
                Code: reverseAStatefulRegistryRuntime(t, priorityPub),
                Storage: storage,
            },
        },
    }
    if _, err := genesis.Commit(db); err != nil {
        t.Fatalf("commit genesis: %v", err)
    }
    engine := ethash.NewFaker()
    bc, err := NewBlockChain(db, nil, cfg, engine, vm.Config{}, nil, nil)
    if err != nil {
        t.Fatalf("new blockchain: %v", err)
    }
    t.Cleanup(bc.Stop)

    return &reverseAPrioritySystem{
        bc: bc, cfg: cfg, registry: registry, coinbase: coinbase, target: target,
        adminKey: adminHex, senderKey: senderHex, priorityKey: priorityHex,
        priorityPub: priorityPub,
    }
}

func (s *reverseAPrioritySystem) transactions(t *testing.T, grant bool, header *types.Header) []*types.Transaction {
    t.Helper()
    admin, _ := crypto.HexToECDSA(s.adminKey)
    sender, _ := crypto.HexToECDSA(s.senderKey)
    priority, _ := crypto.HexToECDSA(s.priorityKey)
    signer := types.MakeSigner(s.cfg, header.Number)

    var mutateData []byte
    if !grant {
        mutateData = []byte{0x01}
    }
    mutate, err := types.SignTx(
        types.NewTransaction(0, s.registry, big.NewInt(0), 100_000, big.NewInt(10), mutateData),
        signer, admin,
    )
    if err != nil { t.Fatalf("sign mutation tx: %v", err) }

    priorityTx, err := types.SignNewPriorityTx(sender, priority, signer, &types.PriorityTx{
        ChainID: s.cfg.ChainID,
        Nonce: 0,
        GasTipCap: big.NewInt(0),
        GasFeeCap: big.NewInt(0),
        Gas: 50_000,
        To: &s.target,
        Value: big.NewInt(1),
    })
    if err != nil { t.Fatalf("sign priority tx: %v", err) }
    return []*types.Transaction{mutate, priorityTx}
}

func (s *reverseAPrioritySystem) header() *types.Header {
    return &types.Header{
        ParentHash: s.bc.CurrentBlock().Hash(),
        Coinbase: s.coinbase,
        Number: big.NewInt(1),
        GasLimit: 1_000_000,
        Time: 1,
        Difficulty: big.NewInt(1),
        BaseFee: big.NewInt(8),
    }
}

func reverseAMinerApply(t *testing.T, s *reverseAPrioritySystem, st *state.StateDB, header *types.Header, txs []*types.Transaction) (types.Receipts, uint64, error) {
    t.Helper()
    st.SetPriorityTransactors(s.bc.GetPriorityTransactorsForState(header, st))
    gp := new(GasPool).AddGas(header.GasLimit)
    used := uint64(0)
    receipts := make(types.Receipts, 0, len(txs))
    for i, tx := range txs {
        st.Prepare(tx.Hash(), i)
        receipt, err := ApplyTransaction(s.cfg, s.bc, &s.coinbase, gp, st, header, tx, &used, vm.Config{})
        if err != nil {
            return receipts, used, err
        }
        receipts = append(receipts, receipt)

        // Mirror miner/worker.go's explicit post-success registry refresh too.
        if tx.To() != nil && *tx.To() == s.cfg.GetPriorityTransactorsContractAddress(header.Number) {
            st.SetPriorityTransactors(s.bc.GetPriorityTransactorsForState(header, st))
        }
    }
    s.bc.Engine().Finalize(s.bc, header, st, txs, nil)
    return receipts, used, nil
}

func reverseAPriorityPresent(st *state.StateDB, pub common.PublicKey) bool {
    tr, ok := st.GetPriorityTransactorByKey(pub)
    return ok && tr.IsGasPriceWaiver
}

func TestReverseASameBlockPriorityMinerImportDifferential(t *testing.T) {
    t.Run("grant_then_use_same_block", func(t *testing.T) {
        sys := reverseANewPrioritySystem(t, false)
        parent, err := sys.bc.State()
        if err != nil { t.Fatal(err) }
        minerState, validatorState := parent.Copy(), parent.Copy()

        minerHeader := sys.header()
        txs := sys.transactions(t, true, minerHeader)
        if reverseAPriorityPresent(minerState, sys.priorityPub) {
            t.Fatal("grant fixture unexpectedly starts authorized")
        }

        minerReceipts, minerGas, minerErr := reverseAMinerApply(t, sys, minerState, minerHeader, txs)
        if minerErr != nil {
            t.Fatalf("miner rejected grant->use sequence: %v", minerErr)
        }
        if !reverseAPriorityPresent(minerState, sys.priorityPub) {
            t.Fatal("miner did not observe same-block grant")
        }

        validatorHeader := sys.header()
        block := types.NewBlock(validatorHeader, txs, nil, nil, trie.NewStackTrie(nil))
        processor := NewStateProcessor(sys.cfg, sys.bc, sys.bc.Engine())
        validatorReceipts, _, validatorGas, validatorErr := processor.Process(block, validatorState, vm.Config{})
        if validatorErr != nil {
            t.Fatalf("validator rejected miner-accepted grant->use block: %v", validatorErr)
        }
        if !reverseAPriorityPresent(validatorState, sys.priorityPub) {
            t.Fatal("validator did not observe same-block grant")
        }
        minerRoot := minerState.IntermediateRoot(sys.cfg.IsEIP158(minerHeader.Number))
        validatorRoot := validatorState.IntermediateRoot(sys.cfg.IsEIP158(validatorHeader.Number))
        if minerRoot != validatorRoot {
            t.Fatalf("CONSENSUS_DIVERGENCE grant root miner=%s validator=%s", minerRoot, validatorRoot)
        }
        if minerGas != validatorGas || len(minerReceipts) != len(validatorReceipts) {
            t.Fatalf("grant accounting divergence minerGas=%d validatorGas=%d minerReceipts=%d validatorReceipts=%d",
                minerGas, validatorGas, len(minerReceipts), len(validatorReceipts))
        }
        for i := range minerReceipts {
            if minerReceipts[i].Status != validatorReceipts[i].Status ||
                minerReceipts[i].GasUsed != validatorReceipts[i].GasUsed ||
                minerReceipts[i].CumulativeGasUsed != validatorReceipts[i].CumulativeGasUsed {
                t.Fatalf("grant receipt divergence at tx %d: miner=%+v validator=%+v", i, minerReceipts[i], validatorReceipts[i])
            }
        }
        t.Logf("REVERSE_A_SAME_BLOCK_GRANT_MINER_IMPORT_PARITY_PASS gas=%d root=%s receipts=%d",
            minerGas, minerRoot, len(minerReceipts))
    })

    t.Run("revoke_then_use_same_block", func(t *testing.T) {
        sys := reverseANewPrioritySystem(t, true)
        parent, err := sys.bc.State()
        if err != nil { t.Fatal(err) }
        minerState, validatorState := parent.Copy(), parent.Copy()

        minerHeader := sys.header()
        txs := sys.transactions(t, false, minerHeader)
        minerState.SetPriorityTransactors(sys.bc.GetPriorityTransactorsForState(minerHeader, minerState))
        if !reverseAPriorityPresent(minerState, sys.priorityPub) {
            t.Fatal("revoke fixture does not start authorized")
        }

        minerReceipts, minerGas, minerErr := reverseAMinerApply(t, sys, minerState, minerHeader, txs)
        if !errors.Is(minerErr, errBadPriorityKey) {
            t.Fatalf("miner revoke->use error=%v want errBadPriorityKey", minerErr)
        }
        if reverseAPriorityPresent(minerState, sys.priorityPub) {
            t.Fatal("miner kept revoked priority key cached")
        }
        if len(minerReceipts) != 1 {
            t.Fatalf("miner should accept mutation then reject priority tx; receipts=%d", len(minerReceipts))
        }

        validatorHeader := sys.header()
        block := types.NewBlock(validatorHeader, txs, nil, nil, trie.NewStackTrie(nil))
        processor := NewStateProcessor(sys.cfg, sys.bc, sys.bc.Engine())
        _, _, _, validatorErr := processor.Process(block, validatorState, vm.Config{})
        if !errors.Is(validatorErr, errBadPriorityKey) {
            t.Fatalf("validator revoke->use error=%v want errBadPriorityKey", validatorErr)
        }
        if reverseAPriorityPresent(validatorState, sys.priorityPub) {
            t.Fatal("validator kept revoked priority key cached")
        }
        minerRoot := minerState.IntermediateRoot(sys.cfg.IsEIP158(minerHeader.Number))
        validatorRoot := validatorState.IntermediateRoot(sys.cfg.IsEIP158(validatorHeader.Number))
        if minerRoot != validatorRoot {
            t.Fatalf("CONSENSUS_DIVERGENCE revoke pre-rejection root miner=%s validator=%s", minerRoot, validatorRoot)
        }
        t.Logf("REVERSE_A_SAME_BLOCK_REVOKE_MINER_IMPORT_PARITY_PASS accepted_before_reject=%d gas_before_reject=%d root=%s",
            len(minerReceipts), minerGas, minerRoot)
    })
}
