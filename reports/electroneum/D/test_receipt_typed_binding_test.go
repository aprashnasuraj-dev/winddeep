// Worker D: certified eth/66 typed-receipt payload -> metadata binding.
// Copied into eth/protocols/eth on the certified scratch tree by Class D CI.
// Synthetic/in-process only: no public peers, no live chain traffic.
package eth

import (
	"fmt"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/rlp"
	"github.com/electroneum/electroneum-sc/trie"
)

// workerDManualReceiptRoot is intentionally independent of types.Receipts.EncodeIndex.
// It marshals each receipt directly and inserts trie keys in the canonical order
// required by StackTrie. This catches ordering/typed-envelope disagreement between
// the handler's raw-RLP metadata and decoded receipt semantics.
func workerDManualReceiptRoot(t *testing.T, receipts types.Receipts) common.Hash {
	t.Helper()
	st := trie.NewStackTrie(nil)
	update := func(i int) {
		key := rlp.AppendUint64(nil, uint64(i))
		value, err := receipts[i].MarshalBinary()
		if err != nil {
			t.Fatalf("marshal receipt %d: %v", i, err)
		}
		st.Update(key, value)
	}
	for i := 1; i < len(receipts) && i <= 0x7f; i++ {
		update(i)
	}
	if len(receipts) > 0 {
		update(0)
	}
	for i := 0x80; i < len(receipts); i++ {
		update(i)
	}
	return st.Hash()
}

func workerDTypedReceiptSet() types.Receipts {
	receipts := make(types.Receipts, 130) // crosses the 0x7f/0x80 trie-index boundary
	for i := range receipts {
		r := &types.Receipt{
			Type:              uint8(i % 3), // legacy, access-list, dynamic-fee
			Status:            uint64(i % 2),
			CumulativeGasUsed: uint64(21000 * (i + 1)),
		}
		if i%11 == 0 {
			r.Logs = []*types.Log{{
				Address: common.Address{byte(i), byte(i >> 8)},
				Topics:  []common.Hash{{byte(i), 0x44}},
				Data:    []byte{byte(i), 0xaa, 0x55},
			}}
		}
		r.Bloom = types.CreateBloom(types.Receipts{r})
		receipts[i] = r
	}
	return receipts
}

func workerDCloneReceipts(in types.Receipts) types.Receipts {
	out := make(types.Receipts, len(in))
	for i, r := range in {
		c := *r
		out[i] = &c
	}
	return out
}

func TestWorkerDTypedReceiptPayloadBinding(t *testing.T) {
	base := workerDTypedReceiptSet()
	cases := []struct {
		name   string
		mutate func(types.Receipts)
	}{
		{name: "honest_mixed_types_130"},
		{name: "reorder_across_127_128_boundary", mutate: func(rs types.Receipts) {
			rs[127], rs[128] = rs[128], rs[127]
		}},
		{name: "valid_status_mutation_at_128", mutate: func(rs types.Receipts) {
			c := *rs[128]
			c.Status ^= 1
			rs[128] = &c
		}},
	}
	var honestRoot common.Hash
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipts := workerDCloneReceipts(base)
			if tc.mutate != nil {
				tc.mutate(receipts)
			}
			oracle := workerDManualReceiptRoot(t, receipts)
			library := types.DeriveSha(receipts, trie.NewStackTrie(nil))
			if oracle != library {
				t.Fatalf("independent trie oracle mismatch: oracle=%x derive=%x", oracle, library)
			}
			if tc.name == "honest_mixed_types_130" {
				honestRoot = oracle
			} else if oracle == honestRoot {
				t.Fatalf("mutation/reorder did not change commitment: root=%x", oracle)
			}

			enc, err := rlp.EncodeToBytes([][]*types.Receipt{[]*types.Receipt(receipts)})
			if err != nil {
				t.Fatal(err)
			}
			peer, app := newDispatchTestPeer(t)
			sink := make(chan *Response, 1)
			go func() {
				peer.RequestReceipts([]common.Hash{{1}}, sink)
			}()
			msg, err := app.ReadMsg()
			if err != nil {
				t.Fatal(err)
			}
			var req GetReceiptsPacket66
			if err := msg.Decode(&req); err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			go func() {
				res := <-sink
				meta, ok := res.Meta.([]common.Hash)
				if !ok || len(meta) != 1 {
					done <- fmt.Errorf("unexpected metadata type/length: %T %#v", res.Meta, res.Meta)
					res.Done <- nil
					return
				}
				if meta[0] != oracle {
					done <- fmt.Errorf("handler metadata root %x, independent oracle %x", meta[0], oracle)
					res.Done <- nil
					return
				}
				raw := *res.Res.(*RawReceiptsPacket)
				if len(raw) != 1 {
					done <- fmt.Errorf("raw receipt packet count %d, want 1", len(raw))
					res.Done <- nil
					return
				}
				decoded, err := DecodeReceipts(raw[0])
				if err != nil {
					done <- fmt.Errorf("DecodeReceipts: %v", err)
					res.Done <- nil
					return
				}
				decodedRoot := workerDManualReceiptRoot(t, decoded)
				if decodedRoot != oracle {
					done <- fmt.Errorf("decoded root %x, payload oracle %x", decodedRoot, oracle)
					res.Done <- nil
					return
				}
				done <- nil
				res.Done <- nil
			}()
			if err := handleReceipts66(nil, responseMsg(ReceiptsMsg, req.RequestId, enc), peer); err != nil {
				t.Fatalf("handler rejected valid synthetic receipt response: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			t.Logf("WORKER_D_TYPED_BINDING_PASS case=%s root=%x count=%d", tc.name, oracle, len(receipts))
		})
	}
}
