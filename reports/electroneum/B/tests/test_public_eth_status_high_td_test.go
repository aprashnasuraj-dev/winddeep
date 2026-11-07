// Public ETH66 status negotiation: TD is peer-supplied and lacks validator
// authorization. Confirms protocol precondition only, not a live attack.
package eth

import (
    "math/big"
    "testing"
    "strings"

    "github.com/electroneum/electroneum-sc/core/forkid"
    "github.com/electroneum/electroneum-sc/p2p"
    "github.com/electroneum/electroneum-sc/p2p/enode"
)

func TestPeerStatusHighTDWithoutValidatorCredentials(t *testing.T) {
    backend := newTestBackend(3)
    defer backend.close()
    genesis := backend.chain.Genesis()
    head := backend.chain.CurrentBlock()
    td := backend.chain.GetTd(head.Hash(), head.NumberU64())
    fork := forkid.NewID(backend.chain.Config(), genesis.Hash(), head.NumberU64())

    for _, tc := range []struct {
        name string
        offered *big.Int
        accepted bool
    }{
        {"ordinary_peer_claims_higher_td", new(big.Int).Add(td,big.NewInt(1000000)),true},
        {"max_allowed_100_bit_claim", new(big.Int).Lsh(big.NewInt(1),99),true},
        {"beyond_100_bit_guard", new(big.Int).Lsh(big.NewInt(1),100),false},
    } {
        t.Run(tc.name,func(t *testing.T) {
            app, remote := p2p.MsgPipe()
            defer app.Close()
            defer remote.Close()
            peer := NewPeer(ETH66,p2p.NewPeer(enode.ID{},"unprivileged-eth66",nil),remote,nil)
            defer peer.Close()
            advertised := StatusPacket{ProtocolVersion:uint32(ETH66),NetworkID:1,
                TD:tc.offered,Head:head.Hash(),Genesis:genesis.Hash(),ForkID:fork}
            // The full-duplex protocol pipe must consume the local status
            // before sending the remote peer's status, or both writes block.
            go func() {
                msg, e := app.ReadMsg()
                if e != nil {return}
                msg.Discard()
                _ = p2p.Send(app,StatusMsg,advertised)
            }()
            err:=peer.Handshake(1,td,head.Hash(),genesis.Hash(),fork,forkid.NewFilter(backend.chain))
            if tc.accepted && err!=nil {t.Fatalf("valid public ETH status wrongly rejected: %v",err)}
            if !tc.accepted && (err==nil || !strings.Contains(err.Error(),"too large total difficulty")) {t.Fatalf("expected TD limit rejection; got %v",err)}
            if tc.accepted {
                gotHead, gotTD := peer.Head()
                if gotHead!=head.Hash()||gotTD.Cmp(tc.offered)!=0 {
                    t.Fatalf("accepted peer TD mismatch: %v %v",gotHead,gotTD)
                }
                t.Logf("P2P_UNTRUSTED_HIGH_TD_ACCEPTED td_bits=%d head=%s validator_auth=none",gotTD.BitLen(),gotHead)
            } else {
                t.Logf("P2P_UNTRUSTED_TD_LIMIT_ENFORCED td_bits=%d err=%v",tc.offered.BitLen(),err)
            }
        })
    }
}
