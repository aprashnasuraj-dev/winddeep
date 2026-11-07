package rpc

// Bounded HTTP ingress controls for E-RPC-007. Copy into rpc/ in the
// certified immutable scratch source; never send requests to public nodes.
import (
 "bytes"
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestWorkerEHTTPOverrideRequestCap(t *testing.T) {
 for _, tc := range []struct{name string; size int; wantTooLarge bool}{
  {"under_limit", maxRequestContentLength-1, false},
  {"at_limit", maxRequestContentLength, false},
  {"over_limit", maxRequestContentLength+1, true},
  {"over_limit_boundary", maxRequestContentLength+2, true},
  {"chunked_under_limit", maxRequestContentLength-1, false},
  {"chunked_over_limit", maxRequestContentLength+1, true},
 } {
  t.Run(tc.name, func(t *testing.T) {
   // A malformed JSON body is intentional: this test isolates ingress
   // rejection, not execution or state-override semantics.
   req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte{' '}, tc.size)))
   req.Header.Set("Content-Type", "application/json")
   if tc.name == "chunked_under_limit" || tc.name == "chunked_over_limit" {
    // Unknown Content-Length exercises streaming enforcement, not only
    // the fast path that rejects a declared oversized Content-Length.
    req.ContentLength = -1
    req.TransferEncoding = []string{"chunked"}
   }
   recorder := httptest.NewRecorder()
   new(Server).ServeHTTP(recorder, req)
   gotTooLarge := recorder.Code == http.StatusRequestEntityTooLarge
   if gotTooLarge != tc.wantTooLarge {
    t.Fatalf("HTTP ingress cap: bytes=%d status=%d expected_413=%t", tc.size, recorder.Code, tc.wantTooLarge)
   }
   t.Logf("E_HTTP_REQUEST_CAP bytes=%d status=%d rejected_413=%t content_length=%d", tc.size, recorder.Code, gotTooLarge, req.ContentLength)
  })
 }
}
