/*
Copyright (c) 2026 the go-pki-est contributors.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est_test

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	est "github.com/misiektoja/go-pki-est"
)

// bodyRecord holds how a request body arrived at the server.
type bodyRecord struct {
	contentLength    int64
	transferEncoding []string
	bodyLength       int
}

// TestClientRequestContentLength checks that every request with a body declares its length,
// because some EST servers, such as the libest example server, cannot read a chunked body.
func TestClientRequestContentLength(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	records := map[string]bodyRecord{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		records[r.URL.Path] = bodyRecord{
			contentLength:    r.ContentLength,
			transferEncoding: r.TransferEncoding,
			bodyLength:       len(body),
		}
		mu.Unlock()
		http.Error(w, "recorded", http.StatusServiceUnavailable)
	}))
	defer s.Close()

	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	client := &est.Client{Host: strings.TrimPrefix(s.URL, "https://"), ExplicitAnchor: pool}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	key := mustGenerateECPrivateKey(t)
	csr := mustCreateCertificateRequest(t, key, "Length Test", nil)
	ek := mustMakeAlternateCertChain(t, mustGenerateECPrivateKey(t), "EK Test")
	calls := map[string]func() error{
		"/.well-known/est/simpleenroll": func() error {
			_, err := client.Enroll(ctx, csr)
			return err
		},
		"/.well-known/est/simplereenroll": func() error {
			_, err := client.Reenroll(ctx, csr)
			return err
		},
		"/.well-known/est/serverkeygen": func() error {
			_, _, err := client.ServerKeyGen(ctx, csr)
			return err
		},
		"/.well-known/est/tpmenroll": func() error {
			_, _, _, err := client.TPMEnroll(ctx, csr, ek[:1], []byte("ek"), []byte("ak"))
			return err
		},
	}
	for path, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: the recording server answered 503, want an error", path)
		}
		mu.Lock()
		rec, ok := records[path]
		mu.Unlock()
		switch {
		case !ok:
			t.Errorf("%s: no request arrived", path)
		case len(rec.transferEncoding) != 0:
			t.Errorf("%s: body sent with Transfer-Encoding %v, want a Content-Length", path, rec.transferEncoding)
		case rec.contentLength != int64(rec.bodyLength) || rec.bodyLength == 0:
			t.Errorf("%s: Content-Length %d for a body of %d bytes", path, rec.contentLength, rec.bodyLength)
		}
	}
}
