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
	"errors"
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

// TestClientMaxResponseBody checks that the client reads a response within MaxResponseBody and
// fails a larger one, also when it is a multipart response. A server must not choose how much the
// client buffers.
func TestClientMaxResponseBody(t *testing.T) {
	t.Parallel()

	s, newClient := newTestServer(t)
	t.Cleanup(s.Close)

	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Body Test", nil)
	cacerts := func(ctx context.Context, c *est.Client) error {
		_, err := c.CACerts(ctx)
		return err
	}
	serverkeygen := func(ctx context.Context, c *est.Client) error {
		_, _, err := c.ServerKeyGen(ctx, csr)
		return err
	}

	testcases := []struct {
		name    string
		max     int64
		call    func(context.Context, *est.Client) error
		wantErr string
	}{
		{name: "Default", call: cacerts},
		{name: "Within", max: 64 << 10, call: cacerts},
		{name: "Exceeded", max: 64, call: cacerts, wantErr: "response body larger than 64 bytes"},
		{name: "Multipart", max: 64, call: serverkeygen, wantErr: "response body larger than 64 bytes"},
		{name: "Negative", max: -1, call: cacerts, wantErr: "MaxResponseBody must not be negative"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := newClient()
			client.MaxResponseBody = tc.max

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			err := tc.call(ctx, client)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("got error %v, want none", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got error %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestClientMaxResponseBodyErrorMessage checks that MaxResponseBody also bounds the error message
// of a failed request, which still yields an error with the response status.
func TestClientMaxResponseBodyErrorMessage(t *testing.T) {
	t.Parallel()

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("x", 4096), http.StatusServiceUnavailable)
	}))
	defer s.Close()

	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	client := &est.Client{Host: strings.TrimPrefix(s.URL, "https://"), ExplicitAnchor: pool, MaxResponseBody: 256}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, err := client.CACerts(ctx)
	var estErr est.Error
	if !errors.As(err, &estErr) || estErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("CACerts returned %v, want an error with status 503", err)
	}
	if !strings.Contains(err.Error(), "response body larger than 256 bytes") || strings.Contains(err.Error(), "xxxx") {
		t.Errorf("got error %q, want the body limit and none of the message", err)
	}
}
