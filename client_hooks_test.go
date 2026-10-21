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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"go.mozilla.org/pkcs7"

	est "github.com/misiektoja/go-pki-est"
)

// recordingTransport records the method, path and status of every exchange.
type recordingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	log  []string
}

// RoundTrip passes the request on and records it with the response status.
func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := rt.next.RoundTrip(r)
	entry := r.Method + " " + r.URL.Path
	if err == nil {
		entry += " " + resp.Status
		if resp.TLS != nil && resp.TLS.HandshakeComplete {
			entry += " tls"
		}
	}
	rt.mu.Lock()
	rt.log = append(rt.log, entry)
	rt.mu.Unlock()
	return resp, err
}

// TestClientWrapTransport checks that WrapTransport sees every exchange and OnConnect every
// connection after its handshake.
func TestClientWrapTransport(t *testing.T) {
	t.Parallel()

	s, newTestClient := newTestServer(t)
	defer s.Close()

	rt := &recordingTransport{}
	var connected []string
	client := newTestClient()
	client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		rt.next = next
		return rt
	}
	client.OnConnect = func(conn net.Conn) {
		tc, ok := conn.(*tls.Conn)
		if !ok || !tc.ConnectionState().HandshakeComplete {
			t.Errorf("OnConnect got %T before the handshake completed", conn)
			return
		}
		connected = append(connected, tc.ConnectionState().ServerName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if _, err := client.CACerts(ctx); err != nil {
		t.Fatalf("CACerts: %v", err)
	}
	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Hook Test", nil)
	if _, err := client.Enroll(ctx, csr); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	want := []string{
		"GET /.well-known/est/cacerts 200 OK tls",
		"POST /.well-known/est/simpleenroll 200 OK tls",
	}
	if strings.Join(rt.log, "\n") != strings.Join(want, "\n") {
		t.Errorf("recorded exchanges:\n%s\nwant:\n%s", strings.Join(rt.log, "\n"), strings.Join(want, "\n"))
	}
	if len(connected) != 2 {
		t.Errorf("OnConnect ran %d times, want 2", len(connected))
	}
}

// TestClientCertificateChain checks enroll, reenroll and serverkeygen responses that carry the
// chain of the issued certificate.
func TestClientCertificateChain(t *testing.T) {
	t.Parallel()

	key := mustGenerateECPrivateKey(t)
	chain := mustMakeAlternateCertChain(t, key, "Chain Test")
	other := mustMakeAlternateCertChain(t, mustGenerateECPrivateKey(t), "Other Test")[0]

	testcases := []struct {
		name    string
		certs   []*x509.Certificate
		allow   bool
		errText string
	}{
		{name: "Single", certs: chain[:1], allow: false},
		{name: "ChainRefused", certs: chain, allow: false, errText: "certificates returned"},
		{name: "ChainAllowed", certs: chain, allow: true},
		{name: "ChainReversed", certs: reversed(chain), allow: true},
		{name: "TwoLeaves", certs: append([]*x509.Certificate{other}, chain...), allow: true, errText: "2 of them issued no other"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := httptest.NewTLSServer(certsHandler(t, tc.certs))
			defer s.Close()

			pool := x509.NewCertPool()
			pool.AddCert(s.Certificate())
			client := &est.Client{
				Host:                  strings.TrimPrefix(s.URL, "https://"),
				ExplicitAnchor:        pool,
				AllowCertificateChain: tc.allow,
			}

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			csr := mustCreateCertificateRequest(t, key, "Chain Test", nil)
			calls := map[string]func() (*x509.Certificate, error){
				"Enroll":   func() (*x509.Certificate, error) { return client.Enroll(ctx, csr) },
				"Reenroll": func() (*x509.Certificate, error) { return client.Reenroll(ctx, csr) },
				"ServerKeyGen": func() (*x509.Certificate, error) {
					cert, _, err := client.ServerKeyGen(ctx, csr)
					return cert, err
				},
			}
			for name, call := range calls {
				cert, err := call()
				if tc.errText != "" {
					if err == nil || !strings.Contains(err.Error(), tc.errText) {
						t.Errorf("%s: got error %v, want one containing %q", name, err, tc.errText)
					}
					continue
				}
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				if !bytes.Equal(cert.Raw, chain[0].Raw) {
					t.Errorf("%s returned %s, want the issued certificate", name, cert.Subject)
				}
			}
		})
	}
}

// reversed returns the certificates in reverse order.
func reversed(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	for i, cert := range certs {
		out[len(certs)-1-i] = cert
	}
	return out
}

// certsHandler answers simpleenroll and simplereenroll with a certs-only response holding certs,
// and serverkeygen with a placeholder key and the same response.
func certsHandler(t *testing.T, certs []*x509.Certificate) http.Handler {
	t.Helper()

	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatalf("failed to encode certs-only response: %v", err)
	}
	body := []byte(base64.StdEncoding.EncodeToString(p7))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case enrollEndpoint, reenrollEndpoint:
			w.Header().Set(typeHeader, "application/pkcs7-mime; smime-type=certs-only")
			w.Header().Set(encodingHeader, encodingBase64)
			_, _ = w.Write(body)
		case "/.well-known/est/serverkeygen":
			var buf bytes.Buffer
			mw := multipart.NewWriter(&buf)
			for _, part := range []struct {
				ctype string
				data  []byte
			}{
				{"application/pkcs8", []byte(base64.StdEncoding.EncodeToString([]byte{0x30, 0x00}))},
				{"application/pkcs7-mime; smime-type=certs-only", body},
			} {
				pw, err := mw.CreatePart(textproto.MIMEHeader{typeHeader: {part.ctype}, encodingHeader: {encodingBase64}})
				if err != nil {
					t.Errorf("failed to create part: %v", err)
					return
				}
				_, _ = pw.Write(part.data)
			}
			_ = mw.Close()
			w.Header().Set(typeHeader, "multipart/mixed; boundary="+mw.Boundary())
			_, _ = w.Write(buf.Bytes())
		default:
			http.NotFound(w, r)
		}
	})
}
