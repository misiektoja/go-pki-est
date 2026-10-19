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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	est "github.com/misiektoja/go-pki-est"
	"github.com/misiektoja/go-pki-est/internal/mockca"
)

// statusError is a host error with a chosen status and Retry-After value.
type statusError struct {
	status int
	retry  int
}

// Error returns the text sent to the client.
func (e statusError) Error() string { return "refused by host" }

// StatusCode returns the HTTP status sent to the client.
func (e statusError) StatusCode() int { return e.status }

// RetryAfter returns the Retry-After value in seconds.
func (e statusError) RetryAfter() int { return e.retry }

// refusalLog records refusals with the context error seen at the time.
type refusalLog struct {
	mu       sync.Mutex
	refusals []est.Refusal
	ctxErrs  []error
	err      error
}

// RecordRefusal stores the refusal and returns the configured error.
func (l *refusalLog) RecordRefusal(ctx context.Context, refusal est.Refusal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refusals = append(l.refusals, refusal)
	l.ctxErrs = append(l.ctxErrs, ctx.Err())
	return l.err
}

// recorded returns a copy of the stored refusals.
func (l *refusalLog) recorded() []est.Refusal {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]est.Refusal(nil), l.refusals...)
}

// newHookRouter returns a router for cfg, backed by a transient mock CA when cfg has no CA.
func newHookRouter(t *testing.T, cfg est.ServerConfig) http.Handler {
	t.Helper()

	if cfg.CA == nil {
		ca, err := mockca.NewTransient()
		if err != nil {
			t.Fatalf("failed to create mock CA: %v", err)
		}
		cfg.CA = ca
	}

	r, err := est.NewRouter(&cfg)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	return r
}

// newHookClient serves h over TLS until the test ends and returns a client that trusts the server.
func newHookClient(t *testing.T, h http.Handler) *est.Client {
	t.Helper()

	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)

	anchor := x509.NewCertPool()
	anchor.AddCert(s.Certificate())

	return &est.Client{
		Host:           strings.TrimPrefix(s.URL, "https://"),
		ExplicitAnchor: anchor,
	}
}

// serve sends one request to h and returns the recorded response.
func serve(h http.Handler, method, target, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set(typeHeader, contentType)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	return w
}

// mustTamperCSR returns a base64 PKCS#10 request whose signature no longer matches its content.
func mustTamperCSR(t *testing.T) []byte {
	t.Helper()

	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Tampered", nil)
	der := append([]byte(nil), csr.Raw...)
	der[len(der)-1] ^= 0xff

	return []byte(base64.StdEncoding.EncodeToString(der))
}

// TestCheckBasicAuthResult checks how CheckBasicAuth results map to responses.
func TestCheckBasicAuthResult(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name       string
		result     error
		status     int
		challenge  bool
		retryAfter string
	}{
		{name: "Accepted", status: http.StatusOK},
		{name: "Forbidden", result: statusError{status: http.StatusForbidden}, status: http.StatusForbidden},
		{name: "Throttled", result: statusError{status: http.StatusTooManyRequests, retry: 7}, status: http.StatusTooManyRequests, retryAfter: "7"},
		{name: "UnauthorizedError", result: statusError{status: http.StatusUnauthorized}, status: http.StatusUnauthorized, challenge: true},
		{name: "PlainError", result: errors.New("bad credentials"), status: http.StatusUnauthorized, challenge: true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotUser, gotPassword string
			h := newHookRouter(t, est.ServerConfig{
				CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
					gotUser, gotPassword = username, password
					return tc.result
				},
			})

			w := serve(h, http.MethodPost, enrollEndpoint, mimeTypePKCS10, mustMakeBase64CSR(t, "Device"))

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if gotUser != "" || gotPassword != "" {
				t.Errorf("got credentials %q/%q for a request without an Authorization header", gotUser, gotPassword)
			}
			//nolint:staticcheck // SA1008: the server stores the header under this spelling for libest.
			if got := len(w.Header()["WWW-Authenticate"]) > 0; got != tc.challenge {
				t.Errorf("got Basic challenge %t, want %t", got, tc.challenge)
			}
			if got := w.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("got Retry-After %q, want %q", got, tc.retryAfter)
			}
		})
	}
}

// TestBasicChallengeSpelling checks that the Basic challenge goes out as WWW-Authenticate on the wire.
// libest compares header names case-sensitively and ignores Go's canonical Www-Authenticate.
func TestBasicChallengeSpelling(t *testing.T) {
	t.Parallel()

	head, _ := basicChallenge(t)
	if !strings.Contains(head, "\r\nWWW-Authenticate: Basic realm=") {
		t.Errorf("challenge header not spelled WWW-Authenticate: %q", head)
	}
}

// TestBasicChallengeHasNoBody checks that the Basic challenge carries no content. Bouncy Castle
// closes the challenge without reading it and fails when content is left unread.
func TestBasicChallengeHasNoBody(t *testing.T) {
	t.Parallel()

	head, body := basicChallenge(t)
	if !strings.Contains(head, "\r\nContent-Length: 0\r\n") || body != "" {
		t.Errorf("challenge has content: %q %q", head, body)
	}
}

// basicChallenge sends an enrollment request with refused credentials over a raw connection and
// returns the head and body of the 401 answer as they appear on the wire.
func basicChallenge(t *testing.T) (string, string) {
	t.Helper()

	h := newHookRouter(t, est.ServerConfig{
		CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
			return errors.New("bad credentials")
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	csr := mustMakeBase64CSR(t, "Device")
	request := "POST " + enrollEndpoint + " HTTP/1.1\r\nHost: est.example.test\r\nContent-Type: " + mimeTypePKCS10 +
		"\r\nContent-Length: " + strconv.Itoa(len(csr)) + "\r\nConnection: close\r\n\r\n" + string(csr)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	if !strings.HasPrefix(head, "HTTP/1.1 401") {
		t.Fatalf("got response %q, want 401", head)
	}
	return head + "\r\n", body
}

// TestCheckCSRSignature checks that the CSR signature hook replaces the default check on enroll.
func TestCheckCSRSignature(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name        string
		check       func(*x509.CertificateRequest) error
		body        func(*testing.T) []byte
		status      int
		bodyContain string
	}{
		{
			name:   "HostAccepts",
			check:  func(*x509.CertificateRequest) error { return nil },
			body:   mustTamperCSR,
			status: http.StatusOK,
		},
		{
			name:   "HostError",
			check:  func(*x509.CertificateRequest) error { return statusError{status: http.StatusForbidden} },
			body:   func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status: http.StatusForbidden,
		},
		{
			name:   "PlainError",
			check:  func(*x509.CertificateRequest) error { return errors.New("bad signature") },
			body:   func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status: http.StatusBadRequest,
		},
		{
			name:        "UnsupportedAlgorithm",
			check:       func(*x509.CertificateRequest) error { return x509.ErrUnsupportedAlgorithm },
			body:        func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status:      http.StatusBadRequest,
			bodyContain: "unsupported",
		},
		{
			name:   "DefaultCheck",
			body:   mustTamperCSR,
			status: http.StatusBadRequest,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHookRouter(t, est.ServerConfig{CheckCSRSignature: tc.check})

			w := serve(h, http.MethodPost, enrollEndpoint, mimeTypePKCS10, tc.body(t))

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.bodyContain) {
				t.Errorf("got body %q, want it to contain %q", w.Body.String(), tc.bodyContain)
			}
		})
	}
}

// TestServerKeyGenIgnoresCSRSignature checks that serverkeygen accepts a request with a bad
// signature and never calls the signature hook, as RFC 7030 section 4.4.1 requires.
func TestServerKeyGenIgnoresCSRSignature(t *testing.T) {
	t.Parallel()

	for _, check := range []func(*x509.CertificateRequest) error{
		nil,
		func(*x509.CertificateRequest) error { return statusError{status: http.StatusForbidden} },
	} {
		h := newHookRouter(t, est.ServerConfig{CheckCSRSignature: check})

		w := serve(h, http.MethodPost, "/.well-known/est/serverkeygen", mimeTypePKCS10, mustTamperCSR(t))
		if w.Code != http.StatusOK {
			t.Fatalf("hook set %t: got status %d, want 200: %s", check != nil, w.Code, w.Body.String())
		}
	}
}

// TestRefusalRecorder checks which refusals reach the recorder and what they carry.
func TestRefusalRecorder(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        func(*testing.T) []byte
		status      int
		operation   string
		aps         string
	}{
		{
			name:        "WrongContentType",
			method:      http.MethodPost,
			target:      "/.well-known/est/mylabel/simpleenroll",
			contentType: mimeTypeText,
			body:        func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status:      http.StatusUnsupportedMediaType,
			operation:   "simpleenroll",
			aps:         "mylabel",
		},
		{
			name:        "MalformedBody",
			method:      http.MethodPost,
			target:      enrollEndpoint,
			contentType: mimeTypePKCS10,
			body:        func(*testing.T) []byte { return []byte("not a request") },
			status:      http.StatusBadRequest,
			operation:   "simpleenroll",
		},
		{
			name:        "RenewalWithoutCertificate",
			method:      http.MethodPost,
			target:      reenrollEndpoint,
			contentType: mimeTypePKCS10,
			body:        func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status:      http.StatusForbidden,
			operation:   "simplereenroll",
		},
		{
			name:        "AuthenticationFailure",
			method:      http.MethodPost,
			target:      "/.well-known/est/locked/simpleenroll",
			contentType: mimeTypePKCS10,
			body:        func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Device") },
			status:      http.StatusUnauthorized,
		},
		{
			name:        "CAError",
			method:      http.MethodPost,
			target:      "/.well-known/est/" + triggerErrorsAPS + "/simpleenroll",
			contentType: mimeTypePKCS10,
			body:        func(t *testing.T) []byte { return mustMakeBase64CSR(t, "Trigger Error Forbidden") },
			status:      http.StatusForbidden,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			log := &refusalLog{}
			h := newHookRouter(t, est.ServerConfig{
				Refusals: log,
				CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
					if aps == "locked" {
						return errors.New("bad credentials")
					}
					return nil
				},
			})

			w := serve(h, tc.method, tc.target, tc.contentType, tc.body(t))
			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}

			got := log.recorded()
			if tc.operation == "" {
				if len(got) != 0 {
					t.Fatalf("got %d refusals, want none for a decision the host or CA made", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d refusals, want 1", len(got))
			}

			refusal := got[0]
			if refusal.Operation != tc.operation || refusal.AdditionalPathSegment != tc.aps || refusal.Status != tc.status {
				t.Errorf("got refusal %s/%q/%d, want %s/%q/%d", refusal.Operation, refusal.AdditionalPathSegment, refusal.Status, tc.operation, tc.aps, tc.status)
			}
			if refusal.Reason == "" || refusal.Request == nil {
				t.Errorf("got refusal without reason or request: %+v", refusal)
			}
			if err := log.ctxErrs[0]; err != nil {
				t.Errorf("got recorder context error %v, want an active context", err)
			}
		})
	}
}

// TestRefusalRecorderFailureKeepsResponse checks that a failing recorder does not change the response.
func TestRefusalRecorderFailureKeepsResponse(t *testing.T) {
	t.Parallel()

	log := &refusalLog{err: errors.New("store unavailable")}
	h := newHookRouter(t, est.ServerConfig{Refusals: log})

	w := serve(h, http.MethodPost, enrollEndpoint, mimeTypeText, mustMakeBase64CSR(t, "Device"))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
	if len(log.recorded()) != 1 {
		t.Fatalf("got %d refusals, want 1", len(log.recorded()))
	}
}

// TestRateLimitRetryAfter checks that the built-in rate limit answers 429 with Retry-After.
func TestRateLimitRetryAfter(t *testing.T) {
	t.Parallel()

	log := &refusalLog{}
	h := newHookRouter(t, est.ServerConfig{RateLimit: 1, Refusals: log})

	// The limiter allows a burst of twice the rate, so a short loop exceeds it.
	for range 10 {
		w := serve(h, http.MethodGet, cacertsEndpoint, "", nil)
		if w.Code == http.StatusOK {
			continue
		}
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("got status %d, want %d", w.Code, http.StatusTooManyRequests)
		}
		if got := w.Header().Get("Retry-After"); got != "1" {
			t.Errorf("got Retry-After %q, want %q", got, "1")
		}
		if got := log.recorded(); len(got) != 1 || got[0].Status != http.StatusTooManyRequests {
			t.Errorf("got refusals %+v, want one 429", got)
		}
		return
	}

	t.Fatal("rate limit was never reached")
}

// TestOmitTransferEncoding checks the Content-Transfer-Encoding header on single and multipart responses.
func TestOmitTransferEncoding(t *testing.T) {
	t.Parallel()

	for _, omit := range []bool{false, true} {
		want := encodingBase64
		if omit {
			want = ""
		}

		h := newHookRouter(t, est.ServerConfig{OmitTransferEncoding: omit})

		w := serve(h, http.MethodGet, cacertsEndpoint, "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("omit %t: got cacerts status %d", omit, w.Code)
		}
		if got := w.Header().Get(encodingHeader); got != want {
			t.Errorf("omit %t: got cacerts %s %q, want %q", omit, encodingHeader, got, want)
		}
		if _, err := base64.StdEncoding.DecodeString(w.Body.String()); err != nil {
			t.Errorf("omit %t: cacerts body is not base64: %v", omit, err)
		}

		w = serve(h, http.MethodPost, "/.well-known/est/serverkeygen", mimeTypePKCS10, mustMakeBase64CSR(t, "Device"))
		if w.Code != http.StatusOK {
			t.Fatalf("omit %t: got serverkeygen status %d: %s", omit, w.Code, w.Body.String())
		}
		for _, part := range mustReadParts(t, w) {
			if got := part.header.Get(encodingHeader); got != want {
				t.Errorf("omit %t: got part %s %q, want %q", omit, encodingHeader, got, want)
			}
		}
	}
}

// TestBase64Whitespace checks that requests with spaces, tabs and line breaks in base64 are accepted.
func TestBase64Whitespace(t *testing.T) {
	t.Parallel()

	h := newHookRouter(t, est.ServerConfig{})

	plain := mustMakeBase64CSR(t, "Device")
	var spaced bytes.Buffer
	for i := 0; i < len(plain); i += 16 {
		end := min(i+16, len(plain))
		spaced.Write(plain[i:end])
		spaced.WriteString(" \t\r\n")
	}

	w := serve(h, http.MethodPost, enrollEndpoint, mimeTypePKCS10, spaced.Bytes())
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// Applies the 64 KiB default request limit and the limit MaxRequestBody sets.
func TestMaxRequestBody(t *testing.T) {
	t.Parallel()

	// Whitespace pads a valid request past 64 KiB, as a large post-quantum CSR would be.
	body := append(mustMakeBase64CSR(t, "Device"), bytes.Repeat([]byte("\r\n"), 40<<10)...)
	tests := []struct {
		name   string
		limit  int64
		status int
	}{
		{"Default", 0, http.StatusRequestEntityTooLarge},
		{"Raised", 128 << 10, http.StatusOK},
		{"Exact", int64(len(body)), http.StatusOK},
		{"OneShort", int64(len(body)) - 1, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHookRouter(t, est.ServerConfig{MaxRequestBody: tc.limit})
			w := serve(h, http.MethodPost, enrollEndpoint, mimeTypePKCS10, body)
			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}
	if _, err := est.NewRouter(&est.ServerConfig{CA: ca, MaxRequestBody: -1}); err == nil {
		t.Fatal("negative MaxRequestBody accepted")
	}
}

// oneAsymmetricKey is the PKCS#8 structure used to build keys crypto/x509 cannot parse.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// keyGenCA returns a fixed private key from ServerKeyGen and delegates everything else to the mock CA.
type keyGenCA struct {
	*mockca.MockCA
	key []byte
}

// ServerKeyGen issues a certificate for the request and returns the fixed key.
func (ca keyGenCA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	cert, err := ca.Enroll(ctx, csr, aps, r)
	return cert, ca.key, err
}

// TestServerKeyGenMLDSA checks that a client receives an ML-DSA key from /serverkeygen as PKCS#8
// that crypto/x509 parses, with a certificate for its public key.
func TestServerKeyGenMLDSA(t *testing.T) {
	t.Parallel()

	key := mustGenerateMLDSAPrivateKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	inner, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}
	client := newHookClient(t, newHookRouter(t, est.ServerConfig{CA: keyGenCA{MockCA: inner, key: der}}))

	// keyGenCA issues the certificate for the request's public key, so the
	// request carries the key the CA returns.
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	cert, got, err := client.ServerKeyGen(ctx, mustCreateCertificateRequest(t, key, "Device", nil))
	if err != nil {
		t.Fatalf("failed to get server-generated key: %v", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(got)
	if err != nil {
		t.Fatalf("failed to parse server-generated key: %v", err)
	}
	if !key.Equal(parsed) {
		t.Errorf("got key %T, want the ML-DSA-65 key from the CA", parsed)
	}
	verifyPublicKey(t, cert.PublicKey, key)
}

// TestServerKeyGenUnrecognizedPKCS8 checks that PKCS#8 keys of algorithms crypto/x509 cannot parse are sent as PKCS#8.
func TestServerKeyGenUnrecognizedPKCS8(t *testing.T) {
	t.Parallel()

	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	// ML-KEM-768 from FIPS 203, which crypto/x509 does not parse.
	mlkem, err := asn1.Marshal(oneAsymmetricKey{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}},
		PrivateKey: secret,
	})
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(mlkem); err == nil {
		t.Fatal("crypto/x509 parsed the key, so the test no longer covers an unrecognized algorithm")
	}

	testcases := []struct {
		name     string
		key      []byte
		status   int
		keyType  string
		numParts int
	}{
		{name: "UnrecognizedAlgorithm", key: mlkem, status: http.StatusOK, keyType: "application/pkcs8", numParts: 2},
		{name: "NotAKey", key: []byte("not a key"), status: http.StatusInternalServerError},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner, err := mockca.NewTransient()
			if err != nil {
				t.Fatalf("failed to create mock CA: %v", err)
			}
			h := newHookRouter(t, est.ServerConfig{CA: keyGenCA{MockCA: inner, key: tc.key}})

			w := serve(h, http.MethodPost, "/.well-known/est/serverkeygen", mimeTypePKCS10, mustMakeBase64CSR(t, "Device"))
			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.status != http.StatusOK {
				return
			}

			parts := mustReadParts(t, w)
			if len(parts) != tc.numParts {
				t.Fatalf("got %d parts, want %d", len(parts), tc.numParts)
			}
			if got, _, _ := mime.ParseMediaType(parts[0].header.Get(typeHeader)); got != tc.keyType {
				t.Errorf("got key part type %q, want %q", got, tc.keyType)
			}
			key, err := base64.StdEncoding.DecodeString(string(parts[0].body))
			if err != nil || !bytes.Equal(key, tc.key) {
				t.Errorf("got key part %q, want the CA key unchanged", parts[0].body)
			}
		})
	}
}

// responsePart is one part of a multipart response with its body trimmed.
type responsePart struct {
	header http.Header
	body   []byte
}

// mustReadParts reads every part of a multipart response.
func mustReadParts(t *testing.T, w *httptest.ResponseRecorder) []responsePart {
	t.Helper()

	_, params, err := mime.ParseMediaType(w.Header().Get(typeHeader))
	if err != nil {
		t.Fatalf("failed to parse response content type: %v", err)
	}

	var parts []responsePart
	reader := multipart.NewReader(w.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return parts
		}
		if err != nil {
			t.Fatalf("failed to read response part: %v", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("failed to read response part body: %v", err)
		}
		parts = append(parts, responsePart{header: http.Header(part.Header), body: bytes.TrimSpace(body)})
	}
}
