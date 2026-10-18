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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/misiektoja/go-pki-est"
)

// checkTestPassword accepts the password xyzzy and, like a hook that also signs clients in by
// certificate, requests without credentials.
func checkTestPassword(ctx context.Context, r *http.Request, aps, username, password string) error {
	if username == "" || password == "xyzzy" {
		return nil
	}
	return errors.New("wrong password")
}

// newPasswordRenewalRequest returns a /simplereenroll request for cn without a client certificate.
func newPasswordRenewalRequest(t *testing.T, cn, username, password string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, reenrollEndpoint, bytes.NewReader(mustMakeBase64CSR(t, cn)))
	req.Header.Set(typeHeader, mimeTypePKCS10)
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	return req
}

// TestPasswordRenewal checks which /simplereenroll requests without a client certificate
// PasswordRenewal accepts.
func TestPasswordRenewal(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		enabled  bool
		username string
		password string
		status   int
	}{
		{name: "Accepted", enabled: true, username: "device-1", password: "xyzzy", status: http.StatusOK},
		{name: "Disabled", username: "device-1", password: "xyzzy", status: http.StatusForbidden},
		{name: "NoCredentials", enabled: true, status: http.StatusForbidden},
		{name: "WrongPassword", enabled: true, username: "device-1", password: "wrong", status: http.StatusUnauthorized},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newRenewalCA(t)
			h := newHookRouter(t, est.ServerConfig{
				CA:              ca,
				CheckBasicAuth:  checkTestPassword,
				PasswordRenewal: tc.enabled,
			})

			w := httptest.NewRecorder()
			h.ServeHTTP(w, newPasswordRenewalRequest(t, "Device", tc.username, tc.password))

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if ca.called != (tc.status == http.StatusOK) {
				t.Fatalf("Reenroll called %t, want %t", ca.called, tc.status == http.StatusOK)
			}
			if ca.called && ca.cert != nil {
				t.Errorf("Reenroll got a certificate, want none")
			}
		})
	}
}

// TestPasswordRenewalWithCertificate checks that a client certificate is still compared with
// the request when PasswordRenewal is set and the request carries a password.
func TestPasswordRenewalWithCertificate(t *testing.T) {
	t.Parallel()

	ca := newRenewalCA(t)
	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Device", nil)
	cert, err := ca.Enroll(context.Background(), csr, "", nil)
	if err != nil {
		t.Fatalf("failed to issue client certificate: %v", err)
	}
	h := newHookRouter(t, est.ServerConfig{CA: ca, CheckBasicAuth: checkTestPassword, PasswordRenewal: true})

	testcases := []struct {
		name   string
		cn     string
		status int
	}{
		{name: "SameSubject", cn: "Device", status: http.StatusOK},
		{name: "ChangedSubject", cn: "Other", status: http.StatusForbidden},
	}

	for _, tc := range testcases {
		req := newPasswordRenewalRequest(t, tc.cn, "device-1", "xyzzy")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != tc.status {
			t.Fatalf("%s: got status %d, want %d: %s", tc.name, w.Code, tc.status, w.Body.String())
		}
	}
	if !ca.called || ca.cert == nil || !bytes.Equal(ca.cert.Raw, cert.Raw) {
		t.Errorf("Reenroll did not receive the client certificate")
	}
}

// TestPasswordRenewalRequiresCheckBasicAuth checks that NewRouter refuses PasswordRenewal when
// nothing checks the password.
func TestPasswordRenewalRequiresCheckBasicAuth(t *testing.T) {
	t.Parallel()

	if _, err := est.NewRouter(&est.ServerConfig{CA: newRenewalCA(t), PasswordRenewal: true}); err == nil {
		t.Fatal("NewRouter accepted PasswordRenewal without CheckBasicAuth")
	}
}

// TestClientPasswordRenewal checks that Client.Reenroll renews with a password alone over TLS.
func TestClientPasswordRenewal(t *testing.T) {
	t.Parallel()

	ca := newRenewalCA(t)
	client := newHookClient(t, newHookRouter(t, est.ServerConfig{CA: ca, CheckBasicAuth: checkTestPassword, PasswordRenewal: true}))
	client.Username, client.Password = "device-1", "xyzzy"

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := client.Reenroll(ctx, mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Device", nil)); err != nil {
		t.Fatalf("failed to renew: %v", err)
	}
	if !ca.called || ca.cert != nil {
		t.Errorf("Reenroll called %t with certificate %t, want a call without certificate", ca.called, ca.cert != nil)
	}
}
