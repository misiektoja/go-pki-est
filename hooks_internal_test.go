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

package est

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestIsPKCS8 checks the structural PKCS#8 classification used by serverkeygen.
func TestIsPKCS8(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	ec, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	unknown := mustMarshal(t, oneAsymmetricKey{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}},
		PrivateKey: []byte{1, 2, 3, 4},
	})
	withPublicKey := mustMarshal(t, oneAsymmetricKey{
		Version:    1,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}},
		PrivateKey: []byte{1, 2, 3, 4},
		PublicKey:  asn1.BitString{Bytes: []byte{5, 6}, BitLength: 16},
	})
	badVersion := mustMarshal(t, oneAsymmetricKey{
		Version:    2,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}},
		PrivateKey: []byte{1, 2, 3, 4},
	})
	noKey := mustMarshal(t, oneAsymmetricKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}},
	})

	testcases := []struct {
		name string
		der  []byte
		want bool
	}{
		{name: "ECDSA", der: ec, want: true},
		{name: "UnknownAlgorithm", der: unknown, want: true},
		{name: "Version2WithPublicKey", der: withPublicKey, want: true},
		{name: "UnknownVersion", der: badVersion},
		{name: "EmptyPrivateKey", der: noKey},
		{name: "TrailingData", der: append(append([]byte(nil), ec...), 0)},
		{name: "NotDER", der: []byte("not a key")},
		{name: "Empty"},
	}

	for _, tc := range testcases {
		if got := isPKCS8(tc.der); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestCACertCacheWithoutSelfSignedRoot checks that CA certificates without a self-signed
// certificate give an empty root pool, because a nil pool would make Verify trust the
// system roots.
func TestCACertCacheWithoutSelfSignedRoot(t *testing.T) {
	t.Parallel()

	rootKey, root := mustCertificate(t, "Root", nil, nil, true)
	interKey, inter := mustCertificate(t, "Intermediate", root, rootKey, true)
	_, leaf := mustCertificate(t, "Device", inter, interKey, false)

	c := newCACertCache(nil)

	entry := c.addSync("intermediate-only", []*x509.Certificate{inter})
	if entry.roots == nil {
		t.Fatal("got a nil root pool, which falls back to the system roots")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: entry.roots, Intermediates: entry.inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("verified a certificate without a trusted root")
	}

	entry = c.addSync("with-root", []*x509.Certificate{inter, root})
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: entry.roots, Intermediates: entry.inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("failed to verify a certificate under the cached root: %v", err)
	}
}

// mustMarshal DER-encodes v or fails the test.
func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	return der
}

// mustCertificate creates a certificate for cn signed by issuer, or self-signed when issuer is nil.
func mustCertificate(t *testing.T, cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, isCA bool) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if issuer == nil {
		issuer, issuerKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return key, cert
}
