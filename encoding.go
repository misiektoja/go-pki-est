/*
Copyright (c) 2020 GMO GlobalSign, Inc.

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
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/google/go-tpm/legacy/tpm2"
	"go.mozilla.org/pkcs7"
)

const (
	base64LineLength = 76
)

// base64Encode base64-encodes a slice of bytes using standard encoding.
func base64Encode(src []byte) []byte {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(enc, src)
	return breakLines(enc, base64LineLength)
}

// base64Decode base64-decodes a slice of bytes using standard encoding. It
// ignores spaces, tabs and line breaks, which RFC 8951 section 3.1 asks
// receivers to tolerate.
func base64Decode(src []byte) ([]byte, error) {
	src = bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, src)
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dec, src)
	if err != nil {
		return nil, err
	}
	return dec[:n], nil
}

// encodePKCS7CertsOnly encodes a slice of certificates as a PKCS#7 degenerate
// "certs-only" response.
func encodePKCS7CertsOnly(certs []*x509.Certificate) ([]byte, error) {
	var cb []byte
	for _, cert := range certs {
		cb = append(cb, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(cb)
}

// decodePKCS7CertsOnly decodes a PKCS#7 degenerate "certs-only" response and
// returns the certificate(s) it contains.
func decodePKCS7CertsOnly(b []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}

// readAllBase64Response reads all data from a reader and base64-decodes it.
// It returns a normal error and is intended to be used from client code.
func readAllBase64Response(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	decoded, err := base64Decode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	return decoded, nil
}

// readCertsResponse reads all data from a reader and decodes it as a base64
// encoded PKCS#7 certs-only structure. It returns a normal error and is
// intended to be used from client code.
func readCertsResponse(r io.Reader) ([]*x509.Certificate, error) {
	p7, err := readAllBase64Response(r)
	if err != nil {
		return nil, err
	}

	certs, err := decodePKCS7CertsOnly(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}

	return certs, nil
}

// readCertResponse reads all data from a reader and decodes it as a base64
// encoded PKCS#7 certs-only structure which is expected to contain exactly
// one certificate. With allowChain it may also hold the chain of that
// certificate, which is then the one certificate that issued none of the
// others. It returns a normal error and is intended to be used from client
// code.
func readCertResponse(r io.Reader, allowChain bool) (*x509.Certificate, error) {
	p7, err := readAllBase64Response(r)
	if err != nil {
		return nil, err
	}

	certs, err := decodePKCS7CertsOnly(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}

	switch n := len(certs); {
	case n < 1:
		return nil, errors.New("no certificate returned")
	case n == 1:
		return certs[0], nil
	case !allowChain:
		return nil, fmt.Errorf("%d certificates returned", n)
	default:
		return issuedCertificate(certs)
	}
}

// issuedCertificate returns the certificate of a chain that issued none of
// the others. Issuers are matched by name only, because crypto/x509 cannot
// check every signature algorithm a CA may use.
func issuedCertificate(certs []*x509.Certificate) (*x509.Certificate, error) {
	var leaves []*x509.Certificate
	for i, cert := range certs {
		issuer := false
		for j, other := range certs {
			if i != j && bytes.Equal(other.RawIssuer, cert.RawSubject) {
				issuer = true
				break
			}
		}
		if !issuer {
			leaves = append(leaves, cert)
		}
	}

	if len(leaves) != 1 {
		return nil, fmt.Errorf("%d certificates returned and %d of them issued no other", len(certs), len(leaves))
	}

	return leaves[0], nil
}

// readCSRAttrsResponse reads all data from a reader and decodes it as a base64
// encoded CSR attributes structure. It returns a normal error and is intended
// to be used from client code.
func readCSRAttrsResponse(r io.Reader) (CSRAttrs, error) {
	der, err := readAllBase64Response(r)
	if err != nil {
		return CSRAttrs{}, err
	}

	var attrs CSRAttrs
	if err := attrs.Unmarshal(der); err != nil {
		return CSRAttrs{}, fmt.Errorf("failed to unmarshal CSR attributes: %w", err)
	}

	return attrs, nil
}

// readAllBase64Response reads all data from a reader and base64-decodes it.
// It returns an error implementing Error and is intended to be used by server
// code.
func readAllBase64Request(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, errBodyTooLarge
		}

		return nil, errInternal
	}

	decoded, err := base64Decode(b)
	if err != nil {
		return nil, errInvalidBase64
	}

	return decoded, nil
}

// readCSRRequest reads all data from a reader and decodes it as a base64
// encoded PKCS#10 CSR. If check is not nil, it verifies the CSR signature after
// decoding. It returns an error implementing Error and is intended to be used
// by server code.
func readCSRRequest(r io.Reader, check func(*x509.CertificateRequest) error) (*x509.CertificateRequest, error) {
	der, estErr := readAllBase64Request(r)
	if estErr != nil {
		return nil, estErr
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errInvalidPKCS10
	}

	if check != nil {
		if err := check(csr); err != nil {
			var hostErr Error
			switch {
			case errors.As(err, &hostErr):
				return nil, err
			case errors.Is(err, x509.ErrUnsupportedAlgorithm):
				return nil, errUnsupportedPKCS10Signature
			default:
				return nil, errInvalidPKCS10Signature
			}
		}
	}

	return csr, nil
}

// readCertsRequest reads all data from a reader and decodes it as a base64
// encoded PKCS#7 certs-only structure. It returns an error implementing Error
// and is intended to be used by server code.
func readCertsRequest(r io.Reader) ([]*x509.Certificate, error) {
	der, estErr := readAllBase64Request(r)
	if estErr != nil {
		return nil, estErr
	}

	certs, err := decodePKCS7CertsOnly(der)
	if err != nil {
		return nil, errInvalidPKCS7
	}

	if n := len(certs); n < 1 {
		return nil, errNoCertificatesInPKCS7
	}

	return certs, nil
}

// readTPMPublicAreaRequest reads all data from a reader and decodes it as a
// base64 encoded TPM object public area. It returns an error implementing
// Error and is intended to be used by server code.
func readTPMPublicAreaRequest(r io.Reader) ([]byte, error) {
	pub, estErr := readAllBase64Request(r)
	if estErr != nil {
		return nil, estErr
	}

	if _, err := tpm2.DecodePublic(pub); err != nil {
		return nil, errInvalidTPMPublicArea
	}

	return pub, nil
}

// validatePublicAreaPublicKey checks if the public key in the provided TPM
// object public area matches the provided public key. It returns an error
// implementing Error and is intended to be used by server code.
func validatePublicAreaPublicKey(pub []byte, key crypto.PublicKey) error {
	dec, err := tpm2.DecodePublic(pub)
	if err != nil {
		return errInvalidTPMPublicArea
	}

	var pk crypto.PublicKey
	if pk, err = dec.Key(); err != nil {
		return errExtractPublicAreaKey
	}

	if !reflect.DeepEqual(pk, key) {
		return errTPMPublicKeyNoMatch
	}

	return nil
}

// breakLines inserts a CRLF line break in the provided slice of bytes every n
// bytes, including a terminating CRLF for the last line.
func breakLines(b []byte, n int) []byte {
	crlf := []byte{'\r', '\n'}
	initialLen := len(b)

	// Just return a terminating CRLF if the input is empty.
	if initialLen == 0 {
		return crlf
	}

	// Allocate a buffer with suitable capacity to minimize allocations.
	buf := bytes.NewBuffer(make([]byte, 0, initialLen+((initialLen/n)+1)*2))

	// Split input into CRLF-terminated lines.
	for {
		lineLen := len(b)
		if lineLen == 0 {
			break
		} else if lineLen > n {
			lineLen = n
		}

		buf.Write(b[0:lineLen])
		b = b[lineLen:]
		buf.Write(crlf)
	}

	return buf.Bytes()
}

// oneAsymmetricKey is the PKCS#8 PrivateKeyInfo structure as extended by
// RFC 5958.
type oneAsymmetricKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue  `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1"`
}

// isPKCS8 reports whether der is a PKCS#8 private key of any algorithm. It
// checks the structure only, so it accepts keys crypto/x509 cannot parse.
func isPKCS8(der []byte) bool {
	var key oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &key)
	return err == nil && len(rest) == 0 && (key.Version == 0 || key.Version == 1) && len(key.PrivateKey) > 0
}
