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

package tpm_test

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/misiektoja/go-pki-est/internal/tpm"
)

// TestKDFa checks KDFa against the go-tpm implementation, including outputs
// that need more than 33 PRF iterations.
func TestKDFa(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		hash     crypto.Hash
		numbytes int
	}{
		{name: "SHA256/Short", hash: crypto.SHA256, numbytes: 16},
		{name: "SHA256/OneBlock", hash: crypto.SHA256, numbytes: sha256.Size},
		{name: "SHA256/33Blocks", hash: crypto.SHA256, numbytes: 33 * sha256.Size},
		{name: "SHA256/34Blocks", hash: crypto.SHA256, numbytes: 34 * sha256.Size},
		{name: "SHA256/Partial", hash: crypto.SHA256, numbytes: 40*sha256.Size + 5},
		{name: "SHA1/34Blocks", hash: crypto.SHA1, numbytes: 34 * sha1.Size},
	}

	key := []byte("seed")
	context := []byte("context")

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tpm.KDFa(tc.hash.New, key, "IDENTITY", context, tc.numbytes)
			if err != nil {
				t.Fatalf("failed to derive key: %v", err)
			}

			want := tpm2.KDFaHash(tc.hash, key, "IDENTITY", context, nil, tc.numbytes*8)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %d bytes that differ from the go-tpm output of %d bytes", len(got), len(want))
			}
		})
	}
}

// TestKDFaLengthRange checks that KDFa refuses lengths whose bit count does
// not fit in 32 bits.
func TestKDFaLengthRange(t *testing.T) {
	t.Parallel()

	for _, numbytes := range []int{-1, 1 << 29} {
		if _, err := tpm.KDFa(sha256.New, []byte("seed"), "IDENTITY", nil, numbytes); err == nil {
			t.Errorf("numbytes %d: got no error, want one", numbytes)
		}
	}
}
