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

package tpm

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"
	"math"
)

// KDFa implements the KDFa function per the TPM2.0 specification. The output
// length is encoded in bits as a 32-bit value, which limits numbytes to
// math.MaxUint32/8.
func KDFa(h func() hash.Hash, key []byte, label string, context []byte, numbytes int) ([]byte, error) {
	if numbytes < 0 || numbytes > math.MaxUint32/8 {
		return nil, errors.New("numbytes out of range")
	}
	l := uint32(numbytes)

	var fixed = append([]byte(label), 0x00)
	fixed = append(fixed, context...)

	var lcount = make([]byte, 4)
	binary.BigEndian.PutUint32(lcount, l*8)
	fixed = append(fixed, lcount...)

	return kdfCounter(h, key, nil, fixed, l, 4)
}

// kdfCounter implements a key derivation function in counter mode, as defined
// by NIST SP 800-108. Fixed data may be place before or after the counter, or
// both. l is the number of requested bytes, and r is the size, in bytes, of
// the counter. Only HMAC-based PRFs are supported.
func kdfCounter(h func() hash.Hash, key, before, after []byte, l, r uint32) ([]byte, error) {

	// r must be <= 32 bits, per SP800-108 section 5.
	if r < 1 || r > 4 {
		return nil, errors.New("r must be 1, 2, 3 or 4 bytes")
	}

	// Calculate number of iterations required. Hash sizes are positive.
	// max keeps the conversion and the division safe.
	var hashSize = uint64(max(h().Size(), 1))
	var n = (uint64(l) + hashSize - 1) / hashSize

	// Number of iterations shall not exceed (2^r)-1, per SP800-108 section 5.
	// Since this function accepts r in bytes, we multiply r by 8.
	if n > (uint64(1)<<(8*r))-1 {
		return nil, errors.New("l too large")
	}

	// Perform PRF iterations. The counter is written as the last r bytes of
	// a 64-bit big-endian value, which the bound above keeps in range.
	var out = make([]byte, 0, n*hashSize)
	var cbuf = make([]byte, 8)
	for c := uint64(1); c <= n; c++ {
		binary.BigEndian.PutUint64(cbuf, c)

		var mac = hmac.New(h, key)
		mac.Write(before)
		mac.Write(cbuf[8-r:])
		mac.Write(after)

		out = append(out, mac.Sum(nil)...)
	}

	// Return only the requested number of bytes.
	return out[:l], nil
}
