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
	"errors"
	"fmt"
	"io"
	"net/http"
)

// responseTooLargeError reports a response body that passed the client's
// limit.
type responseTooLargeError struct {
	limit int64
}

// Error returns the message with the limit in bytes.
func (e *responseTooLargeError) Error() string {
	return fmt.Sprintf("response body larger than %d bytes", e.limit)
}

// boundResponses is a RoundTripper that bounds the body of every response of
// the transport it wraps, so a server cannot make the client buffer or parse
// more than max bytes. The client reads whole bodies, and the PKCS#7 decoder
// recurses once per nested structure, so an unbounded body costs memory
// without limit and a deeply nested one exhausts the stack.
type boundResponses struct {
	next http.RoundTripper
	max  int64
}

// RoundTrip passes the request on and bounds the body of the response.
func (b *boundResponses) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{body: resp.Body, remaining: b.max, limit: b.max}
	return resp, nil
}

// limitedBody reads at most limit bytes from a response body and fails the
// read that would pass it, as http.MaxBytesReader does for request bodies. A
// body of exactly limit bytes reads to its end.
type limitedBody struct {
	body      io.ReadCloser
	remaining int64
	limit     int64
	err       error
}

// Read reads from the body until the limit is passed. The error of a read
// that ended or failed the body is returned again by every later read.
func (l *limitedBody) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Reading one byte past the budget tells a body that ends at the limit
	// from one that passes it.
	if int64(len(p))-1 > l.remaining {
		p = p[:l.remaining+1]
	}
	n, err := l.body.Read(p)
	if int64(n) <= l.remaining {
		l.remaining -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.remaining)
	l.remaining = 0
	l.err = &responseTooLargeError{limit: l.limit}
	return n, l.err
}

// Close closes the body.
func (l *limitedBody) Close() error {
	return l.body.Close()
}

// readError returns the limit error when the body of resp passed the client's
// limit, because a reader that parses lines, such as the multipart reader,
// reports a truncated line instead. Otherwise it returns err.
func readError(resp *http.Response, err error) error {
	if body, ok := resp.Body.(*limitedBody); ok {
		if tooLarge, ok := errors.AsType[*responseTooLargeError](body.err); ok {
			return tooLarge
		}
	}
	return err
}
