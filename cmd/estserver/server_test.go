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

package main

import (
	"net"
	"testing"
)

// TestDefaultListenAddr checks that estserver serves the local host only unless the
// configuration names another address, because its mock CA issues a certificate to anyone.
func TestDefaultListenAddr(t *testing.T) {
	t.Parallel()

	host, _, err := net.SplitHostPort(defaultListenAddr)
	if err != nil {
		t.Fatalf("failed to split %q: %v", defaultListenAddr, err)
	}
	if host != "localhost" {
		t.Errorf("default listen host is %q, want localhost", host)
	}
}
