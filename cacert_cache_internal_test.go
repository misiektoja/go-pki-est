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
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

// TestCACertCacheBound checks that the CA certificate cache holds at most maxCacheEntries
// additional path segments and evicts the least recently updated one. Any peer can add an entry
// per segment through /cacerts, so an unbounded cache lets a peer exhaust the server's memory.
func TestCACertCacheBound(t *testing.T) {
	t.Parallel()

	_, root := mustCertificate(t, "Root", nil, nil, true)
	certs := []*x509.Certificate{root}
	c := newCACertCache(nil)

	const extra = 10
	for i := range maxCacheEntries + extra {
		c.addSync(fmt.Sprintf("ca-%d", i), certs)
	}

	if len(c.cache) != maxCacheEntries || c.order.Len() != maxCacheEntries {
		t.Fatalf("cache holds %d entries in %d list elements, want %d", len(c.cache), c.order.Len(), maxCacheEntries)
	}
	if _, ok := c.lookup("ca-0"); ok {
		t.Error("the first entry survived the bound")
	}
	if _, ok := c.lookup(fmt.Sprintf("ca-%d", extra-1)); ok {
		t.Errorf("entry %d survived the bound", extra-1)
	}
	if _, ok := c.lookup(fmt.Sprintf("ca-%d", maxCacheEntries+extra-1)); !ok {
		t.Error("the last entry was not kept")
	}

	// A stale entry that is refreshed keeps its place in the cache and becomes the most recently
	// updated, so the next eviction removes another entry.
	refreshed := fmt.Sprintf("ca-%d", extra)
	el := c.cache[refreshed]
	stale := el.Value.(cacheEntry)
	stale.updated = time.Now().Add(-2 * assumeFresh)
	el.Value = stale

	c.addSync(refreshed, certs)
	if len(c.cache) != maxCacheEntries {
		t.Fatalf("refreshing an entry changed the count to %d", len(c.cache))
	}
	if back := c.order.Back().Value.(cacheEntry); back.aps != refreshed {
		t.Fatalf("most recently updated entry is %q, want %q", back.aps, refreshed)
	}

	c.addSync("one-more", certs)
	if _, ok := c.lookup(refreshed); !ok {
		t.Error("the refreshed entry was evicted")
	}
	if _, ok := c.lookup(fmt.Sprintf("ca-%d", extra+1)); ok {
		t.Error("the least recently updated entry was not evicted")
	}
	if len(c.cache) != maxCacheEntries || c.order.Len() != maxCacheEntries {
		t.Fatalf("cache holds %d entries in %d list elements, want %d", len(c.cache), c.order.Len(), maxCacheEntries)
	}
}
