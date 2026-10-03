package ncentralclient_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatmate/ncentralclient"
)

// TestConcurrentCallersRenewOnce has two callers find the token due at the
// same moment. The server answers the first renewal it receives, and fails any
// renewal after it, slowly, so that a second renewal would finish last. The
// client must renew once and let the other caller use the new token; renewing
// twice lets the failure, finishing last, clear the token that the success had
// just stored, and every call after that goes out with no token.
func TestConcurrentCallersRenewOnce(t *testing.T) {
	var authenticates atomic.Int32
	var lock sync.Mutex
	valid := map[string]bool{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/authenticate", func(w http.ResponseWriter, r *http.Request) {
		n := authenticates.Add(1)
		expiry := 1 // the first token is due almost at once
		switch {
		case n == 2:
			time.Sleep(100 * time.Millisecond)
			expiry = 3600
		case n > 2:
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token := "token-" + string(rune('a'+n))
		lock.Lock()
		valid[token] = true
		lock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": map[string]any{"access": map[string]any{"token": token, "type": "Bearer", "expirySeconds": expiry}}})
	})
	mux.HandleFunc("GET /api/service-orgs", func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		ok := valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		lock.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"totalPages":1,"pageNumber":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := ncentralclient.New(server.URL)
	require.NoError(t, client.Authenticate(t.Context(), "key"))
	time.Sleep(1100 * time.Millisecond) // the 1s token is now due

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = client.GetServiceOrgs(t.Context())
		}()
	}
	wg.Wait()
	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])

	for range 3 {
		_, err := client.GetServiceOrgs(t.Context())
		assert.NoError(t, err, "the token the renewal stored must still be in use")
	}
	assert.EqualValues(t, 2, authenticates.Load(), "the first authentication, then one renewal for both callers")
}
