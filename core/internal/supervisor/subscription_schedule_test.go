package supervisor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"veil/internal/config"
)

// A subscription with an interval refreshes itself when the tunnel starts and the
// interval has elapsed, which is what a Clash client does on launch. It is a
// single pass per start, not a timer: a timer would wake an idle device.
func TestDueSubscriptionRefreshesOnStart(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:1?type=tcp&security=none#scheduled-node")
	}))
	defer srv.Close()

	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Subscriptions = []config.Subscription{{
		Name: "sched", URL: srv.URL, Interval: 1, Updated: time.Now().Add(-time.Hour).Unix(),
	}}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	sup.refreshDueSubscriptions(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("the due subscription was never fetched")
	}
	// The refresh is asynchronous; wait for the stamp to move.
	for time.Now().Before(deadline) {
		if sup.Config().Subscriptions[0].Updated > cfg.Subscriptions[0].Updated {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := sup.Config().Subscriptions[0].Updated; got <= cfg.Subscriptions[0].Updated {
		t.Fatalf("Updated = %d, want it refreshed past %d", got, cfg.Subscriptions[0].Updated)
	}
}

// A subscription that is not due yet must not be fetched.
func TestFreshSubscriptionIsNotRefreshed(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "vless://00000000-0000-0000-0000-000000000002@127.0.0.1:1?type=tcp&security=none#fresh-node")
	}))
	defer srv.Close()

	sup := newRuleSupervisor(t)
	cfg := sup.Config()
	cfg.Subscriptions = []config.Subscription{{
		Name: "fresh", URL: srv.URL, Interval: 86400, Updated: time.Now().Unix(),
	}}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	sup.refreshDueSubscriptions(context.Background())
	time.Sleep(200 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("fetched %d time(s), want none for a subscription that is not due", n)
	}
}
