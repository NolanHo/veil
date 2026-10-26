package supervisor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/rpc"
)

// TestConcurrentConfigWritesStayConsistent is acceptance (1) for the write path:
// the three writers the UI drives at the same time — Import, set_mode and
// SetConfig — must not land on config.json together.
//
// Before the writers shared one entry point, set_mode and SetConfig edited the
// live configuration and saved on the side while Import held cfgMu, so two
// config.Save calls wrote and renamed the same "config.json.tmp": one of them
// failed with "rename .../config.json.tmp .../config.json: no such file or
// directory", and the loser's change could stay in memory without reaching the
// file. Run with -race for the second half of the report.
func TestConcurrentConfigWritesStayConsistent(t *testing.T) {
	sup := newRuleSupervisor(t)
	const rounds = 50

	errs := make(chan error, 3*rounds)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"}); err != nil {
				errs <- fmt.Errorf("import: %w", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		modes := []string{config.ModeRule, config.ModeGlobal, config.ModeDirect}
		for i := 0; i < rounds; i++ {
			raw := []byte(fmt.Sprintf(`{"mode":%q}`, modes[i%len(modes)]))
			if _, err := sup.Call(context.Background(), rpc.MethodSetMode, raw); err != nil {
				errs <- fmt.Errorf("set_mode: %w", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			cfg := sup.Config()
			cfg = writeRules(cfg, config.Rule{
				Type:   "domain-suffix",
				Value:  fmt.Sprintf("ui-%d.test", i),
				Action: "direct",
			})
			if _, err := sup.SetConfig(cfg); err != nil {
				errs <- fmt.Errorf("set_config: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}

	// Nothing may be left behind by a save that lost its temporary file.
	if _, err := os.Stat(sup.cfgPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("%s.tmp still exists after the writers finished (stat err = %v)", sup.cfgPath, err)
	}
	// What was written is what is in memory: a reopen must see the same
	// configuration the supervisor currently reports.
	reopened, err := New(sup.cfgPath, sup.log)
	if err != nil {
		t.Fatalf("reopen supervisor: %v", err)
	}
	if got, want := reopened.Config(), sup.Config(); !reflect.DeepEqual(got, want) {
		t.Fatalf("configuration on disk and in memory disagree:\ndisk   = %+v\nmemory = %+v", got, want)
	}
}

// gatedSubServer is a subscription provider whose answer the test releases. It
// lets a refresh be parked inside its fetch, which is where the old code held
// the configuration lock.
type gatedSubServer struct {
	url       string
	requested chan struct{}
	release   chan struct{}
	once      sync.Once
}

func newGatedSubServer(t *testing.T, body string) *gatedSubServer {
	t.Helper()
	g := &gatedSubServer{
		requested: make(chan struct{}, 8),
		release:   make(chan struct{}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case g.requested <- struct{}{}:
		default:
		}
		<-g.release
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	g.url = srv.URL
	return g
}

// open releases a parked fetch. Idempotent, so a failing test can still let the
// server shut down.
func (g *gatedSubServer) open() { g.once.Do(func() { close(g.release) }) }

// subscribe installs the subscription without going through the RPC that would
// fetch it immediately.
func subscribe(t *testing.T, sup *Supervisor, name, url string) {
	t.Helper()
	cfg := sup.Config()
	cfg.Subscriptions = []config.Subscription{{Name: name, URL: url, Interval: 86400}}
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig(subscription): %v", err)
	}
}

// TestSubscriptionRefreshKeepsTheConfigLockFree is acceptance for the fetch half
// of the refresh: the provider is held inside its answer while another writer
// runs, and that writer must finish without waiting for it. The old code fetched
// with cfgMu held, so every other configuration write queued behind a provider
// that takes up to 25 seconds.
func TestSubscriptionRefreshKeepsTheConfigLockFree(t *testing.T) {
	srv := newGatedSubServer(t, subDoc("subnode", "rules:\n  - DOMAIN,a1.test,DIRECT\n"))
	defer srv.open()

	sup := newRuleSupervisor(t)
	subscribe(t, sup, "A", srv.url)

	refreshed := make(chan error, 1)
	go func() {
		_, err := sup.updateSubscription(context.Background(), "A")
		refreshed <- err
	}()
	<-srv.requested

	written := make(chan error, 1)
	go func() {
		_, err := sup.Import(rpc.ImportParams{Text: routingYAML(), Source: "clash"})
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("Import while a subscription fetch was in flight: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Import was blocked by a subscription fetch that had not returned")
	}

	srv.open()
	if err := <-refreshed; err != nil {
		t.Fatalf("refresh: %v", err)
	}
}

// TestRefreshDropsBodyOfADeletedSubscription is the other half: because the
// fetch runs outside the lock, the subscription can be deleted while it is in
// flight (the delete must not wait for the provider, which the timeout below
// checks). The body then speaks for something that no longer exists, so the
// re-check inside the transaction has to drop it instead of resurrecting a
// subscription the user just removed.
func TestRefreshDropsBodyOfADeletedSubscription(t *testing.T) {
	srv := newGatedSubServer(t, subDoc("subnode", "rules:\n  - DOMAIN,a1.test,DIRECT\n"))
	defer srv.open()

	sup := newRuleSupervisor(t)
	subscribe(t, sup, "A", srv.url)

	refreshed := make(chan error, 1)
	go func() {
		_, err := sup.updateSubscription(context.Background(), "A")
		refreshed <- err
	}()
	<-srv.requested

	deleted := make(chan error, 1)
	go func() { deleted <- sup.deleteSubscription("A") }()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("delete while the fetch was in flight: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delete was blocked by a subscription fetch that had not returned")
	}

	srv.open()
	if err := <-refreshed; err == nil {
		t.Fatal("refreshing a deleted subscription succeeded; the fetched body was applied")
	}
	cfg := sup.Config()
	if len(cfg.Subscriptions) != 0 {
		t.Fatalf("subscriptions after the delete = %+v, want none", cfg.Subscriptions)
	}
	for _, n := range cfg.Nodes {
		if n.Source == "A" {
			t.Fatalf("node %q came back from the abandoned fetch", n.Tag)
		}
	}
}

// TestRefreshDropsBodyOfARepointedSubscription: the same re-check catches a
// subscription whose address the user changed while the old one was being
// fetched. The stale body must not be installed under the new name.
func TestRefreshDropsBodyOfARepointedSubscription(t *testing.T) {
	srv := newGatedSubServer(t, subDoc("subnode", "rules:\n  - DOMAIN,a1.test,DIRECT\n"))
	defer srv.open()

	sup := newRuleSupervisor(t)
	subscribe(t, sup, "A", srv.url)

	refreshed := make(chan error, 1)
	go func() {
		_, err := sup.updateSubscription(context.Background(), "A")
		refreshed <- err
	}()
	<-srv.requested

	cfg := sup.Config()
	cfg.Subscriptions[0].URL = "http://127.0.0.1:1/moved"
	if _, err := sup.SetConfig(cfg); err != nil {
		t.Fatalf("repointing the subscription: %v", err)
	}

	srv.open()
	if err := <-refreshed; err == nil {
		t.Fatal("refreshing a repointed subscription succeeded; the old body was applied")
	}
	if got := sup.Config().Subscriptions[0].URL; got != "http://127.0.0.1:1/moved" {
		t.Fatalf("subscription url = %q, want the new address", got)
	}
	if nodes := sup.Config().Nodes; len(nodes) != 0 {
		t.Fatalf("the abandoned fetch installed nodes: %+v", nodes)
	}
}
