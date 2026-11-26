package warrant

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	deployment = "orbtr"
	homeRealm  = "orbtr.io"
	aud        = "node.orbtr.io"
	issuer     = "io-edge"
	ver        = "v1"
)

func mustCap(t *testing.T, s string) Capability {
	t.Helper()
	c, err := ParseCapability(s)
	if err != nil {
		t.Fatalf("ParseCapability(%q): %v", s, err)
	}
	return c
}

func homeTrust() RealmTrust {
	return RealmTrust{Realm: homeRealm, Issuer: issuer, Audience: aud, PolicyVersion: ver, ExpiresAtMS: 1 << 62}
}

func fixedClock(now int64) Clock { return func() int64 { return now } }

func routes(t *testing.T) []Route {
	t.Helper()
	rRead, err := PartitionBoundRoute("device.read", mustCap(t, "orbtr.io:device.read"))
	if err != nil {
		t.Fatal(err)
	}
	rAdmin, err := PartitionBoundRoute("device.admin", mustCap(t, "orbtr.io:device.admin"))
	if err != nil {
		t.Fatal(err)
	}
	rGlobal, err := GlobalRoute("tuf.get", mustCap(t, "orbtr.io:tuf.get"))
	if err != nil {
		t.Fatal(err)
	}
	return []Route{rRead, rAdmin, rGlobal}
}

func newAuthz(t *testing.T, v *Verifier, clock Clock, foreign ...RealmTrust) *Authorizer {
	t.Helper()
	a, err := NewAuthorizer(v, deployment, clock, routes(t), homeTrust(), foreign...)
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	return a
}

// baseAssertion is a valid partition-bound home-realm assertion with a valid (mandatory) nonce.
func baseAssertion() Assertion {
	return Assertion{
		Subject:      Subject{ID: "u1", Kind: "user"},
		Deployment:   deployment,
		HasPartition: true,
		Partition:    "acme",
		Capabilities: []string{"orbtr.io:device.read"},
		Issuer:       issuer,
		Audience:     aud,
		Version:      ver,
		Realm:        homeRealm,
		ExpiresAtMS:  10_000,
		Nonce:        "nonce-base-01",
	}
}

func withNonce(a Assertion, n string) Assertion { a.Nonce = n; return a }

func denied(err error) bool { return errors.Is(err, ErrDenied) }

func mustMint(t *testing.T, v *Verifier, a Assertion) VerifiedPrincipal {
	t.Helper()
	p, err := v.Mint(a)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return p
}

func TestReceiverPinned_ForeignVerifierDenied(t *testing.T) {
	real, _ := NewVerifier()
	forger, _ := NewVerifier()
	a := newAuthz(t, real, fixedClock(5000))
	forged := mustMint(t, forger, baseAssertion()) // perfect fields, foreign key
	if _, err := a.Authorize(context.Background(), forged, "device.read", "acme"); !denied(err) {
		t.Fatalf("principal minted by a foreign Verifier must be DENIED; got %v", err)
	}
}

func TestZeroValuePrincipalDenied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), VerifiedPrincipal{}, "device.read", "acme"); !denied(err) {
		t.Fatal("zero-value principal must be DENIED")
	}
}

func TestPartitionBound_Positive(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	id, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.read", "acme")
	if err != nil {
		t.Fatalf("valid partition-bound request should succeed; got %v", err)
	}
	if id.Partition.Realm() != homeRealm || id.Partition.Partition() != "acme" {
		t.Fatalf("wrong Partition: %+v", id.Partition)
	}
}

func TestWrongDeployment_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.Deployment = "someone-else"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("foreign deployment must be DENIED")
	}
}

func TestUnknownOperation_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.nonexistent", "acme"); !denied(err) {
		t.Fatal("unregistered operation must be DENIED")
	}
}

func TestTrust_IssuerAudienceVersionExpiry(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	// each mutation denies BEFORE replay (step 6), so the shared nonce is never consumed.
	for name, mut := range map[string]func(*Assertion){
		"bad-issuer":   func(as *Assertion) { as.Issuer = "attacker" },
		"bad-audience": func(as *Assertion) { as.Audience = "some.other.aud" },
		"bad-version":  func(as *Assertion) { as.Version = "v99" },
		"expired":      func(as *Assertion) { as.ExpiresAtMS = 4000 }, // clock 5000
		"no-expiry":    func(as *Assertion) { as.ExpiresAtMS = 0 },
	} {
		as := baseAssertion()
		mut(&as)
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
			t.Fatalf("%s must be DENIED", name)
		}
	}
}

// TestRealmBinding_ForeignRealmHomeCapDenied is the realm-binding case: a TRUSTED foreign
// realm carrying a HOME-realm capability must NOT authorize the home route.
func TestRealmBinding_ForeignRealmHomeCapDenied(t *testing.T) {
	v, _ := NewVerifier()
	foreign := RealmTrust{Realm: "orbtr.ai", Issuer: "ai-edge", Audience: aud, PolicyVersion: ver, ExpiresAtMS: 1 << 62}
	a := newAuthz(t, v, fixedClock(5000), foreign)
	as := baseAssertion()
	as.Realm = "orbtr.ai"                              // FOREIGN-realm principal
	as.Issuer = "ai-edge"                              // trusted
	as.Capabilities = []string{"orbtr.io:device.read"} // ...carrying a HOME capability
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("foreign-realm principal with a home capability must be DENIED (realm binding)")
	}
	// positive control: a home-realm principal on the home route succeeds.
	if _, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.read", "acme"); err != nil {
		t.Fatalf("home-realm positive control must succeed; got %v", err)
	}
	// discriminating mutation: a home principal whose capability is foreign-realm is denied.
	bad := baseAssertion()
	bad.Nonce = "n-badcap"
	bad.Capabilities = []string{"orbtr.ai:device.read"}
	if _, err := a.Authorize(context.Background(), mustMint(t, v, bad), "device.read", "acme"); !denied(err) {
		t.Fatal("a home principal holding a foreign-realm capability must be DENIED")
	}
}

func TestPartitionBound_PartitionMismatch_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.read", "evil"); !denied(err) {
		t.Fatal("sealed partition != body partition must be DENIED")
	}
}

// TestRepresentationConsistency_MintRejects: HasPartition must equal Partition-presence, enforced AT MINT
// — an inconsistent bundle can never be sealed.
func TestRepresentationConsistency_MintRejects(t *testing.T) {
	v, _ := NewVerifier()
	as := baseAssertion()
	as.HasPartition = false
	as.Partition = "acme"
	if _, err := v.Mint(as); err == nil {
		t.Fatal("Mint must reject HasPartition=false with partition material")
	}
	as2 := baseAssertion()
	as2.HasPartition = true
	as2.Partition = ""
	if _, err := v.Mint(as2); err == nil {
		t.Fatal("Mint must reject HasPartition=true with an empty partition")
	}
	as3 := baseAssertion()
	as3.Subject = Subject{}
	if _, err := v.Mint(as3); err == nil {
		t.Fatal("Mint must reject an empty subject")
	}
}

func TestGlobal_PositiveAndPartitionMaterialRejected(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	// positive global: no partition, holds the global cap.
	as := baseAssertion()
	as.HasPartition = false
	as.Partition = ""
	as.Capabilities = []string{"orbtr.io:tuf.get"}
	as.Nonce = "n-global-ok"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "tuf.get", ""); err != nil {
		t.Fatalf("valid global request should succeed; got %v", err)
	}
	// partition-bearing principal at a global route → denied (partition material).
	as2 := baseAssertion()
	as2.Capabilities = []string{"orbtr.io:tuf.get"}
	as2.Nonce = "n-global-owner"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as2), "tuf.get", ""); !denied(err) {
		t.Fatal("partition-bearing principal at a global route must be DENIED")
	}
	// global route with a non-empty body owner → denied.
	if _, err := a.Authorize(context.Background(), mustMint(t, v, withNonce(as, "n-global-body")), "tuf.get", "acme"); !denied(err) {
		t.Fatal("global route with a body owner must be DENIED")
	}
}

func TestCapabilityInjection_LowPrivCannotReachHighRoute(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.admin", "acme"); !denied(err) {
		t.Fatal("low-privilege sealed principal must NOT reach the high route")
	}
	as := baseAssertion()
	as.Capabilities = []string{"orbtr.io:device.admin"}
	as.Nonce = "n-admin-ok"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.admin", "acme"); err != nil {
		t.Fatalf("device.admin with the admin capability should succeed; got %v", err)
	}
}

func TestIoSubjectKinds_Accepted(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	for i, kind := range []SubjectKind{"device", "mesh_peer"} {
		as := baseAssertion()
		as.Subject = Subject{ID: "d1", Kind: kind}
		as.Nonce = fmt.Sprintf("n-kind-%d", i) // distinct nonce per positive (mandatory + exactly-once)
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); err != nil {
			t.Fatalf("subject kind %q must be accepted; got %v", kind, err)
		}
	}
}

func TestNonce_MandatoryAndBounded(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	for name, n := range map[string]string{
		"empty":    "",
		"short":    "short",                             // < minNonceLen(8)
		"oversize": string(make([]byte, maxNonceLen+1)), // > maxNonceLen
	} {
		as := withNonce(baseAssertion(), n)
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
			t.Fatalf("%s nonce must be DENIED (replay is not caller-optional)", name)
		}
	}
}

func TestReplay_SecondUseDeniedAndNoPoison(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	p := mustMint(t, v, withNonce(baseAssertion(), "n-replay-1"))
	if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err != nil {
		t.Fatalf("first use should succeed; got %v", err)
	}
	if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); !denied(err) {
		t.Fatal("identical second use must be DENIED (replay)")
	}
	// no-poison: a request that FAILS an earlier check must not consume its nonce.
	pp := mustMint(t, v, withNonce(baseAssertion(), "n-replay-2"))
	if _, err := a.Authorize(context.Background(), pp, "device.read", "wrong-owner"); !denied(err) {
		t.Fatal("setup: wrong-owner denies")
	}
	if _, err := a.Authorize(context.Background(), pp, "device.read", "acme"); err != nil {
		t.Fatalf("a failed earlier check must not poison the nonce; got %v", err)
	}
}

func TestReplay_ConcurrentExactlyOnce(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	p := mustMint(t, v, withNonce(baseAssertion(), "n-concurrent"))
	const goroutines = 32
	var success int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 1 {
		t.Fatalf("exactly one concurrent use must succeed; got %d", success)
	}
}

func TestNilSeam_FailClosed(t *testing.T) {
	var nilA *Authorizer
	if _, err := nilA.Authorize(context.Background(), VerifiedPrincipal{}, "device.read", "acme"); !denied(err) {
		t.Fatal("nil Authorizer must fail closed")
	}
	v, _ := NewVerifier()
	if _, err := NewAuthorizer(nil, deployment, nil, routes(t), homeTrust()); !denied(err) {
		t.Fatal("nil verifier must reject")
	}
	if _, err := NewAuthorizer(v, "", nil, routes(t), homeTrust()); !denied(err) {
		t.Fatal("empty deployment must reject")
	}
	if _, err := NewAuthorizer(v, deployment, nil, routes(t), RealmTrust{}); !denied(err) {
		t.Fatal("invalid home trust must reject")
	}
}

func TestParseCapability_Malformed(t *testing.T) {
	for _, s := range []string{
		"", "noColon", "orbtr.io:", "orbtr.io:device", ":device.read",
		"orbtr.io:device.read.extra", ".orbtr:device.read", "orbtr.:device.read",
		"orbtr..io:device.read", "orbtr.io:dev ice.read", "orbtr.io:device.*.x",
		"ORBTR.io:device.read",
	} {
		if _, err := ParseCapability(s); err == nil {
			t.Fatalf("malformed capability %q must fail to parse", s)
		}
	}
	if _, err := ParseCapability("orbtr.io:device.*"); err != nil {
		t.Fatalf("orbtr.io:device.* should parse; got %v", err)
	}
}

// TestReplayStore_CapacityFailClosed: at capacity the store denies rather than
// evicting an unexpired entry to admit reuse; an expired entry is evicted to free space.
func TestReplayStore_CapacityFailClosed(t *testing.T) {
	r := &replayStore{consumed: map[replayKey]int64{}, maxEntries: 2}
	k := func(n string) replayKey { return replayKey{issuer, aud, ver, homeRealm, n} }
	if !r.consumeFor(k("a"), "s1", 100, 10) || !r.consumeFor(k("b"), "s2", 100, 10) {
		t.Fatal("first two unexpired entries must admit")
	}
	if r.consumeFor(k("c"), "s3", 100, 10) {
		t.Fatal("at capacity with all entries unexpired, a new entry must FAIL CLOSED (no evict-to-admit)")
	}
	// advance the clock past expiry: the expired entries evict, freeing capacity.
	if !r.consumeFor(k("d"), "s1", 500, 200) {
		t.Fatal("once entries expire, a fresh nonce admits")
	}
}

// TestMonoClock_RollbackSafe: a rolled-back wall clock never yields a lower time,
// so a consumed/expired principal cannot resurrect.
func TestMonoClock_RollbackSafe(t *testing.T) {
	cur := int64(1000)
	m := &monoClock{clock: func() int64 { return cur }}
	if got := m.now(); got != 1000 {
		t.Fatalf("now=%d, want 1000", got)
	}
	cur = 500 // clock rolls BACK
	if got := m.now(); got != 1000 {
		t.Fatalf("a rolled-back clock must not decrease; now=%d, want 1000", got)
	}
	cur = 2000 // forward
	if got := m.now(); got != 2000 {
		t.Fatalf("a forward clock advances; now=%d, want 2000", got)
	}
}

// TestLongHorizonTTL_Denied: a principal whose expiry exceeds the TTL cap is denied,
// bounding how long a consumed nonce must be retained.
func TestLongHorizonTTL_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.ExpiresAtMS = 5000 + maxPrincipalTTLms + 1
	as.Nonce = "n-longhorizon"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("a principal whose TTL exceeds the cap must be DENIED")
	}
}

// TestAuthorizerFmtRedactsKey: formatting the handler-facing Authorizer (which holds
// the Verifier) redacts the key — no minting material leaks through ordinary logging.
func TestAuthorizerFmtRedactsKey(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	dump := fmt.Sprintf("%#v|%+v|%v", a, a, a)
	if !strings.Contains(dump, "redacted") {
		t.Fatalf("Authorizer formatting must redact the Verifier key; got: %s", dump)
	}
}

// TestC1_SingleClockReadPerDecision (C1): Authorize reads its clock EXACTLY ONCE per decision. The
// prior two-sample gap (trustAccepts read the clock, then consume read it again) let a principal pass
// admission at one instant and be consumed after expiry at a later one; a fixed clock could never
// expose it because it never advances between reads. A counting clock proves the single instant.
func TestC1_SingleClockReadPerDecision(t *testing.T) {
	v, _ := NewVerifier()
	var reads int64
	clock := func() int64 { atomic.AddInt64(&reads, 1); return 5000 }
	a := newAuthz(t, v, clock)
	p := mustMint(t, v, withNonce(baseAssertion(), "n-c1-oneread"))
	if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err != nil {
		t.Fatalf("valid request should succeed; got %v", err)
	}
	if n := atomic.LoadInt64(&reads); n != 1 {
		t.Fatalf("Authorize must read the clock exactly ONCE per decision; got %d", n)
	}
}

// TestC1_ExactExpiryDeniedNoExpiredReplayInsert (C1): a principal whose single decision instant has
// reached expiry is DENIED (now >= ExpiresAtMS), and — the other half of the bug — it inserts NO
// replay entry, so an already-expired identity never lands in the store.
func TestC1_ExactExpiryDeniedNoExpiredReplayInsert(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(10_000)) // clock == ExpiresAtMS(10_000)
	as := withNonce(baseAssertion(), "n-c1-exactexp")
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("a principal at exact expiry must be DENIED")
	}
	key := replayKey{issuer, aud, ver, homeRealm, "n-c1-exactexp"}
	a.replay.mu.Lock()
	_, present := a.replay.consumed[key]
	heapLen := len(a.replay.heap)
	a.replay.mu.Unlock()
	if present || heapLen != 0 {
		t.Fatalf("an expired/denied principal must insert no replay entry; present=%v heapLen=%d", present, heapLen)
	}
	// boundary control: one millisecond before expiry admits.
	a2 := newAuthz(t, v, fixedClock(9_999))
	if _, err := a2.Authorize(context.Background(), mustMint(t, v, withNonce(baseAssertion(), "n-c1-inwindow")), "device.read", "acme"); err != nil {
		t.Fatalf("a principal one ms before expiry must be admitted; got %v", err)
	}
}

// TestC2_EvictsOnlyExpiredInHeapOrder (C2): consume reclaims ONLY entries expired at nowMS, in heap
// (expiry) order, and never an unexpired one — no full-map scan.
func TestC2_EvictsOnlyExpiredInHeapOrder(t *testing.T) {
	r := newReplayStore()
	k := func(n string) replayKey { return replayKey{issuer, aud, ver, homeRealm, n} }
	if !r.consume(k("e30"), 30, 5) || !r.consume(k("e10"), 10, 5) || !r.consume(k("e20"), 20, 5) {
		t.Fatal("setup: three distinct fresh nonces must admit")
	}
	if !r.consume(k("new"), 100, 25) { // now=25 → e10,e20 expired; e30 live
		t.Fatal("a fresh nonce must admit")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.consumed[k("e10")]; ok {
		t.Fatal("expired e10 must be evicted")
	}
	if _, ok := r.consumed[k("e20")]; ok {
		t.Fatal("expired e20 must be evicted")
	}
	if _, ok := r.consumed[k("e30")]; !ok {
		t.Fatal("live e30 must NOT be evicted (never evict an unexpired entry)")
	}
	if _, ok := r.consumed[k("new")]; !ok {
		t.Fatal("the new nonce must be recorded")
	}
	if len(r.consumed) != 2 || len(r.heap) != 2 {
		t.Fatalf("store must hold exactly the two live entries; map=%d heap=%d", len(r.consumed), len(r.heap))
	}
}

// TestC2_LargeLiveSetDoesNotEvictUnexpired (C2): with a large live set and nothing expired, a fresh
// consume adds exactly one entry and evicts none — the heap root is in the future, so the eviction
// loop does zero pops and never traverses the live set (the CPU-exhaustion surface is closed).
func TestC2_LargeLiveSetDoesNotEvictUnexpired(t *testing.T) {
	r := newReplayStore()
	const n = 2000
	for i := 0; i < n; i++ {
		if !r.consume(replayKey{issuer, aud, ver, homeRealm, fmt.Sprintf("live-%d", i)}, 1_000_000, 1000) {
			t.Fatalf("live entry %d must admit", i)
		}
	}
	if !r.consume(replayKey{issuer, aud, ver, homeRealm, "fresh"}, 1_000_000, 1000) {
		t.Fatal("a fresh nonce must admit while all others are live")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.consumed) != n+1 || len(r.heap) != n+1 {
		t.Fatalf("no live entry may be evicted; map=%d heap=%d want %d", len(r.consumed), len(r.heap), n+1)
	}
}

// TestC1_DeterministicDenialsReadClockZeroTimes: every deterministic authority
// denial — malformed/unmet/cross-realm capability, wrong owner, global owner-material — is decided
// BEFORE the single time sample, so it reads the clock ZERO times; only a decision that has passed
// every deterministic check reaches the clock, and a valid one reads it EXACTLY once. A counting
// clock is the discriminator the pre-reorder code (which sampled before capability/owner) fails.
func TestC1_DeterministicDenialsReadClockZeroTimes(t *testing.T) {
	v, _ := NewVerifier()
	var reads int64
	clock := func() int64 { atomic.AddInt64(&reads, 1); return 5000 }
	a := newAuthz(t, v, clock)

	cases := []struct {
		name   string
		mutate func(*Assertion)
		op     OperationID
		body   string
	}{
		{"malformed-capability", func(as *Assertion) { as.Capabilities = []string{"not-a-capability"}; as.Nonce = "n-c1-malcap" }, "device.read", "acme"},
		{"unmet-capability", func(as *Assertion) { as.Nonce = "n-c1-unmet" }, "device.admin", "acme"}, // read cap on admin route
		{"cross-realm-capability", func(as *Assertion) { as.Capabilities = []string{"orbtr.ai:device.read"}; as.Nonce = "n-c1-xrealm" }, "device.read", "acme"},
		{"wrong-owner", func(as *Assertion) { as.Nonce = "n-c1-wrongowner" }, "device.read", "evil"},
		{"global-owner-material", func(as *Assertion) { as.Capabilities = []string{"orbtr.io:tuf.get"}; as.Nonce = "n-c1-globalowner" }, "tuf.get", ""},
	}
	for _, c := range cases {
		as := baseAssertion()
		c.mutate(&as)
		atomic.StoreInt64(&reads, 0)
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), c.op, c.body); !denied(err) {
			t.Fatalf("%s must be DENIED", c.name)
		}
		if n := atomic.LoadInt64(&reads); n != 0 {
			t.Fatalf("%s is a deterministic denial and must read the clock ZERO times; got %d", c.name, n)
		}
	}

	atomic.StoreInt64(&reads, 0)
	if _, err := a.Authorize(context.Background(), mustMint(t, v, withNonce(baseAssertion(), "n-c1-valid")), "device.read", "acme"); err != nil {
		t.Fatalf("valid decision should succeed; got %v", err)
	}
	if n := atomic.LoadInt64(&reads); n != 1 {
		t.Fatalf("a valid decision must read the clock EXACTLY once; got %d", n)
	}
}

// TestC2_EvictionInspectionsIndependentOfLiveSet: the operation-count witness. A
// consume with nothing expired inspects only the heap root — ONE inspection — regardless of live-set
// size. A regression to a full live-map range would make the count scale with N; length-only
// assertions could not tell the difference.
func TestC2_EvictionInspectionsIndependentOfLiveSet(t *testing.T) {
	measure := func(n int) int64 {
		r := newReplayStore()
		for i := 0; i < n; i++ {
			r.consume(replayKey{issuer, aud, ver, homeRealm, fmt.Sprintf("live-%d", i)}, 1_000_000, 1000)
		}
		before := r.evictInspections
		r.consume(replayKey{issuer, aud, ver, homeRealm, "probe"}, 1_000_000, 1000) // nothing expired
		return r.evictInspections - before
	}
	small, large := measure(1_000), measure(50_000)
	if small != 1 || large != 1 {
		t.Fatalf("eviction cost must be independent of live-set size (root-only when nothing expired); small=%d large=%d", small, large)
	}
	// control: with k entries expired at nowMS, inspections scale with k (the reclaimed set), not N.
	r := newReplayStore()
	for i := 0; i < 500; i++ { // expire at 100
		r.consume(replayKey{issuer, aud, ver, homeRealm, fmt.Sprintf("exp-%d", i)}, 100, 10)
	}
	for i := 0; i < 5_000; i++ { // live far out
		r.consume(replayKey{issuer, aud, ver, homeRealm, fmt.Sprintf("live-%d", i)}, 1_000_000, 10)
	}
	before := r.evictInspections
	r.consume(replayKey{issuer, aud, ver, homeRealm, "probe2"}, 1_000_000, 200) // now=200 → the 500 expire
	got := r.evictInspections - before
	if got != 501 { // 500 expired popped + 1 final root peek; independent of the 5000 live
		t.Fatalf("inspections must scale with the EXPIRED set (500)+1, not the live set; got %d", got)
	}
}

// TestC2a_HeapPopZerosVacatedSlot (assurance C2a): heapPop must zero the vacated backing-array slot,
// so a popped entry's replayKey strings are GC-reclaimable rather than retained until a later push
// overwrites the index. After a spike of expiring entries drains, every backing slot beyond the live
// length up to cap must be the zero replayEntry.
func TestC2a_HeapPopZerosVacatedSlot(t *testing.T) {
	r := newReplayStore()
	for i := 0; i < 100; i++ { // spike, all expire at 100
		r.consume(replayKey{issuer, aud, ver, homeRealm, fmt.Sprintf("spike-%d", i)}, 100, 10)
	}
	r.consume(replayKey{issuer, aud, ver, homeRealm, "drain"}, 1_000_000, 200) // now=200 pops all 100
	r.mu.Lock()
	defer r.mu.Unlock()
	full := r.heap[:cap(r.heap)]
	for i := len(r.heap); i < len(full); i++ {
		if full[i] != (replayEntry{}) {
			t.Fatalf("backing slot %d retains a popped entry %+v — heapPop must zero it for reclamation", i, full[i])
		}
	}
}

// TestC2a_SameKeyExpireReinsert (assurance C2a invariant): a live second use is denied (replay);
// after expiry the SAME key re-admits as a fresh assertion with its new expiry; map/heap stay 1:1.
func TestC2a_SameKeyExpireReinsert(t *testing.T) {
	r := newReplayStore()
	k := replayKey{issuer, aud, ver, homeRealm, "reused"}
	if !r.consume(k, 100, 10) {
		t.Fatal("first use must admit")
	}
	if r.consume(k, 100, 50) {
		t.Fatal("a live second use of the same key must be DENIED (replay)")
	}
	if !r.consume(k, 1_000, 200) { // now=200 > 100: prior expired → reclaimed → re-admits
		t.Fatal("after expiry the same key must re-admit with its new assertion")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.consumed[k] != 1_000 || len(r.consumed) != 1 || len(r.heap) != 1 {
		t.Fatalf("map/heap must be 1:1 with the reinserted expiry; map[k]=%d len(map)=%d len(heap)=%d", r.consumed[k], len(r.consumed), len(r.heap))
	}
}

// TestC2b_ObjectIdentityWhitelist is the durable C2b guard. C2b forbids any O(N) scan of the live
// replay map replayStore.consumed (the op-count witness measures only the heap loop, so a scan added
// ELSEWHERE would not move it). The guard closes the whole class at the SOURCE via go/types object
// identity: it discovers and type-checks the COMPLETE non-test production set of the root package,
// resolves the exact replayStore.consumed field object (a *types.Var — spelling/shadowing grants no
// authority), and rejects EVERY selector use of that object except two safe positions — the X of an
// index expression (r.consumed[k] read/write) and the first argument to the builtins len/delete
// (resolved as *types.Builtin, not by name). Because every path to the map's value passes through such
// a selector, this one rule closes direct range, alias/implicit assignment, helper/conversion
// arguments, method-receiver escape, interface boxing and maps.Keys — including a mutation whose range
// lives in a SECOND package file, which a single-file guard never parses. The underlying-range defense
// is retained (a range whose operand's underlying type equals the live map's). A same-process
// reflect/unsafe memory read is out of scope (a fundamental Go limit; consumers are first-party
// endpoint code).
//
// Non-vacuity is asserted so an aborted type-check cannot silently pass: production-set discovery
// includes warrant.go, the field object resolves, and the three whitelisted admissions (index, len,
// delete) are each observed on clean source. Six independent mutant controls each turn the guard RED,
// and the prior single-file range-only guard is shown GREEN on the cross-file bypass it could not see.
func TestC2b_ObjectIdentityWhitelist(t *testing.T) {
	// (A) CLEAN real package: discover + type-check the complete non-test production set.
	realFiles := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		realFiles[name] = string(b)
	}
	// discovery non-vacuity: the production set includes warrant.go.
	if _, ok := realFiles["warrant.go"]; !ok {
		t.Fatal("discovery non-vacuity: warrant.go not found in the root package production set")
	}
	fset, files, info, pkg := c2bTypeCheck(t, realFiles)
	field := c2bResolveField(pkg)
	if field == nil {
		t.Fatal("non-vacuity: the replayStore.consumed field object did not resolve — the guard is checking nothing")
	}
	viol, idx, lenA, delA := c2bAnalyze(fset, files, info, field)
	if len(viol) != 0 {
		t.Fatalf("clean source must be GREEN (0 violations); got: %v", viol)
	}
	// admission non-vacuity: index, len, and delete are each observed independently on clean source.
	if idx == 0 || lenA == 0 || delA == 0 {
		t.Fatalf("admission non-vacuity failed (each must be >=1): index=%d len=%d delete=%d", idx, lenA, delA)
	}

	// (B) SIX mutant controls: each independent bypass must turn the successor guard RED (>=1 violation).
	mutants := []struct {
		name  string
		files map[string]string
	}{
		{"direct-selector-range", map[string]string{
			"warrant.go": c2bBase("", `func (r *replayStore) consume() { for range r.consumed { _ = r } }`)}},
		{"free-helper-parameter", map[string]string{
			"warrant.go": c2bBase("", `func scanMap(m map[replayKey]int64) { for range m { } }
func (r *replayStore) consume() { scanMap(r.consumed) }`)}},
		{"plain-alias", map[string]string{
			"warrant.go": c2bBase("", `func (r *replayStore) consume() { m := r.consumed; for range m { } }`)}},
		{"named-wrapper-conversion", map[string]string{
			"warrant.go": c2bBase("", `type replayMap map[replayKey]int64
func (r *replayStore) consume() { for range replayMap(r.consumed) { } }`)}},
		{"maps-keys-iterator", map[string]string{
			"warrant.go": c2bBase(`"maps"`, `func (r *replayStore) consume() { for range maps.Keys(r.consumed) { } }`)}},
		{"implicit-assign-crossfile", map[string]string{
			"warrant.go": c2bBase("", `type replayIndex map[replayKey]int64
func (r *replayStore) consume() { var live replayIndex = r.consumed; live.scan() }`),
			"replayindex.go": "package warrant\nfunc (m replayIndex) scan() { for range m { } }\n"}},
		// Seventh, discriminating control: a same-shaped consumed field on a DECOY struct (with fully
		// admitted index/len/delete uses) must NOT let a forbidden bare use of the REAL replayStore.consumed
		// pass. A resolver that scanned Defs by name/shape could bind the decoy field and miss the real one.
		{"same-shaped-decoy-owner", map[string]string{
			"warrant.go": c2bBase("", `type replayStoreDecoy struct { consumed map[replayKey]int64 }
func (d *replayStoreDecoy) touch() { _ = d.consumed[replayKey("x")]; _ = len(d.consumed); delete(d.consumed, replayKey("x")) }
func (r *replayStore) exposeConsumedForReview() map[replayKey]int64 { return r.consumed }`)}},
	}
	for _, mu := range mutants {
		fs, fl, in, pk := c2bTypeCheck(t, mu.files)
		fld := c2bResolveField(pk)
		if fld == nil {
			t.Errorf("[%s] the consumed field object did not resolve in the fixture", mu.name)
			continue
		}
		mv, _, _, _ := c2bAnalyze(fs, fl, in, fld)
		if len(mv) == 0 {
			t.Errorf("[%s] mutant must be RED under the successor guard, but no violation was detected", mu.name)
		}
	}

	// (C) The sixth (cross-file) control, examined directly: prove the second production file
	// participates in the SAME type-check, that the OLD single-file range-only guard is GREEN on it (the
	// gap), and that the successor guard is RED.
	bypass := map[string]string{
		"warrant.go": c2bBase("", `type replayIndex map[replayKey]int64
func (r *replayStore) consume() { var live replayIndex = r.consumed; live.scan() }`),
		"replayindex.go": "package warrant\nfunc (m replayIndex) scan() { for range m { } }\n",
	}
	bfset, bfiles, binfo, bpkg := c2bTypeCheck(t, bypass)
	bfield := c2bResolveField(bpkg)
	if bfield == nil {
		t.Fatal("[bypass] the consumed field object did not resolve")
	}
	// second-file participation: the scan method declared in replayindex.go resolved in this type-check.
	secondFileSeen := false
	for id, obj := range binfo.Defs {
		if id != nil && id.Name == "scan" {
			if _, ok := obj.(*types.Func); ok {
				secondFileSeen = true
			}
		}
	}
	if !secondFileSeen {
		t.Fatal("[bypass] sixth-control non-vacuity: the second production file did not participate in the same type-check")
	}
	// old single-file range-only guard over ONLY warrant.go: GREEN, because the range is in the other file.
	var warrantFile *ast.File
	for _, f := range bfiles {
		if strings.HasSuffix(bfset.Position(f.Pos()).Filename, "warrant.go") {
			warrantFile = f
		}
	}
	if warrantFile == nil {
		t.Fatal("[bypass] could not locate the warrant.go fixture file")
	}
	if n := c2bRangeOnly(bfset, warrantFile, binfo, bfield.Type().Underlying()); n != 0 {
		t.Fatalf("[bypass] old single-file range-only guard must be GREEN on warrant.go (it cannot see a cross-file range); got %d range violations", n)
	}
	// successor guard over BOTH files: RED (it flags the alias site AND the cross-file range).
	if bv, _, _, _ := c2bAnalyze(bfset, bfiles, binfo, bfield); len(bv) == 0 {
		t.Fatal("[bypass] successor guard must be RED on the cross-file bypass")
	}
}

// c2bTypeCheck parses the named source files as package warrant and type-checks them together. The
// source importer resolves stdlib; any unresolvable in-module/generic import is collected and IGNORED
// (Error continues), because the in-package replayStore/replayKey/consumed types resolve regardless.
func c2bTypeCheck(t *testing.T, srcByName map[string]string) (*token.FileSet, []*ast.File, *types.Info, *types.Package) {
	t.Helper()
	fset := token.NewFileSet()
	names := make([]string, 0, len(srcByName))
	for n := range srcByName {
		names = append(names, n)
	}
	sort.Strings(names)
	var parsed []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcByName[name], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed = append(parsed, f)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(error) {}}
	pkg, _ := conf.Check("github.com/bbmumford/warrant", fset, parsed, info)
	return fset, parsed, info, pkg
}

// c2bResolveField returns the field object OWNED BY replayStore named consumed, or nil. It resolves the
// replayStore type from the package scope and selects that struct's own consumed field — it does NOT
// scan arbitrary Defs by name/shape, so a same-shaped consumed field on a DIFFERENT struct can never be
// mistaken for it (a nondeterministic-selection bypass). The shape (map[replayKey]int64) is validated
// on replayStore's own field; a shape mismatch fails closed (nil).
func c2bResolveField(pkg *types.Package) *types.Var {
	if pkg == nil {
		return nil
	}
	tn, ok := pkg.Scope().Lookup("replayStore").(*types.TypeName)
	if !ok || tn == nil {
		return nil
	}
	st, ok := tn.Type().Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Name() != "consumed" {
			continue
		}
		m, ok := f.Type().Underlying().(*types.Map)
		if !ok {
			return nil
		}
		named, ok := m.Key().(*types.Named)
		if !ok || named.Obj().Name() != "replayKey" {
			return nil
		}
		if b, ok := m.Elem().(*types.Basic); ok && b.Kind() == types.Int64 {
			return f
		}
		return nil
	}
	return nil
}

// c2bAnalyze reports every non-whitelisted use of the consumed field object across all files, plus any
// retained underlying-range violation, and counts the three whitelisted admission forms observed
// (index, len, delete) for non-vacuity. A selector use is admitted only as the X of an index expression
// or the first argument to the go/types-resolved builtins len/delete; everything else — assignment,
// conversion, non-builtin call argument, address-of, bare use — is a violation.
func c2bAnalyze(fset *token.FileSet, files []*ast.File, info *types.Info, field *types.Var) (viol []string, idx, lenA, delA int) {
	liveUnder := field.Type().Underlying()
	builtinName := func(call *ast.CallExpr) string {
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return ""
		}
		if b, ok := info.Uses[id].(*types.Builtin); ok {
			return b.Name()
		}
		return ""
	}
	for _, f := range files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			switch x := n.(type) {
			case *ast.RangeStmt:
				if tv, ok := info.Types[x.X]; ok && tv.Type != nil && types.Identical(tv.Type.Underlying(), liveUnder) {
					viol = append(viol, "range over the live-map underlying type at "+fset.Position(x.Pos()).String())
				}
			case *ast.SelectorExpr:
				if info.Uses[x.Sel] == field {
					switch p := parent.(type) {
					case *ast.IndexExpr:
						if p.X == x {
							idx++ // r.consumed[k] read/write — admitted
						} else {
							viol = append(viol, "consumed used as an index key at "+fset.Position(x.Pos()).String())
						}
					case *ast.CallExpr:
						if len(p.Args) > 0 && p.Args[0] == x && (builtinName(p) == "len" || builtinName(p) == "delete") {
							if builtinName(p) == "len" {
								lenA++
							} else {
								delA++
							}
						} else {
							viol = append(viol, "consumed passed to a non-whitelisted callee at "+fset.Position(x.Pos()).String())
						}
					default:
						viol = append(viol, "non-whitelisted use of replayStore.consumed at "+fset.Position(x.Pos()).String())
					}
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	return
}

// c2bRangeOnly is the prior single-file range-only guard, retained solely to demonstrate the gap the
// object-identity successor closes: it counts only ranges over the live-map underlying type in ONE file.
func c2bRangeOnly(fset *token.FileSet, f *ast.File, info *types.Info, liveUnder types.Type) int {
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		if rng, ok := node.(*ast.RangeStmt); ok {
			if tv, ok := info.Types[rng.X]; ok && tv.Type != nil && types.Identical(tv.Type.Underlying(), liveUnder) {
				n++
			}
		}
		return true
	})
	return n
}

// c2bBase builds a minimal package-warrant fixture: replayKey + replayStore.consumed + the given body,
// with an optional import (e.g. `"maps"`).
func c2bBase(imp, body string) string {
	head := "package warrant\n"
	if imp != "" {
		head += "import " + imp + "\n"
	}
	head += "type replayKey string\n"
	head += "type replayStore struct { consumed map[replayKey]int64 }\n"
	return head + body + "\n"
}
