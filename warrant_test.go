package warrant

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	tenant    = "orbtr"
	homeRealm = "orbtr.io"
	aud       = "node.orbtr.io"
	issuer    = "io-edge"
	ver       = "v1"
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

// routes returns a fixed table: a low owner-bound op, a high owner-bound op, a global op.
func routes(t *testing.T) []Route {
	t.Helper()
	rRead, err := OwnerBoundRoute("device.read", mustCap(t, "orbtr.io:device.read"))
	if err != nil {
		t.Fatal(err)
	}
	rAdmin, err := OwnerBoundRoute("device.admin", mustCap(t, "orbtr.io:device.admin"))
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
	a, err := NewAuthorizer(v, tenant, clock, routes(t), homeTrust(), foreign...)
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	return a
}

// baseAssertion is a valid owner-bound home-realm assertion (nonce empty by default).
func baseAssertion() Assertion {
	return Assertion{
		Subject:        Subject{ID: "u1", Kind: "user"},
		PlatformTenant: tenant,
		HasOwner:       true,
		Owner:          "acme",
		Capabilities:   []string{"orbtr.io:device.read"},
		Issuer:         issuer,
		Audience:       aud,
		Version:        ver,
		Realm:          homeRealm,
		ExpiresAtMS:    10_000,
	}
}

func denied(err error) bool { return errors.Is(err, ErrDenied) }

// ── The receiver-pinned core: a principal minted by ANOTHER Verifier is denied ──────────
// In-module analog of the nested-module hostile (the true nested-path proof is in
// warrant-exttest). A "forger" builds its own Verifier and mints a fully-valid-looking
// principal; the real Authorizer denies it purely on the seal mismatch.
func TestReceiverPinned_ForeignVerifierDenied(t *testing.T) {
	real, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	forger, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	a := newAuthz(t, real, fixedClock(5000))
	// The forged principal is perfect in every field — only the secret differs.
	forged := forger.Mint(baseAssertion())
	if _, err := a.Authorize(context.Background(), forged, "device.read", "acme"); !denied(err) {
		t.Fatalf("principal minted by a foreign Verifier must be DENIED; got %v", err)
	}
	// The forger's OWN authorizer accepting its own principal is irrelevant to the guarantee.
	self := newAuthz(t, forger, fixedClock(5000))
	if _, err := self.Authorize(context.Background(), forged, "device.read", "acme"); err != nil {
		t.Fatalf("sanity: forger's own authorizer should accept its own principal; got %v", err)
	}
}

func TestZeroValuePrincipalDenied(t *testing.T) {
	real, _ := NewVerifier()
	a := newAuthz(t, real, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), VerifiedPrincipal{}, "device.read", "acme"); !denied(err) {
		t.Fatal("zero-value (unsealed) principal must be DENIED")
	}
}

func TestOwnerBound_Positive(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	p := v.Mint(baseAssertion())
	id, err := a.Authorize(context.Background(), p, "device.read", "acme")
	if err != nil {
		t.Fatalf("valid owner-bound request should succeed; got %v", err)
	}
	if id.OwnerScope.Realm() != homeRealm || id.OwnerScope.Owner() != "acme" {
		t.Fatalf("wrong OwnerScope: %+v", id.OwnerScope)
	}
}

func TestWrongPlatformTenant_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.PlatformTenant = "someone-else"
	if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", "acme"); !denied(err) {
		t.Fatal("foreign platform tenant must be DENIED")
	}
}

func TestUnknownOperation_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	if _, err := a.Authorize(context.Background(), v.Mint(baseAssertion()), "device.nonexistent", "acme"); !denied(err) {
		t.Fatal("an operation with no registered route must be DENIED")
	}
}

func TestTrust_IssuerAudienceVersionExpiry(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	for name, mut := range map[string]func(*Assertion){
		"bad-issuer":   func(as *Assertion) { as.Issuer = "attacker" },
		"bad-audience": func(as *Assertion) { as.Audience = "some.other.aud" },
		"bad-version":  func(as *Assertion) { as.Version = "v99" },
		"expired":      func(as *Assertion) { as.ExpiresAtMS = 4000 }, // clock is 5000
		"no-expiry":    func(as *Assertion) { as.ExpiresAtMS = 0 },
		"untrusted-realm": func(as *Assertion) {
			as.Realm = "orbtr.ai"
			as.Capabilities = []string{"orbtr.ai:device.read"}
		},
	} {
		as := baseAssertion()
		mut(&as)
		if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", "acme"); !denied(err) {
			t.Fatalf("%s must be DENIED", name)
		}
	}
}

func TestTrustEntry_Expired_Denied(t *testing.T) {
	v, _ := NewVerifier()
	// A foreign realm whose entry is expired relative to the clock.
	expired := RealmTrust{Realm: "orbtr.ai", Issuer: "ai-edge", Audience: aud, PolicyVersion: ver, ExpiresAtMS: 4000}
	a := newAuthz(t, v, fixedClock(5000), expired)
	as := baseAssertion()
	as.Realm = "orbtr.ai"
	as.Issuer = "ai-edge"
	as.Capabilities = []string{"orbtr.io:device.read"} // even with a home-realm cap
	if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", "acme"); !denied(err) {
		t.Fatal("an expired foreign trust entry must DENY")
	}
}

func TestCrossRealm_Denied(t *testing.T) {
	v, _ := NewVerifier()
	// orbtr.ai IS a live trusted foreign realm, but the principal only holds ai capabilities.
	foreign := RealmTrust{Realm: "orbtr.ai", Issuer: "ai-edge", Audience: aud, PolicyVersion: ver, ExpiresAtMS: 1 << 62}
	a := newAuthz(t, v, fixedClock(5000), foreign)
	as := baseAssertion()
	as.Realm = "orbtr.ai"
	as.Issuer = "ai-edge"
	as.Capabilities = []string{"orbtr.ai:device.read"} // ai cap cannot satisfy an io route
	if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", "acme"); !denied(err) {
		t.Fatal("an orbtr.ai capability must NOT satisfy an orbtr.io route (cross-realm)")
	}
}

func TestOwnerBound_OwnerMismatch_Denied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	// sealed owner acme, but the op body names a different owner.
	if _, err := a.Authorize(context.Background(), v.Mint(baseAssertion()), "device.read", "evil"); !denied(err) {
		t.Fatal("sealed owner != body owner must be DENIED")
	}
	// owner-bound route but the principal carries no owner.
	as := baseAssertion()
	as.HasOwner = false
	as.Owner = ""
	if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", ""); !denied(err) {
		t.Fatal("owner-bound route with an owner-less principal must be DENIED")
	}
}

func TestGlobal_PositiveAndOwnerRejected(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	// positive global: no owner, holds the global cap.
	as := baseAssertion()
	as.HasOwner = false
	as.Owner = ""
	as.Capabilities = []string{"orbtr.io:tuf.get"}
	if _, err := a.Authorize(context.Background(), v.Mint(as), "tuf.get", ""); err != nil {
		t.Fatalf("valid global request should succeed; got %v", err)
	}
	// an owner-bearing principal at a global route must be denied.
	as2 := baseAssertion()
	as2.Capabilities = []string{"orbtr.io:tuf.get"}
	if _, err := a.Authorize(context.Background(), v.Mint(as2), "tuf.get", ""); !denied(err) {
		t.Fatal("owner-bearing principal at a global route must be DENIED")
	}
	// a global route with a non-empty body owner must be denied.
	if _, err := a.Authorize(context.Background(), v.Mint(as), "tuf.get", "acme"); !denied(err) {
		t.Fatal("global route with a body owner must be DENIED")
	}
}

func TestCapabilityInjection_LowPrivCannotReachHighRoute(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	// sealed low-privilege principal (device.read) invoking the high op (device.admin).
	if _, err := a.Authorize(context.Background(), v.Mint(baseAssertion()), "device.admin", "acme"); !denied(err) {
		t.Fatal("a low-privilege sealed principal must NOT reach the high route (no injection)")
	}
	// positive: the same op with the correct sealed capability succeeds.
	as := baseAssertion()
	as.Capabilities = []string{"orbtr.io:device.admin"}
	if _, err := a.Authorize(context.Background(), v.Mint(as), "device.admin", "acme"); err != nil {
		t.Fatalf("device.admin with the admin capability should succeed; got %v", err)
	}
}

func TestIoSubjectKinds_Accepted(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	for _, kind := range []SubjectKind{"device", "mesh_peer"} {
		as := baseAssertion()
		as.Subject = Subject{ID: "d1", Kind: kind}
		if _, err := a.Authorize(context.Background(), v.Mint(as), "device.read", "acme"); err != nil {
			t.Fatalf("subject kind %q must be accepted (no allowlist); got %v", kind, err)
		}
	}
}

func TestReplay_SecondUseDeniedAndNoPoison(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.Nonce = "n1"
	p := v.Mint(as)
	if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err != nil {
		t.Fatalf("first use of a nonce should succeed; got %v", err)
	}
	if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); !denied(err) {
		t.Fatal("identical second use of a nonce must be DENIED (replay)")
	}
	// No-poison: a request that FAILS an earlier check must NOT consume its nonce.
	poison := baseAssertion()
	poison.Nonce = "n2"
	pp := v.Mint(poison)
	if _, err := a.Authorize(context.Background(), pp, "device.read", "wrong-owner"); !denied(err) {
		t.Fatal("setup: wrong-owner call should be denied")
	}
	// n2 must still be consumable by a legitimate use.
	if _, err := a.Authorize(context.Background(), pp, "device.read", "acme"); err != nil {
		t.Fatalf("a failed earlier check must not poison the nonce; got %v", err)
	}
}

func TestReplay_ConcurrentExactlyOnce(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.Nonce = "n-concurrent"
	p := v.Mint(as)
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
		t.Fatalf("exactly one concurrent use of a nonce must succeed; got %d", success)
	}
}

func TestNilSeam_FailClosed(t *testing.T) {
	var nilA *Authorizer
	if _, err := nilA.Authorize(context.Background(), VerifiedPrincipal{}, "device.read", "acme"); !denied(err) {
		t.Fatal("nil Authorizer must fail closed")
	}
	v, _ := NewVerifier()
	if _, err := NewAuthorizer(nil, tenant, nil, routes(t), homeTrust()); !denied(err) {
		t.Fatal("nil verifier must reject")
	}
	if _, err := NewAuthorizer(v, "", nil, routes(t), homeTrust()); !denied(err) {
		t.Fatal("empty tenant must reject")
	}
	if _, err := NewAuthorizer(v, tenant, nil, routes(t), RealmTrust{}); !denied(err) {
		t.Fatal("invalid home trust must reject")
	}
	badForeign := RealmTrust{Realm: "orbtr.ai", Issuer: "ai", Audience: "other", PolicyVersion: ver, ExpiresAtMS: 1 << 62}
	if _, err := NewAuthorizer(v, tenant, nil, routes(t), homeTrust(), badForeign); !denied(err) {
		t.Fatal("foreign entry with a mismatched audience must reject")
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
