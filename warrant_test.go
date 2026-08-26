package warrant

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/warrant/internal/mint"
)

const now = 1_000_000

// principalWith mints a verified principal with SEALED caps + claims (in-module test may
// import internal/mint; an external module cannot — see warrant-exttest).
func principalWith(caps []string, claims map[string]string) VerifiedPrincipal {
	return mint.Mint(Subject{ID: "u1", Kind: "user"}, "orbtr", claims, caps)
}

func liveTrust(realm string) RealmTrust {
	return RealmTrust{Realm: realm, Issuer: "iss", Audience: "aud", PolicyVersion: "v1", ExpiresAtMS: now + 1_000}
}

func authorizer(t *testing.T, entries ...RealmTrust) *Authorizer {
	t.Helper()
	a, err := NewAuthorizer("orbtr", "orbtr.ai", "aud", entries...)
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	return a
}

func cap(t *testing.T, s string) Capability {
	t.Helper()
	c, err := ParseCapability(s)
	if err != nil {
		t.Fatalf("ParseCapability(%q): %v", s, err)
	}
	return c
}

func ownerBound(t *testing.T, c string) Route {
	t.Helper()
	r, err := OwnerBoundRoute(cap(t, c))
	if err != nil {
		t.Fatalf("OwnerBoundRoute: %v", err)
	}
	return r
}

func global(t *testing.T, c string) Route {
	t.Helper()
	r, err := GlobalRoute(cap(t, c))
	if err != nil {
		t.Fatalf("GlobalRoute: %v", err)
	}
	return r
}

type routeOnly struct {
	res Resolution
	err error
}

func (p routeOnly) Resolve(context.Context, VerifiedPrincipal, Route) (Resolution, error) {
	return p.res, p.err
}

func run(a *Authorizer, pol CapabilityPolicy, p VerifiedPrincipal, route Route, bodyOwner, nonce string) (Identity, error) {
	return a.Authorize(context.Background(), pol, p, route, bodyOwner, now, nonce)
}

// ── #1 principal forgery: zero-value principal is unverified → DENY ──
func TestForgedPrincipal_Denied(t *testing.T) {
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	if _, err := run(authorizer(t), pol, VerifiedPrincipal{}, ownerBound(t, "orbtr.ai:x.read"), "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("forged unverified principal must DENY")
	}
}

// ── #1 CAPABILITY injection: caps come from the SEALED principal, not the policy. A
// low-privilege principal + a route requiring a higher cap DENIES even though the policy
// returns valid routing — the policy cannot grant the missing capability. ──
func TestCapabilityInjection_Closed(t *testing.T) {
	// sealed low-priv cap only; route requires a cap the principal does NOT hold.
	p := principalWith([]string{"orbtr.ai:low.read"}, map[string]string{"org": "acme"})
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}} // valid routing, no grants
	if _, err := run(authorizer(t), pol, p, ownerBound(t, "orbtr.ai:admin.write"), "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("a policy must NOT be able to authorize a capability absent from the sealed principal")
	}
	// positive: the same route WITH the sealed cap present succeeds.
	p2 := principalWith([]string{"orbtr.ai:admin.write"}, map[string]string{"org": "acme"})
	if _, err := run(authorizer(t), pol, p2, ownerBound(t, "orbtr.ai:admin.write"), "acme", ""); err != nil {
		t.Fatalf("sealed cap present must succeed; got %v", err)
	}
}

func TestNilPolicyOrInvalidRoute_Denied(t *testing.T) {
	p := principalWith([]string{"orbtr.ai:x.read"}, map[string]string{"org": "acme"})
	if _, err := run(authorizer(t), nil, p, ownerBound(t, "orbtr.ai:x.read"), "", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("nil policy must DENY")
	}
	if _, err := run(authorizer(t), routeOnly{}, p, Route{}, "", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid route must DENY")
	}
}

// ── #4 principal validity + platform-tenant admission binding ──
func TestPrincipalValidity_And_PlatformTenantBinding(t *testing.T) {
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	route := ownerBound(t, "orbtr.ai:x.read")
	caps := []string{"orbtr.ai:x.read"}
	for name, p := range map[string]VerifiedPrincipal{
		"empty id":          mint.Mint(Subject{ID: "", Kind: "user"}, "orbtr", map[string]string{"org": "acme"}, caps),
		"empty kind":        mint.Mint(Subject{ID: "u", Kind: ""}, "orbtr", map[string]string{"org": "acme"}, caps),
		"foreign plat tenant": mint.Mint(Subject{ID: "u", Kind: "user"}, "evil", map[string]string{"org": "acme"}, caps),
		"empty plat tenant":   mint.Mint(Subject{ID: "u", Kind: "user"}, "", map[string]string{"org": "acme"}, caps),
	} {
		if _, err := run(authorizer(t), pol, p, route, "acme", ""); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s must DENY", name)
		}
	}
	// io kinds accepted (no hard-coded allowlist).
	for _, k := range []SubjectKind{"device", "mesh_peer"} {
		p := mint.Mint(Subject{ID: "d", Kind: k}, "orbtr", map[string]string{"org": "acme"}, caps)
		if _, err := run(authorizer(t), pol, p, route, "acme", ""); err != nil {
			t.Fatalf("io kind %q must be accepted; got %v", k, err)
		}
	}
}

// ── #2 owner from sealed claim; absent → DENY; foreign body → DENY ──
func TestSealedOwner_And_BodyCompare(t *testing.T) {
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	route := ownerBound(t, "orbtr.ai:x.read")
	caps := []string{"orbtr.ai:x.read"}
	id, err := run(authorizer(t), pol, principalWith(caps, map[string]string{"org": "acme"}), route, "acme", "")
	if err != nil || id.OwnerScope.Owner() != "acme" {
		t.Fatalf("owner must come from sealed claim; got owner=%q err=%v", id.OwnerScope.Owner(), err)
	}
	if _, err := run(authorizer(t), pol, principalWith(caps, map[string]string{}), route, "", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("absent sealed owner claim must DENY")
	}
	if _, err := run(authorizer(t), pol, principalWith(caps, map[string]string{"org": "acme"}), route, "villain", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign bodyOwner must DENY")
	}
}

// ── #3 cross-PRODUCT realm binding ──
func TestCrossRealm_Denied(t *testing.T) {
	// held ai cap, io OwnerBound route + io realm resolution → DENY.
	a, _ := NewAuthorizer("orbtr", "orbtr.io", "aud")
	polIO := routeOnly{res: Resolution{Realm: "orbtr.io", OwnerKey: ClaimOrg}}
	pAI := mint.Mint(Subject{ID: "u", Kind: "user"}, "orbtr", map[string]string{"org": "acme"}, []string{"orbtr.ai:x.read"})
	if _, err := a.Authorize(context.Background(), polIO, pAI, ownerBound(t, "orbtr.io:x.read"), "acme", now, ""); !errors.Is(err, ErrDenied) {
		t.Fatal("orbtr.ai sealed cap must NOT authorize an orbtr.io route")
	}
	// realm-mismatch attributable to the binding (trust orbtr.io so it's not the trust gate).
	polMismatch := routeOnly{res: Resolution{Realm: "orbtr.io", OwnerKey: ClaimOrg}}
	pAI2 := principalWith([]string{"orbtr.ai:x.read"}, map[string]string{"org": "acme"})
	if _, err := run(authorizer(t, liveTrust("orbtr.io")), polMismatch, pAI2, ownerBound(t, "orbtr.ai:x.read"), "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("partition realm != capability realm must DENY")
	}
}

// ── #5 global realm binding + owner ambiguity ──
func TestGlobal(t *testing.T) {
	caps := []string{"orbtr.ai:promo.lookup"}
	polNoOwner := routeOnly{res: Resolution{Realm: "orbtr.ai"}}
	// clean global success → zero OwnerScope.
	id, err := run(authorizer(t), polNoOwner, principalWith(caps, nil), global(t, "orbtr.ai:promo.lookup"), "", "")
	if err != nil || !id.OwnerScope.IsZero() {
		t.Fatalf("clean global must succeed with zero OwnerScope; got %+v err=%v", id.OwnerScope, err)
	}
	// global + policy owner key → DENY.
	polKey := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	if _, err := run(authorizer(t), polKey, principalWith(caps, map[string]string{"org": "acme"}), global(t, "orbtr.ai:promo.lookup"), "", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("global route with a policy owner key must DENY")
	}
	// global + body owner → DENY.
	if _, err := run(authorizer(t), polNoOwner, principalWith(caps, nil), global(t, "orbtr.ai:promo.lookup"), "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("global route with a body owner must DENY")
	}
	// global realm mismatch → DENY (#5).
	polWrongRealm := routeOnly{res: Resolution{Realm: "orbtr.io"}}
	if _, err := run(authorizer(t), polWrongRealm, principalWith(caps, nil), global(t, "orbtr.ai:promo.lookup"), "", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("global route realm mismatch must DENY")
	}
}

func TestMissingCapability_And_PolicyError(t *testing.T) {
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	route := ownerBound(t, "orbtr.ai:x.read")
	// sealed caps empty → missing → DENY.
	if _, err := run(authorizer(t), pol, principalWith(nil, map[string]string{"org": "acme"}), route, "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("missing (empty sealed) capability must DENY")
	}
	secret := errors.New("org 42 not in registry")
	_, err := run(authorizer(t), routeOnly{err: secret}, principalWith([]string{"orbtr.ai:x.read"}, map[string]string{"org": "acme"}), route, "acme", "")
	if !errors.Is(err, ErrDenied) || errors.Is(err, secret) {
		t.Fatalf("policy error must be ErrDenied and non-disclosing; got %v", err)
	}
}

// ── #2 trust validity + #3 replay ──
func TestTrust_ValidityAndReplay(t *testing.T) {
	// NewAuthorizer rejects an invalid trust entry.
	if _, err := NewAuthorizer("orbtr", "orbtr.ai", "aud", RealmTrust{Realm: "calndr" /* missing issuer/audience/version/expiry */}); !errors.Is(err, ErrDenied) {
		t.Fatal("NewAuthorizer must reject an invalid trust entry")
	}
	// a sealed FOREIGN-realm cap needs a live trust entry.
	pol := routeOnly{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg}}
	route := ownerBound(t, "orbtr.ai:x.read")
	pForeign := principalWith([]string{"orbtr.ai:x.read", "calndr:y.read"}, map[string]string{"org": "acme"})
	// untrusted foreign realm → DENY.
	if _, err := run(authorizer(t), pol, pForeign, route, "acme", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("untrusted foreign-realm sealed cap must DENY")
	}
	// expired / revoked / wrong-audience → DENY.
	for name, e := range map[string]RealmTrust{
		"expired":  {Realm: "calndr", Issuer: "i", Audience: "aud", PolicyVersion: "v1", ExpiresAtMS: now - 1},
		"revoked":  {Realm: "calndr", Issuer: "i", Audience: "aud", PolicyVersion: "v1", ExpiresAtMS: now + 1_000, Revoked: true},
		"wrong-aud": {Realm: "calndr", Issuer: "i", Audience: "other", PolicyVersion: "v1", ExpiresAtMS: now + 1_000},
	} {
		a, err := NewAuthorizer("orbtr", "orbtr.ai", "aud", e)
		if err != nil {
			t.Fatalf("%s ctor: %v", name, err)
		}
		if _, err := a.Authorize(context.Background(), pol, pForeign, route, "acme", now, ""); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s foreign trust must DENY", name)
		}
	}
	// REPLAY: same nonce twice → first succeeds, second denies.
	a := authorizer(t, liveTrust("calndr"))
	if _, err := a.Authorize(context.Background(), pol, pForeign, route, "acme", now, "nonce-1"); err != nil {
		t.Fatalf("first use of nonce must succeed; got %v", err)
	}
	if _, err := a.Authorize(context.Background(), pol, pForeign, route, "acme", now, "nonce-1"); !errors.Is(err, ErrDenied) {
		t.Fatal("replayed nonce must DENY on second use")
	}
}

func TestParseCapability_Malformed(t *testing.T) {
	for _, s := range []string{"", "noresource", "realm:noaction", "orbtr.ai:x.read.extra", "orbtr.ai:x.RE", "UP:x.y", ":x.y", ".:x.y", "orbtr..ai:x.y", ".orbtr.ai:x.y", "orbtr.ai.:x.y", "orbtr.ai:.y", "orbtr.ai:x."} {
		if _, err := ParseCapability(s); !errors.Is(err, ErrDenied) {
			t.Fatalf("malformed %q must be denied", s)
		}
	}
}

func TestCapabilitySet_SameRealm_Wildcard_Subsumes(t *testing.T) {
	set := NewCapabilitySet(cap(t, "orbtr.ai:x.*"))
	if !set.Allows(cap(t, "orbtr.ai:x.read")) || set.Allows(cap(t, "orbtr.io:x.read")) || NewCapabilitySet().Allows(cap(t, "orbtr.ai:x.read")) {
		t.Fatal("same-realm wildcard subsumes; cross-realm never; empty denies")
	}
	if !set.Subsumes(NewCapabilitySet(cap(t, "orbtr.ai:x.read"))) || set.Subsumes(NewCapabilitySet(cap(t, "orbtr.ai:y.write"))) {
		t.Fatal("subsumes clamp")
	}
}
