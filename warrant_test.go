package warrant

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/warrant/internal/mint"
)

const now = 1_000_000

// verified mints a real principal (in-module test may import internal/mint).
func verified(claims map[string]string) VerifiedPrincipal {
	return mint.Mint(Subject{ID: "u1", Kind: "user"}, "orbtr", claims)
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

type stub struct {
	res Resolution
	err error
}

func (s stub) Resolve(context.Context, VerifiedPrincipal, Route) (Resolution, error) {
	return s.res, s.err
}

// homeTrust trusts only orbtr.ai (the receiver's home) unless entries are added.
func homeTrust(entries ...RealmTrust) StaticTrust { return NewStaticTrust("orbtr.ai", entries...) }

func auth(policy CapabilityPolicy, trust TrustEvaluator, p VerifiedPrincipal, route Route, bodyOwner string) (Identity, error) {
	return Authorize(context.Background(), policy, trust, p, route, bodyOwner, now)
}

// ── #1 forgery: a zero-value (external-constructible) principal is unverified → DENY ──
func TestAuthorize_ForgedUnverifiedPrincipal_Denied(t *testing.T) {
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	if _, err := auth(pol, homeTrust(), VerifiedPrincipal{}, ownerBound(t, "orbtr.ai:x.read"), "acme"); !errors.Is(err, ErrDenied) {
		t.Fatalf("forged unverified principal must DENY; got %v", err)
	}
}

func TestAuthorize_NilPolicyOrTrustOrRoute_Denied(t *testing.T) {
	p := verified(map[string]string{"org": "acme"})
	if _, err := auth(nil, homeTrust(), p, ownerBound(t, "orbtr.ai:x.read"), ""); !errors.Is(err, ErrDenied) {
		t.Fatal("nil policy must DENY")
	}
	if _, err := Authorize(context.Background(), stub{}, nil, p, ownerBound(t, "orbtr.ai:x.read"), "", now); !errors.Is(err, ErrDenied) {
		t.Fatal("nil trust must DENY")
	}
	if _, err := auth(stub{}, homeTrust(), p, Route{}, ""); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid route must DENY")
	}
}

// ── #4 principal validity ──
func TestAuthorize_PrincipalValidity_Denied(t *testing.T) {
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	for name, p := range map[string]VerifiedPrincipal{
		"empty subject id":   mint.Mint(Subject{ID: "", Kind: "user"}, "orbtr", map[string]string{"org": "acme"}),
		"empty subject kind": mint.Mint(Subject{ID: "u1", Kind: ""}, "orbtr", map[string]string{"org": "acme"}),
		"empty platform ten": mint.Mint(Subject{ID: "u1", Kind: "user"}, "", map[string]string{"org": "acme"}),
	} {
		if _, err := auth(pol, homeTrust(), p, ownerBound(t, "orbtr.ai:x.read"), "acme"); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s must DENY; got %v", name, err)
		}
	}
	// io kinds must be accepted (no hard-coded allowlist): device/mesh_peer succeed.
	for _, k := range []SubjectKind{"device", "mesh_peer"} {
		p := mint.Mint(Subject{ID: "d1", Kind: k}, "orbtr", map[string]string{"org": "acme"})
		if _, err := auth(pol, homeTrust(), p, ownerBound(t, "orbtr.ai:x.read"), "acme"); err != nil {
			t.Fatalf("io kind %q must be accepted (scope-agnostic); got %v", k, err)
		}
	}
}

// ── #2 sealed owner from claim; absent claim → DENY (policy cannot inject a raw owner) ──
func TestAuthorize_OwnerFromSealedClaim(t *testing.T) {
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	// present sealed claim → bound to it.
	id, err := auth(pol, homeTrust(), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "acme")
	if err != nil || id.OwnerScope.Owner() != "acme" {
		t.Fatalf("owner must come from the sealed claim; got owner=%q err=%v", id.OwnerScope.Owner(), err)
	}
	// absent sealed claim → DENY (no raw fallback).
	if _, err := auth(pol, homeTrust(), verified(map[string]string{}), ownerBound(t, "orbtr.ai:x.read"), ""); !errors.Is(err, ErrDenied) {
		t.Fatal("absent sealed owner claim must DENY")
	}
}

func TestAuthorize_ForeignBodyOwner_Denied(t *testing.T) {
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	if _, err := auth(pol, homeTrust(), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "villain"); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign bodyOwner must DENY (compare-only)")
	}
}

// ── #3 cross-PRODUCT realm binding: ai capability must not authorize an io route (+ mirror) ──
func TestAuthorize_CrossRealm_Denied(t *testing.T) {
	// held ai caps, io OwnerBound route (+ io realm resolution): DENY.
	polIO := stub{res: Resolution{Realm: "orbtr.io", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	if _, err := Authorize(context.Background(), polIO, NewStaticTrust("orbtr.io"), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.io:x.read"), "acme", now); !errors.Is(err, ErrDenied) {
		t.Fatal("orbtr.ai capability must NOT authorize an orbtr.io route")
	}
	// mirror: held io caps, ai route.
	polAI := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.io:x.read"))}}
	if _, err := auth(polAI, homeTrust(), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "acme"); !errors.Is(err, ErrDenied) {
		t.Fatal("orbtr.io capability must NOT authorize an orbtr.ai route (mirror)")
	}
	// realm-mismatch between resolved partition realm and required realm: DENY.
	polMismatch := stub{res: Resolution{Realm: "orbtr.io", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"))}}
	if _, err := auth(polMismatch, homeTrust(NowTrust("orbtr.io")), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "acme"); !errors.Is(err, ErrDenied) {
		t.Fatal("partition realm != capability realm must DENY")
	}
}

// ── #3 global: reject body owner AND policy owner key ──
func TestAuthorize_GlobalOwnerAmbiguity_Denied(t *testing.T) {
	polKey := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:promo.lookup"))}}
	if _, err := auth(polKey, homeTrust(), verified(map[string]string{"org": "acme"}), global(t, "orbtr.ai:promo.lookup"), ""); !errors.Is(err, ErrDenied) {
		t.Fatal("global route with a policy owner key must DENY")
	}
	polOK := stub{res: Resolution{Realm: "orbtr.ai", Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:promo.lookup"))}}
	if _, err := auth(polOK, homeTrust(), verified(map[string]string{"org": "acme"}), global(t, "orbtr.ai:promo.lookup"), "acme"); !errors.Is(err, ErrDenied) {
		t.Fatal("global route with a body owner must DENY")
	}
	// clean global success → zero OwnerScope.
	id, err := auth(polOK, homeTrust(), verified(map[string]string{"org": "acme"}), global(t, "orbtr.ai:promo.lookup"), "")
	if err != nil || !id.OwnerScope.IsZero() {
		t.Fatalf("clean global must succeed with zero OwnerScope; got %+v err=%v", id.OwnerScope, err)
	}
}

func TestAuthorize_MissingCapability_Denied(t *testing.T) {
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet()}}
	if _, err := auth(pol, homeTrust(), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "acme"); !errors.Is(err, ErrDenied) {
		t.Fatal("missing capability must DENY")
	}
}

func TestAuthorize_PolicyError_NonDisclosing(t *testing.T) {
	secret := errors.New("org 42 not in registry")
	_, err := auth(stub{err: secret}, homeTrust(), verified(map[string]string{"org": "acme"}), ownerBound(t, "orbtr.ai:x.read"), "acme")
	if !errors.Is(err, ErrDenied) || errors.Is(err, secret) {
		t.Fatalf("policy error must surface as ErrDenied and NOT disclose the secret; got %v", err)
	}
}

// ── #5 foreign-realm capability is trust-gated; expiry/revocation/replay/absence fail closed ──
func TestAuthorize_ForeignRealmCapability_TrustGated(t *testing.T) {
	// A held capability in a FOREIGN realm (calndr) on an orbtr.ai route: the foreign
	// realm must be trusted or the whole set is rejected.
	pol := stub{res: Resolution{Realm: "orbtr.ai", OwnerKey: ClaimOrg, Capabilities: NewCapabilitySet(cap(t, "orbtr.ai:x.read"), cap(t, "calndr:y.read"))}}
	route := ownerBound(t, "orbtr.ai:x.read")
	p := verified(map[string]string{"org": "acme"})
	// untrusted foreign realm → DENY.
	if _, err := auth(pol, homeTrust(), p, route, "acme"); !errors.Is(err, ErrDenied) {
		t.Fatal("untrusted foreign-realm capability must DENY")
	}
	// expired / revoked / replayed → DENY.
	for name, e := range map[string]RealmTrust{
		"expired": {Realm: "calndr", ExpiresAtMS: now - 1},
		"revoked": {Realm: "calndr", ExpiresAtMS: now + 1_000, Revoked: true},
		"replay":  {Realm: "calndr", ExpiresAtMS: now + 1_000, NonceSeen: true},
	} {
		if _, err := auth(pol, homeTrust(e), p, route, "acme"); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s foreign trust must DENY; got %v", name, err)
		}
	}
	// live trust → succeeds.
	if _, err := auth(pol, homeTrust(RealmTrust{Realm: "calndr", ExpiresAtMS: now + 1_000}), p, route, "acme"); err != nil {
		t.Fatalf("live foreign trust must permit; got %v", err)
	}
}

func TestParseCapability_Malformed_Denied(t *testing.T) {
	for _, s := range []string{"", "noresource", "realm:noaction", "orbtr.ai:x.read.extra", "orbtr.ai:x.RE", "UP:x.y", ":x.y", ".:x.y", "orbtr..ai:x.y", ".orbtr.ai:x.y", "orbtr.ai.:x.y", "orbtr.ai:.y", "orbtr.ai:x."} {
		if _, err := ParseCapability(s); !errors.Is(err, ErrDenied) {
			t.Fatalf("malformed %q must be denied", s)
		}
	}
}

func TestCapabilitySet_SameRealm_Wildcard_Subsumes(t *testing.T) {
	set := NewCapabilitySet(cap(t, "orbtr.ai:x.*"))
	if !set.Allows(cap(t, "orbtr.ai:x.read")) {
		t.Fatal("same-realm wildcard must subsume")
	}
	if set.Allows(cap(t, "orbtr.io:x.read")) {
		t.Fatal("cross-realm must never subsume")
	}
	if NewCapabilitySet().Allows(cap(t, "orbtr.ai:x.read")) {
		t.Fatal("empty set must deny")
	}
	if !set.Subsumes(NewCapabilitySet(cap(t, "orbtr.ai:x.read"))) {
		t.Fatal("parent x.* must subsume child x.read")
	}
	if set.Subsumes(NewCapabilitySet(cap(t, "orbtr.ai:y.write"))) {
		t.Fatal("child must not exceed parent")
	}
}

// NowTrust is a tiny helper: a live trust entry for realm r.
func NowTrust(r string) RealmTrust { return RealmTrust{Realm: r, ExpiresAtMS: now + 1_000} }
