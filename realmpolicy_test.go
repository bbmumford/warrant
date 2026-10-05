/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package warrant

import (
	"context"
	"testing"
)

func TestRealmTrust_GrammarVersionDeclaration(t *testing.T) {
	v, _ := NewVerifier()

	declared := homeTrust()
	declared.GrammarVersion = GrammarVersion
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), declared); err != nil {
		t.Fatalf("an entry declaring the implemented grammar must be accepted: %v", err)
	}
	// An entry that declares nothing is read at the implemented grammar (homeTrust sets
	// no version and every other test here builds an Authorizer from it).
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), homeTrust()); err != nil {
		t.Fatalf("an entry declaring no grammar must be accepted: %v", err)
	}

	other := homeTrust()
	other.GrammarVersion = GrammarVersion + "-next"
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), other); !denied(err) {
		t.Fatal("an entry declaring a grammar this build does not implement must be REFUSED")
	}

	foreign := RealmTrust{Realm: "orbtr.ai", Issuer: "ai-edge", Audience: aud, PolicyVersion: ver,
		GrammarVersion: GrammarVersion + "-next", ExpiresAtMS: 1 << 62}
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), homeTrust(), foreign); !denied(err) {
		t.Fatal("a FOREIGN entry declaring another grammar must be REFUSED")
	}
}

func TestRealmTrust_PolicyDigestBoundAtConstruction(t *testing.T) {
	v, _ := NewVerifier()

	right := homeTrust()
	right.PolicyDigest = right.policyIdentityDigest()
	az, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), right)
	if err != nil {
		t.Fatalf("an entry declaring the digest over its own fields must be accepted: %v", err)
	}
	// Bound, not merely accepted: the entry in the Authorizer's map carries the digest and
	// the grammar version, so no decision reads either at a default.
	bound := az.trust[homeRealm]
	if bound.PolicyDigest != right.policyIdentityDigest() || bound.GrammarVersion != GrammarVersion {
		t.Fatalf("the pinned entry must carry the bound digest and grammar: %+v", bound)
	}
	// An entry that declares none is bound to the digest over its own fields.
	az2 := newAuthz(t, v, fixedClock(5000))
	if az2.trust[homeRealm].PolicyDigest != homeTrust().policyIdentityDigest() {
		t.Fatal("an entry declaring no digest must still be bound to one")
	}

	wrong := homeTrust()
	wrong.PolicyDigest = "00" + right.policyIdentityDigest()[2:]
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), wrong); !denied(err) {
		t.Fatal("an entry whose declared digest does not cover its own fields must be REFUSED")
	}

	// The digest covers the policy version, so an entry ratified under one version and
	// edited to another is refused rather than serving under a digest that no longer names it.
	moved := homeTrust()
	moved.PolicyDigest = moved.policyIdentityDigest()
	moved.PolicyVersion = "v2"
	if _, err := NewAuthorizer(v, deployment, fixedClock(5000), routes(t), moved); !denied(err) {
		t.Fatal("a field edited after the digest was taken must be REFUSED")
	}
}

// At Authorize: the identity the sealed assertion presents must digest to the value bound
// on the trusted entry. The positive is the ordinary request; each negative moves one field
// the digest covers.
func TestAuthorize_PolicyIdentityDigestChecked(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))

	if _, err := a.Authorize(context.Background(), mustMint(t, v, baseAssertion()), "device.read", "acme"); err != nil {
		t.Fatalf("a principal presenting the trusted policy identity must authorize: %v", err)
	}
	for name, mut := range map[string]func(*Assertion){
		"another issuer":         func(as *Assertion) { as.Issuer = "attacker" },
		"another audience":       func(as *Assertion) { as.Audience = "other.aud" },
		"another policy version": func(as *Assertion) { as.Version = "v99" },
	} {
		as := baseAssertion()
		as.Nonce = "nonce-digest-" + name[:4]
		mut(&as)
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
			t.Fatalf("%s must be DENIED by the policy digest", name)
		}
	}
}

// An entry that reached a decision without passing through pinned carries no digest and
// authorizes nothing, so a trust map built by any other path fails closed.
func TestPolicyMatches_UnboundEntryDenies(t *testing.T) {
	v, _ := NewVerifier()
	p := mustMint(t, v, baseAssertion())
	if homeTrust().policyMatches(p) {
		t.Fatal("an entry with no bound digest must not match any principal")
	}
	if !homeTrust().pinned().policyMatches(p) {
		t.Fatal("a bound entry must match the principal presenting its own policy identity")
	}
}
