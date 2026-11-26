package mint

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestVerifierFmtRedactsKey: formatting the Verifier discloses no key bytes.
func TestVerifierFmtRedactsKey(t *testing.T) {
	v, _ := NewVerifier()
	dump := fmt.Sprintf("%#v|%+v|%v", v, v, v)
	if bytes.Contains([]byte(dump), v.key) {
		t.Fatal("Verifier formatting must NOT contain the key bytes")
	}
	if !strings.Contains(dump, "redacted") {
		t.Fatal("Verifier formatting must show a redaction marker")
	}
}

func sample() Assertion {
	return Assertion{
		Subject: Subject{ID: "u1", Kind: "user"}, Deployment: "orbtr",
		HasPartition: true, Partition: "acme", Capabilities: []string{"orbtr.io:device.read"},
		Issuer: "io-edge", Audience: "node.orbtr.io", Version: "v1", Realm: "orbtr.io",
		ExpiresAtMS: 10_000, Nonce: "nonce-abc123",
	}
}

// TestPrincipalDoesNotEmbedKey proves the receiver key never enters a
// principal, so reflecting/logging one (fmt %#v/%+v/%v) discloses no key material.
func TestPrincipalDoesNotEmbedKey(t *testing.T) {
	v, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := v.Mint(sample())
	dump := fmt.Sprintf("%#v|%+v|%v", p, p, p)
	if bytes.Contains([]byte(dump), v.key) {
		t.Fatal("a principal's representation must NOT contain the Verifier key")
	}
	if bytes.Equal(p.tag, v.key) {
		t.Fatal("the tag must be a MAC over the assertion, never the key itself")
	}
	if len(p.tag) == 0 {
		t.Fatal("a minted principal must carry a tag")
	}
}

// TestMACTamperEvident: changing ANY assertion field invalidates the tag (the canonical encoding
// covers everything), so a forger cannot mutate a captured principal.
func TestMACTamperEvident(t *testing.T) {
	v, _ := NewVerifier()
	p, _ := v.Mint(sample())
	if !v.Verify(p) {
		t.Fatal("a freshly minted principal must verify")
	}
	// tamper with each field on a copy; the stored tag no longer matches the recomputed one.
	mutators := []func(*VerifiedPrincipal){
		func(x *VerifiedPrincipal) { x.partition = "evil" },
		func(x *VerifiedPrincipal) { x.realm = "orbtr.ai" },
		func(x *VerifiedPrincipal) { x.nonce = "different" },
		func(x *VerifiedPrincipal) { x.caps = []string{"orbtr.io:device.admin"} },
		func(x *VerifiedPrincipal) { x.deployment = "someone-else" },
		func(x *VerifiedPrincipal) { x.expiresMS = 1 << 40 },
	}
	for i, mut := range mutators {
		tampered := p
		mut(&tampered)
		if v.Verify(tampered) {
			t.Fatalf("mutator %d: a tampered principal must FAIL verification (tag is over all fields)", i)
		}
	}
}

func TestForeignVerifierRejected(t *testing.T) {
	real, _ := NewVerifier()
	forger, _ := NewVerifier()
	p, _ := forger.Mint(sample())
	if real.Verify(p) {
		t.Fatal("a principal minted by a foreign Verifier must be rejected")
	}
	if !forger.Verify(p) {
		t.Fatal("sanity: the minting Verifier accepts its own principal")
	}
}

func TestConsistent(t *testing.T) {
	if !(Assertion{HasPartition: true, Partition: "x"}).Consistent() {
		t.Fatal("HasPartition+Partition should be consistent")
	}
	if !(Assertion{HasPartition: false, Partition: ""}).Consistent() {
		t.Fatal("no-owner should be consistent")
	}
	if (Assertion{HasPartition: false, Partition: "x"}).Consistent() {
		t.Fatal("owner material with HasPartition=false must be inconsistent")
	}
	if (Assertion{HasPartition: true, Partition: ""}).Consistent() {
		t.Fatal("HasPartition=true with empty owner must be inconsistent")
	}
}
