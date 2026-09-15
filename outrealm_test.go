package warrant

import "testing"

// TestOutRealmUnsetIsByteIdenticalToBefore is the compatibility property the
// field exists to preserve: a conversion that never sets it must emit exactly
// what it emitted when the type had one realm.
func TestOutRealmUnsetIsByteIdenticalToBefore(t *testing.T) {
	c := ScopeConversion{Realm: "orbtr.ai", KnownResources: []string{"ledger", "skills"}}
	for _, scope := range []string{
		"orbtr.ai.ledger.read",
		"orbtr.ai.ledger.*",
		"orbtr.ai.*",
		"-orbtr.ai.ledger.read",
	} {
		for _, got := range c.ScopesToCapabilities([]string{scope}) {
			if got.Realm() != "orbtr.ai" {
				t.Fatalf("scope %q emitted realm %q; unset OutRealm must keep Realm", scope, got.Realm())
			}
		}
	}
}

// TestOutRealmSeparatesReadFromEmit is the case the field was added for: read a
// shared vocabulary, emit into a distinct realm.
func TestOutRealmSeparatesReadFromEmit(t *testing.T) {
	c := ScopeConversion{Realm: "orbtr", OutRealm: "orbtr.ai", KnownResources: []string{"ledger"}}

	caps := c.ScopesToCapabilities([]string{"orbtr.ledger.read"})
	if len(caps) != 1 {
		t.Fatalf("a scope at the input realm produced %v, want one capability", caps)
	}
	if caps[0].Realm() != "orbtr.ai" {
		t.Fatalf("emitted realm %q, want the output realm", caps[0].Realm())
	}

	// A scope at the OUTPUT realm is not readable — input matching stays on Realm.
	if got := c.ScopesToCapabilities([]string{"orbtr.ai.ledger.read"}); len(got) != 0 {
		t.Fatalf("a scope at the output realm was read as input: %v", got)
	}
}

// TestOutRealmKeepsIssuersDistinct is why it is load-bearing: two conversions
// reading the SAME shared vocabulary must not mint capabilities that compare
// equal, or one issuer's grant satisfies the other's route.
func TestOutRealmKeepsIssuersDistinct(t *testing.T) {
	shared := []string{"ledger"}
	a := ScopeConversion{Realm: "orbtr", OutRealm: "orbtr.ai", KnownResources: shared}
	b := ScopeConversion{Realm: "orbtr", OutRealm: "orbtr.io", KnownResources: shared}

	ca := a.ScopesToCapabilities([]string{"orbtr.ledger.read"})
	cb := b.ScopesToCapabilities([]string{"orbtr.ledger.read"})
	if len(ca) != 1 || len(cb) != 1 {
		t.Fatalf("expected one capability each, got %v and %v", ca, cb)
	}
	if ca[0].String() == cb[0].String() {
		t.Fatalf("two issuers minted the same capability %q from the same scope", ca[0])
	}
	// And one must not satisfy the other.
	if NewCapabilitySet(ca[0]).Allows(cb[0]) {
		t.Fatalf("%q satisfied %q across issuers", ca[0], cb[0])
	}
}
