package warrant

import "testing"

// String exists so a capability set can cross a []string boundary — a mint input —
// without losing what it holds. That only works if the round trip is exact, so the
// property is asserted over every shape ParseCapability admits, denies included.
func TestCapabilityStringRoundTripsThroughParse(t *testing.T) {
	for _, want := range []string{
		"orbtr.io:device.read",
		"orbtr.io:device.*",
		"-orbtr.io:device.read",
		"-orbtr.io:device.*",
		"orbtr.ai.storage:token.mint",     // dotted realm
		"-orbtr.ai.storage:token.mint",    // dotted realm, revoked
		"orbtr.io:device_group.read-only", // _ and - are legal segment characters
	} {
		c, err := ParseCapability(want)
		if err != nil {
			t.Fatalf("ParseCapability(%q): %v", want, err)
		}
		if got := c.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
		again, err := ParseCapability(c.String())
		if err != nil {
			t.Fatalf("re-parsing %q failed: %v", c.String(), err)
		}
		// Printed field-by-field: Capability now has a String method, so %v would
		// render both sides through it and hide the very difference under test.
		if again != c {
			t.Errorf("round trip changed the capability: {realm:%s resource:%s action:%s deny:%v} -> "+
				"{realm:%s resource:%s action:%s deny:%v}",
				c.realm, c.resource, c.action, c.deny,
				again.realm, again.resource, again.action, again.deny)
		}
		if again.IsDeny() != c.IsDeny() {
			t.Errorf("round trip lost the deny flag on %q", want)
		}
	}
}

// The deny marker must survive a string boundary, because a converter's output
// reaches a mint as text. Losing it silently converts a revocation into a grant.
func TestDenySurvivesAStringBoundary(t *testing.T) {
	conv := ScopeConversion{
		Realm:          "orbtr.io.storage",
		KnownResources: []string{"reservation", "blob", "token"},
	}
	caps := conv.ScopesToCapabilities([]string{"orbtr.io.storage.*", "-orbtr.io.storage.token.mint"})

	// Exactly what a []string mint path does: render, carry, parse back.
	var carried []string
	for _, c := range caps {
		carried = append(carried, c.String())
	}
	rebuilt := make([]Capability, 0, len(carried))
	for _, s := range carried {
		c, err := ParseCapability(s)
		if err != nil {
			t.Fatalf("a rendered capability did not parse back: %q: %v", s, err)
		}
		rebuilt = append(rebuilt, c)
	}
	if NewCapabilitySet(rebuilt...).Allows(mustCap(t, "orbtr.io.storage:token.mint")) {
		t.Error("the revocation was lost crossing a []string boundary; the wildcard conferred it again")
	}
	if !NewCapabilitySet(rebuilt...).Allows(mustCap(t, "orbtr.io.storage:blob.write")) {
		t.Error("the string boundary dropped a legitimate grant")
	}
}

// A zero Capability renders "" rather than ":.", which would be a string
// ParseCapability rejects while looking like a capability at a glance.
func TestZeroCapabilityRendersEmpty(t *testing.T) {
	if got := (Capability{}).String(); got != "" {
		t.Errorf("zero Capability rendered %q, want empty", got)
	}
}
