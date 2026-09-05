package warrant

import "testing"

// mustCap is declared in warrant_test.go.

// The load-bearing case: a role written as a broad grant minus specific revocations. The wildcard
// DOES confer the action, so the revocation is only expressible if deny outranks it.
func TestDenyBeatsWildcardGrant(t *testing.T) {
	set := NewCapabilitySet(
		mustCap(t, "orbtr.ai:exec.*"),
		mustCap(t, "-orbtr.ai:exec.run_as"),
	)
	if set.Allows(mustCap(t, "orbtr.ai:exec.run_as")) {
		t.Error("explicit deny did not beat the wildcard grant; a revocation is a no-op")
	}
	if !set.Allows(mustCap(t, "orbtr.ai:exec.mode")) {
		t.Error("deny of run_as leaked onto exec.mode; a deny must revoke only what it covers")
	}
}

func TestDenyBeatsExactGrant_RegardlessOfOrder(t *testing.T) {
	denyFirst := NewCapabilitySet(
		mustCap(t, "-orbtr.io:storage.mint"),
		mustCap(t, "orbtr.io:storage.mint"),
	)
	grantFirst := NewCapabilitySet(
		mustCap(t, "orbtr.io:storage.mint"),
		mustCap(t, "-orbtr.io:storage.mint"),
	)
	req := mustCap(t, "orbtr.io:storage.mint")
	if denyFirst.Allows(req) || grantFirst.Allows(req) {
		t.Error("deny precedence is order-dependent; it must hold whichever way the set is built")
	}
}

// A wildcard DENY revokes every action it covers, mirroring the wildcard grant.
func TestWildcardDenyRevokesTheResource(t *testing.T) {
	set := NewCapabilitySet(
		mustCap(t, "orbtr.ai:exec.run_as"),
		mustCap(t, "orbtr.ai:exec.mode"),
		mustCap(t, "-orbtr.ai:exec.*"),
	)
	for _, action := range []string{"orbtr.ai:exec.run_as", "orbtr.ai:exec.mode"} {
		if set.Allows(mustCap(t, action)) {
			t.Errorf("wildcard deny did not revoke %s", action)
		}
	}
}

// Deny is realm- and resource-scoped like a grant: it must not bleed across either.
func TestDenyDoesNotCrossRealmOrResource(t *testing.T) {
	set := NewCapabilitySet(
		mustCap(t, "orbtr.io:storage.mint"),
		mustCap(t, "orbtr.ai:storage.mint"),
		mustCap(t, "-orbtr.ai:storage.mint"),
	)
	if !set.Allows(mustCap(t, "orbtr.io:storage.mint")) {
		t.Error("an orbtr.ai deny revoked an orbtr.io capability; deny crossed realms")
	}
	set2 := NewCapabilitySet(
		mustCap(t, "orbtr.ai:exec.run"),
		mustCap(t, "-orbtr.ai:storage.run"),
	)
	if !set2.Allows(mustCap(t, "orbtr.ai:exec.run")) {
		t.Error("a storage deny revoked an exec capability; deny crossed resources")
	}
}

// A set with no negatives must behave exactly as it did before deny existed.
func TestPositiveOnlySetIsUnchanged(t *testing.T) {
	set := NewCapabilitySet(mustCap(t, "orbtr.ai:exec.*"), mustCap(t, "orbtr.io:storage.mint"))
	for _, ok := range []string{"orbtr.ai:exec.run_as", "orbtr.ai:exec.mode", "orbtr.io:storage.mint"} {
		if !set.Allows(mustCap(t, ok)) {
			t.Errorf("positive-only set stopped allowing %s", ok)
		}
	}
	for _, no := range []string{"orbtr.io:exec.run_as", "orbtr.ai:storage.mint"} {
		if set.Allows(mustCap(t, no)) {
			t.Errorf("positive-only set started allowing %s", no)
		}
	}
}

// A negative capability must never be satisfiable as a REQUIREMENT — otherwise a caller could ask
// "am I denied X?" and have a matching deny read back as permission.
func TestNegativeRequirementIsRefused(t *testing.T) {
	set := NewCapabilitySet(mustCap(t, "-orbtr.ai:exec.run_as"))
	if set.Allows(mustCap(t, "-orbtr.ai:exec.run_as")) {
		t.Error("a negative requirement was satisfied by a matching deny")
	}
	full := NewCapabilitySet(mustCap(t, "orbtr.ai:exec.*"))
	if full.Allows(mustCap(t, "-orbtr.ai:exec.run_as")) {
		t.Error("a negative requirement was satisfied by a wildcard grant")
	}
}

// The leading "-" must be stripped BEFORE validation. validSegment admits "-" as an ordinary
// character, so leaving it on would parse a revocation as a capability in a realm named
// "-orbtr.ai" — matching nothing, denying nothing, and silently voiding the revocation.
func TestNegativeParsesAsTheSameRealmNotABogusOne(t *testing.T) {
	deny := mustCap(t, "-orbtr.ai:exec.run_as")
	grant := mustCap(t, "orbtr.ai:exec.run_as")
	if deny.Realm() != grant.Realm() {
		t.Fatalf("deny realm = %q, grant realm = %q; the '-' was not stripped before parsing",
			deny.Realm(), grant.Realm())
	}
	if !deny.IsDeny() || grant.IsDeny() {
		t.Errorf("IsDeny wrong: deny=%v grant=%v", deny.IsDeny(), grant.IsDeny())
	}
}

// Subsumption has no meaning once the compared set carries a revocation, and skipping it would let
// an attenuated set claim to subsume one whose denies it does not reproduce.
func TestSubsumesRefusesASetContainingADeny(t *testing.T) {
	broad := NewCapabilitySet(mustCap(t, "orbtr.ai:exec.*"))
	withDeny := NewCapabilitySet(mustCap(t, "orbtr.ai:exec.run"), mustCap(t, "-orbtr.ai:exec.mode"))
	if broad.Subsumes(withDeny) {
		t.Error("a set containing a deny was reported as subsumed")
	}
	positive := NewCapabilitySet(mustCap(t, "orbtr.ai:exec.run"))
	if !broad.Subsumes(positive) {
		t.Error("wildcard set stopped subsuming a positive-only set")
	}
}
