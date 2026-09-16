package warrant

import "testing"

// productRealm is the conversion as a product-scoped realm reads it today;
// neutralRealm is the same conversion after the realm drops its product segment.
// Both are declared here so every case below states which side of a rename it is
// asserting, rather than leaving the reader to infer it from a string.
var (
	productRealm = ScopeConversion{Realm: "orbtr.ai", KnownResources: []string{"conversation", "billing"}}
	neutralRealm = ScopeConversion{Realm: "orbtr", KnownResources: []string{"conversation", "billing"}}
)

// TestOrphanedDeniesFindsTheDenyARealmRenameStopsApplying is the case the whole
// function exists for, and the one ScopesToCapabilities cannot show.
//
// A deny stored under the neutral realm, read by a conversion still on the
// product realm, matches no prefix and expands to nothing. The converted output
// is simply missing it, which is identical to the output for a subject that was
// never denied anything — so an assertion on capabilities passes while the
// revocation has stopped applying.
func TestOrphanedDeniesFindsTheDenyARealmRenameStopsApplying(t *testing.T) {
	stored := []string{"orbtr.conversation.read", "-orbtr.conversation.send"}

	caps := productRealm.ScopesToCapabilities(stored)
	for _, c := range caps {
		if c.String()[0] == '-' {
			t.Fatalf("expected the deny to vanish from the conversion, got %q", c.String())
		}
	}

	orphaned := productRealm.OrphanedDenies(stored)
	if len(orphaned) != 1 || orphaned[0] != "-orbtr.conversation.send" {
		t.Fatalf("OrphanedDenies = %v, want the one deny that expands to nothing", orphaned)
	}
}

// TestOrphanedDeniesIsEmptyWhenTheRealmMatches pins the positive leg. Without it
// a function that returned every deny unconditionally would pass the test above,
// which is the shape a reporter is easiest to get wrong in.
func TestOrphanedDeniesIsEmptyWhenTheRealmMatches(t *testing.T) {
	stored := []string{"orbtr.conversation.read", "-orbtr.conversation.send"}

	if got := neutralRealm.OrphanedDenies(stored); len(got) != 0 {
		t.Fatalf("OrphanedDenies under the matching realm = %v, want none", got)
	}
	// And the deny genuinely converts there, so "none orphaned" is not "none seen".
	var sawDeny bool
	for _, c := range neutralRealm.ScopesToCapabilities(stored) {
		if c.String()[0] == '-' {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatal("the matching realm produced no deny capability; the control proves nothing")
	}
}

// TestOrphanedDeniesReportsTheOtherRealmCaseToo records a deliberate limit rather
// than a defect: a deny belonging to a genuinely different realm also expands to
// nothing and is also reported.
//
// The function cannot separate the two — that is the whole reason it exists, and
// a caller that could tell them apart would not need it. A realm rename asserts
// the result is EMPTY, which is only meaningful when the stored set is scoped to
// the realm being renamed. Asserting emptiness over a multi-realm store would
// fail on correct data.
func TestOrphanedDeniesReportsTheOtherRealmCaseToo(t *testing.T) {
	stored := []string{"-orbtr.io.storage.delete"}

	got := productRealm.OrphanedDenies(stored)
	if len(got) != 1 {
		t.Fatalf("OrphanedDenies = %v, want the foreign-realm deny reported", got)
	}
}

// TestARealmRenameCanWidenADenyOntoTheFormerProductSegment is §8.4's OTHER
// acceptance leg, and it is the half that reads as working.
//
// A deny stored under the product realm, read after the realm drops its product
// segment, DOES match the shorter prefix — so it is not orphaned. It expands,
// and what it expands to names the former product segment as a RESOURCE. The
// revocation lands on a resource that does not exist, and the capability it was
// written to revoke stays granted.
//
// OrphanedDenies cannot catch this one, which is why the acceptance test is two
// assertions and not one: the deny that vanishes and the deny that survives
// pointing at nothing fail the same way and are found differently.
func TestARealmRenameCanWidenADenyOntoTheFormerProductSegment(t *testing.T) {
	stored := []string{"-orbtr.ai.conversation.read"}

	if got := neutralRealm.OrphanedDenies(stored); len(got) != 0 {
		t.Fatalf("this deny is NOT orphaned — it matches the shorter realm; got %v", got)
	}

	caps := neutralRealm.ScopesToCapabilities(stored)
	if len(caps) == 0 {
		t.Fatal("expected the deny to expand under the neutral realm")
	}
	var found string
	for _, c := range caps {
		if s := c.String(); s[0] == '-' {
			found = s
		}
	}
	if found != "-orbtr:ai.conversation" {
		t.Fatalf("deny expanded to %q; the former product segment should land as the RESOURCE, "+
			"which is what makes this revocation apply to nothing", found)
	}
}
