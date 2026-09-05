package warrant

import (
	"sort"
	"testing"
)

func conv() ScopeConversion {
	return ScopeConversion{
		Realm:          "orbtr.ai",
		KnownResources: []string{"exec", "assistant", "billing", "forge"},
		Reserved:       map[string]struct{}{"forge": {}},
	}
}

func capStrings(caps []Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, c.realm+":"+c.resource+"."+c.action)
	}
	sort.Strings(out)
	return out
}

func allows(t *testing.T, caps []Capability, want string) bool {
	t.Helper()
	return NewCapabilitySet(caps...).Allows(mustCap(t, want))
}

// The shape that made deny worth keeping: a realm-wide grant minus specific
// revocations. The wildcard genuinely confers them; only the deny removes them.
func TestRealmWildcardMinusDenies(t *testing.T) {
	caps := conv().ScopesToCapabilities([]string{
		"orbtr.ai.*",
		"-orbtr.ai.exec.*",
	})
	if allows(t, caps, "orbtr.ai:exec.run_as") {
		t.Error("deny of exec.* did not remove exec from the realm-wide grant")
	}
	if !allows(t, caps, "orbtr.ai:assistant.write") {
		t.Error("deny of exec.* wrongly removed an unrelated resource")
	}
}

// A reserved resource must be unreachable by ANY scope — wildcard or explicit.
// This is the forge-guard: reserved families are mint-only.
func TestReservedResourceIsUnreachableFromScopes(t *testing.T) {
	viaWildcard := conv().ScopesToCapabilities([]string{"orbtr.ai.*"})
	for _, c := range capStrings(viaWildcard) {
		if c == "orbtr.ai:forge.*" {
			t.Fatal("a realm wildcard reached a RESERVED resource")
		}
	}
	viaExplicit := conv().ScopesToCapabilities([]string{"orbtr.ai.forge.mint"})
	if len(viaExplicit) != 0 {
		t.Errorf("an explicit reserved scope converted to %v, want nothing", capStrings(viaExplicit))
	}
}

// Every unrecognised shape must convert to NOTHING. Each of these once looked
// like a plausible grant; converting any of them permissively would over-grant.
func TestUnrecognisedShapesConferNothing(t *testing.T) {
	for _, scope := range []string{
		"orbtr.io.storage.read",    // another realm
		"orbtr.ai.exec",            // bare resource, no action
		"orbtr.ai.exec.tool.write", // per-instance path a capability cannot express
		"orbtr.ai.*.write",         // resource wildcard — not expressible
		"orbtr.ai..write",          // empty resource
		"orbtr.ai.exec.",           // empty action
		"",
	} {
		if got := conv().ScopesToCapabilities([]string{scope}); len(got) != 0 {
			t.Errorf("scope %q converted to %v, want nothing", scope, capStrings(got))
		}
	}
}

// An action wildcard IS expressible and must survive conversion.
func TestActionWildcardSurvives(t *testing.T) {
	caps := conv().ScopesToCapabilities([]string{"orbtr.ai.exec.*"})
	if !allows(t, caps, "orbtr.ai:exec.run_as") || !allows(t, caps, "orbtr.ai:exec.mode") {
		t.Errorf("action wildcard did not confer its actions: %v", capStrings(caps))
	}
}

// An incomplete resource vocabulary must UNDER-grant, never over-grant: a
// wildcard cannot confer a capability for a resource the consumer never named.
func TestIncompleteVocabularyUnderGrants(t *testing.T) {
	narrow := ScopeConversion{Realm: "orbtr.ai", KnownResources: []string{"exec"}}
	caps := narrow.ScopesToCapabilities([]string{"orbtr.ai.*"})
	if allows(t, caps, "orbtr.ai:assistant.write") {
		t.Error("wildcard granted a resource absent from KnownResources")
	}
	if !allows(t, caps, "orbtr.ai:exec.run_as") {
		t.Error("wildcard failed to grant a resource that IS in KnownResources")
	}
}

// Deny must subtract regardless of the order scopes arrive in.
func TestDenySubtractsRegardlessOfOrder(t *testing.T) {
	a := conv().ScopesToCapabilities([]string{"orbtr.ai.exec.run_as", "-orbtr.ai.exec.run_as"})
	b := conv().ScopesToCapabilities([]string{"-orbtr.ai.exec.run_as", "orbtr.ai.exec.run_as"})
	if len(a) != 0 || len(b) != 0 {
		t.Errorf("deny did not subtract in both orders: %v / %v", capStrings(a), capStrings(b))
	}
}
