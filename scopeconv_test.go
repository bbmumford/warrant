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

// Renders the deny flag, because a revocation and a grant are otherwise printed
// identically and a failure message reads as the opposite of what it found.
func capStrings(caps []Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		s := c.realm + ":" + c.resource + "." + c.action
		if c.deny {
			s = "-" + s
		}
		out = append(out, s)
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

// Deny must win regardless of the order scopes arrive in. Asserted on the VERDICT,
// not on the emitted set: a deny is now carried as a negative capability rather
// than removed, so both a grant and its revocation are present and only Allows
// says which prevails.
func TestDenyWinsRegardlessOfOrder(t *testing.T) {
	a := conv().ScopesToCapabilities([]string{"orbtr.ai.exec.run_as", "-orbtr.ai.exec.run_as"})
	b := conv().ScopesToCapabilities([]string{"-orbtr.ai.exec.run_as", "orbtr.ai.exec.run_as"})
	for name, caps := range map[string][]Capability{"grant-first": a, "deny-first": b} {
		if allows(t, caps, "orbtr.ai:exec.run_as") {
			t.Errorf("%s: deny lost to the grant in the same set: %v", name, capStrings(caps))
		}
	}
}

// A DENY FINER THAN THE GRANT IT LIMITS. The realm wildcard emits an action
// wildcard ("token.*"), and the revocation names one action under it
// ("token.mint"). Removing denied capabilities from the emitted set cannot
// express this: no emitted string equals "token.mint", so the revocation
// vanishes and the wildcard keeps conferring mint — a privilege escalation that
// builds and tests green everywhere except at the operation itself.
//
// The realm-wide-minus-revocations test above passes under either mechanism
// because it denies at the SAME granularity the wildcard emits. This one does
// not, which is the whole reason it exists.
func TestDenyNarrowerThanTheWildcardThatWouldConferIt(t *testing.T) {
	c := ScopeConversion{
		Realm:          "orbtr.io.storage",
		KnownResources: []string{"reservation", "placementclass", "blob", "token", "audit", "access"},
	}
	caps := c.ScopesToCapabilities([]string{"orbtr.io.storage.*", "-orbtr.io.storage.token.mint"})
	if allows(t, caps, "orbtr.io.storage:token.mint") {
		t.Errorf("a realm wildcard conferred an action that was explicitly revoked: %v", capStrings(caps))
	}
	if !allows(t, caps, "orbtr.io.storage:token.read") {
		t.Errorf("revoking one action removed the rest of the resource: %v", capStrings(caps))
	}
	if !allows(t, caps, "orbtr.io.storage:blob.write") {
		t.Errorf("revoking one action removed an unrelated resource: %v", capStrings(caps))
	}
}

// A REVOCATION THE GRAMMAR CANNOT EXPRESS MUST WIDEN, NEVER DISAPPEAR. A
// per-instance path has no capability form: a capability is realm:resource.action
// and this names a fourth segment. Conferring nothing for an unrecognised GRANT is
// safe; conferring nothing for an unrecognised DENY leaves the broad grant intact.
// So it is widened to the resource.action it sits under — over-broad, and over-broad
// fails loudly at a legitimate call rather than silently at an illegitimate one.
func TestInexpressibleDenyWidensRatherThanVanishing(t *testing.T) {
	c := ScopeConversion{Realm: "orbtr.ai", KnownResources: []string{"exec", "assistant"}}
	caps := c.ScopesToCapabilities([]string{"orbtr.ai.*", "-orbtr.ai.exec.run_as.system"})
	if allows(t, caps, "orbtr.ai:exec.run_as") {
		t.Errorf("a per-instance revocation vanished and left the wildcard conferring it: %v", capStrings(caps))
	}
	if !allows(t, caps, "orbtr.ai:exec.mode") {
		t.Errorf("widening reached past the action it names: %v", capStrings(caps))
	}
	if !allows(t, caps, "orbtr.ai:assistant.write") {
		t.Errorf("widening reached past the resource it names: %v", capStrings(caps))
	}
}

// A bare resource names no action, so revoking it revokes the whole resource.
// The grant path confers nothing for the same shape — the asymmetry is deliberate.
func TestBareResourceDenyRevokesTheWholeResource(t *testing.T) {
	caps := conv().ScopesToCapabilities([]string{"orbtr.ai.*", "-orbtr.ai.exec"})
	if allows(t, caps, "orbtr.ai:exec.run_as") || allows(t, caps, "orbtr.ai:exec.mode") {
		t.Errorf("a bare-resource revocation left actions on that resource: %v", capStrings(caps))
	}
	if !allows(t, caps, "orbtr.ai:assistant.write") {
		t.Errorf("a bare-resource revocation reached another resource: %v", capStrings(caps))
	}
}

// Reserved constrains grants only. Withholding a revocation because it names a
// reserved resource could only widen access, so the deny is still emitted.
func TestDenyReachesReservedResources(t *testing.T) {
	caps := conv().ScopesToCapabilities([]string{"-orbtr.ai.forge.mint"})
	if len(caps) != 1 || !caps[0].IsDeny() {
		t.Fatalf("a revocation naming a reserved resource was dropped: %v", capStrings(caps))
	}
}

// Another realm's revocation revokes nothing here — nothing here is in its realm.
// This is the one drop on the deny path, and it is not a widening decision.
func TestForeignRealmDenyIsIgnored(t *testing.T) {
	caps := conv().ScopesToCapabilities([]string{"orbtr.ai.exec.run_as", "-orbtr.io.exec.run_as"})
	if !allows(t, caps, "orbtr.ai:exec.run_as") {
		t.Errorf("a revocation from another realm suppressed a grant in this one: %v", capStrings(caps))
	}
}

// REALM DEPTH IS PART OF THE CONFIGURATION, and getting it wrong converts every
// scope to nothing — which denies silently rather than erroring.
//
// The remainder after trimming Realm must be exactly <resource>.<action>. A
// consumer whose scopes are "orbtr.io.storage.reservation.read" has a THREE-part
// remainder under Realm="orbtr.io", so nothing converts; its realm is
// "orbtr.io.storage" and its resources are reservation/blob/token.
//
// This case exists because the converter was generalised from a consumer whose
// scopes are natively realm.resource.verb, and every other test here inherits
// that shape. Tested against the shape it was generalised FOR, not only FROM.
func TestRealmDepthMustMatchTheScopeShape(t *testing.T) {
	scope := "orbtr.io.storage.reservation.read"

	tooShallow := ScopeConversion{
		Realm:          "orbtr.io",
		KnownResources: []string{"storage"},
	}
	if got := tooShallow.ScopesToCapabilities([]string{scope}); len(got) != 0 {
		t.Errorf("a too-shallow realm converted %q to %v; expected nothing "+
			"(the remainder has 3 parts, not resource.action)", scope, capStrings(got))
	}

	correct := ScopeConversion{
		Realm:          "orbtr.io.storage",
		KnownResources: []string{"reservation", "blob", "token"},
	}
	caps := correct.ScopesToCapabilities([]string{scope})
	if len(caps) != 1 {
		t.Fatalf("correct realm depth converted %q to %v, want exactly one capability",
			scope, capStrings(caps))
	}
	if !NewCapabilitySet(caps...).Allows(mustCap(t, "orbtr.io.storage:reservation.read")) {
		t.Errorf("converted capability does not allow the operation it names: %v", capStrings(caps))
	}
}

// A realm wildcard has to match the same depth, or it expands across the wrong
// vocabulary — the failure that would silently empty a whole surface.
func TestRealmWildcardRespectsRealmDepth(t *testing.T) {
	c := ScopeConversion{
		Realm:          "orbtr.io.storage",
		KnownResources: []string{"reservation", "blob"},
	}
	caps := c.ScopesToCapabilities([]string{"orbtr.io.storage.*"})
	if !NewCapabilitySet(caps...).Allows(mustCap(t, "orbtr.io.storage:blob.write")) {
		t.Errorf("realm wildcard at the correct depth did not confer blob.write: %v", capStrings(caps))
	}
}
