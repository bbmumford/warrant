package warrant

import "testing"

// An action wildcard on a resource ActionWildcards lists converts to the actions
// named, whether it is spelled for the resource or reaches it through a realm-wide
// grant, so an action left out (a held-back verb) is reached by no wildcard, with
// or without a parameter, while a grant naming it still reaches it. A deny of the
// resource's wildcard keeps its wildcard.
func TestActionWildcardsNarrowGrantsOnly(t *testing.T) {
	c := ScopeConversion{
		Realm:           "orbtr",
		KnownResources:  []string{"held", "open"},
		ActionWildcards: map[string][]string{"held": {"read", "write"}},
	}
	allows := func(scopes []string, capability string) bool {
		t.Helper()
		want, err := ParseCapability(capability)
		if err != nil {
			t.Fatal(err)
		}
		return NewCapabilitySet(c.ScopesToCapabilities(scopes)...).Allows(want)
	}
	for _, scopes := range [][]string{{"orbtr.held.*"}, {"orbtr.*"}, {"*"}} {
		for _, ok := range []string{"orbtr:held.read", "orbtr:held.write", "orbtr:held.write(x)"} {
			if !allows(scopes, ok) {
				t.Errorf("%v must reach %s", scopes, ok)
			}
		}
		for _, no := range []string{"orbtr:held.hold", "orbtr:held.hold(x)"} {
			if allows(scopes, no) {
				t.Errorf("%v reached %s, an action no wildcard confers", scopes, no)
			}
		}
	}
	if !allows([]string{"orbtr.*"}, "orbtr:open.anything") {
		t.Error("orbtr.* must still reach an unlisted resource's every action")
	}
	if !allows([]string{"orbtr.held.hold"}, "orbtr:held.hold") {
		t.Error("a grant naming the action must still reach it")
	}
	if allows([]string{"orbtr.held.hold", "-orbtr.held.*"}, "orbtr:held.hold") {
		t.Error("a deny of the listed resource's wildcard must keep its wildcard")
	}
}
