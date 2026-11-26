/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import "testing"

// A stored deny whose own spelling the capability grammar refuses is widened, never dropped: under
// a realm-wide grant it still refuses what it names, and OrphanedDenies reports it so the stored
// scope can be corrected.
func TestADenyTheGrammarCannotReadIsWidenedAndReported(t *testing.T) {
	c := ScopeConversion{Realm: "orbtr", KnownResources: []string{"exec", "files"}}
	for deny, want := range map[string]struct{ refused, allowed []string }{
		"-orbtr.exec.approve(fs.delete)": {[]string{"orbtr:exec.approve", "orbtr:exec.approve(fs_delete)"}, []string{"orbtr:exec.run", "orbtr:files.approve"}},
		"-orbtr.Exec.approve":            {[]string{"orbtr:exec.approve", "orbtr:files.approve"}, []string{"orbtr:exec.run"}},
		"-orbtr.exec.Approve":            {[]string{"orbtr:exec.approve", "orbtr:exec.run"}, []string{"orbtr:files.approve"}},
	} {
		scopes := []string{"orbtr.*", deny}
		set := NewCapabilitySet(c.ScopesToCapabilities(scopes)...)
		for _, r := range want.refused {
			req, err := ParseCapability(r)
			if err != nil {
				t.Fatal(err)
			}
			if set.Allows(req) {
				t.Errorf("%q dropped: %s is still allowed", deny, r)
			}
		}
		// The widening reaches no further than the segment the grammar refused.
		for _, r := range want.allowed {
			req, err := ParseCapability(r)
			if err != nil {
				t.Fatal(err)
			}
			if !set.Allows(req) {
				t.Errorf("%q widened past what it names: %s is refused", deny, r)
			}
		}
		if got := c.OrphanedDenies(scopes); len(got) != 1 || got[0] != deny {
			t.Errorf("OrphanedDenies(%q) = %q, want the deny reported", deny, got)
		}
	}
	// A deny the grammar reads exactly is neither widened nor reported.
	scopes := []string{"orbtr.*", "-orbtr.exec.approve(fs_delete)"}
	set := NewCapabilitySet(c.ScopesToCapabilities(scopes)...)
	other, _ := ParseCapability("orbtr:exec.approve(net_open)")
	if !set.Allows(other) {
		t.Error("an exact parameter deny widened to every parameter")
	}
	if got := c.OrphanedDenies(scopes); len(got) != 0 {
		t.Errorf("OrphanedDenies reported an exact deny: %q", got)
	}
}
