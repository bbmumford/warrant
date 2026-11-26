/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import "testing"

// A capability whose realm begins with "-" is refused: a doubled deny marker would otherwise read
// as a deny in a realm named "-orbtr", which revokes nothing.
func TestARealmBeginningWithADashIsRefused(t *testing.T) {
	for _, s := range []string{"--orbtr:exec.run_as", "-orbtr:exec.run_as(-x)x", "-:exec.run_as", "---orbtr:exec.*"} {
		if c, err := ParseCapability(s); err == nil {
			t.Errorf("ParseCapability(%q) = %v (realm %q), want a refusal", s, c, c.Realm())
		}
	}
	if _, err := ParseCapability("-orbtr:exec.run_as"); err != nil {
		t.Errorf("a single-dash deny was refused: %v", err)
	}
	if _, err := ParseCapability("orbtr-x:exec.run_as"); err != nil {
		t.Errorf("a realm holding an inner dash was refused: %v", err)
	}
}
