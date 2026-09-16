package warrant

import "strings"

// OrphanedDenies returns the deny scopes in scopes that expand to NO capability
// under this conversion, exactly as stored (leading "-" kept).
//
// ScopesToCapabilities drops such a deny silently: expandDeny returns nothing and
// the loop moves on, so a revocation that no longer applies is indistinguishable
// in the output from one that was never written. This reports them instead of
// converting them, because the two reasons a deny expands to nothing cannot be
// told apart from the result:
//
//   - the deny belongs to another realm, which is correct and intended — a
//     multi-realm store legitimately holds denies this conversion must ignore;
//   - the deny was written under a realm spelling that has since changed, so a
//     revocation that used to apply now silently applies to nothing.
//
// The second is a fail-open: the capability the deny was protecting against
// stays granted, nothing errors, and no test that asserts on the converted
// output can see it, because the deny is simply absent from that output.
//
// It is a reporter rather than a refusal on purpose. Making a realm miss an
// error would break the first case, which expandDeny's own contract requires. The
// behaviour is right; what is missing is the ability to ask. A realm rename uses
// this to assert its own work: convert the stored denies under the new realm and
// require the result to be empty before the rename is called done.
func (c ScopeConversion) OrphanedDenies(scopes []string) []string {
	var orphaned []string
	for _, s := range scopes {
		rest, isDeny := strings.CutPrefix(s, "-")
		if !isDeny {
			continue
		}
		if len(c.expandDeny(rest)) == 0 {
			orphaned = append(orphaned, s)
		}
	}
	return orphaned
}
