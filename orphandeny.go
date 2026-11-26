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
//
// It also reports each deny ScopesToCapabilities could keep only by widening it past its own
// spelling (parseableDeny): a scope such as "-orbtr.exec.approve(fs.delete)" or "-orbtr.Exec.approve"
// still revokes, but more than it names, and only correcting the stored scope makes it revoke what
// it says.
func (c ScopeConversion) OrphanedDenies(scopes []string) []string {
	var orphaned []string
	for _, s := range scopes {
		rest, isDeny := strings.CutPrefix(s, "-")
		if !isDeny {
			continue
		}
		caps := c.expandDeny(rest)
		report := len(caps) == 0
		for _, cap := range caps {
			if _, widened, _ := c.parseableDeny(cap); widened {
				report = true
			}
		}
		if report {
			orphaned = append(orphaned, s)
		}
	}
	return orphaned
}
