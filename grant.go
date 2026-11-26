/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import (
	"fmt"
	"strings"
)

// GrantPolicy turns the capability strings a role or key is AUTHORED with into
// the set it actually confers. A consumer holds one per realm it grants in and
// calls Grant where it reads a stored grant out of storage; the result feeds
// NewCapabilitySet.
//
// NEVER APPLY IT TO A PRINCIPAL'S HELD CAPABILITIES. Held capabilities arrive on
// a VerifiedPrincipal that the edge minted from a completed authentication, and
// a minted principal MAY carry a reserved family — carrying one is what proves
// it was minted rather than granted, which is the whole property Reserved
// exists to create. Passing held capabilities through Grant strips exactly that
// capability, so the authority it was minted to confer silently stops applying
// and every test that does not mint a reserved family stays green. Grant reads
// what an author wrote; Authorize reads what a principal holds.
//
// It exists because an authored grant and a minted one are different acts with
// different trust. Mint is performed by the edge from a completed
// authentication, so what it seals is already server-established. An authored
// grant is a stored list somebody wrote, and the writer may be a partition's own
// administrator: roles are an open set, so a role authored there can name any
// capability it likes.
// Grant is the seam where that list stops being text and becomes authority, and
// it is the only place a reserved family can be refused before it is conferred.
type GrantPolicy struct {
	// Reserved names resources that NO authored grant may confer, however the
	// grant is written. They are carried only by a direct, narrow-at-issue mint,
	// so a principal holding one proves it was minted rather than granted — the
	// property an admission gate reads when it treats a capability as evidence
	// of provisioning rather than of a role.
	//
	// It constrains POSITIVE capabilities only. A deny naming a reserved
	// resource is kept, because withholding a revocation could only ever widen
	// access, and a grant list that revokes something it could not have granted
	// is harmless.
	Reserved map[string]struct{}
}

// Grant parses authored capability strings and returns what they confer.
//
// The returned set NEVER contains a positive capability naming a reserved
// resource, whether or not the caller inspects err. That is deliberate: a
// caller that logs the error and proceeds still does not confer the reserved
// family, so the guard does not depend on anyone handling a return value
// correctly. err reports every entry that was refused or unparseable, so a
// malformed role is loud as well as harmless.
//
// An unparseable entry is reported rather than silently dropped. An authored
// capability is a deliberate act, so a string that does not parse is a typo in a
// stored grant, and a role that quietly confers less than its author intended
// fails in a way nobody notices until someone is denied.
func (p GrantPolicy) Grant(authored []string) ([]Capability, error) {
	out := make([]Capability, 0, len(authored))
	var refused, malformed []string

	for _, s := range authored {
		c, err := ParseCapability(s)
		if err != nil {
			malformed = append(malformed, s)
			continue
		}
		if !c.IsDeny() {
			if _, reserved := p.Reserved[c.resource]; reserved {
				refused = append(refused, s)
				continue
			}
		}
		out = append(out, c)
	}

	return out, grantError(refused, malformed)
}

// grantError renders the two refusal kinds as one error, or nil when the grant
// list was wholly admitted. They are reported together because a caller reacts
// the same way to both — the grant is not what its author wrote — and separating
// them would invite handling one and not the other.
func grantError(refused, malformed []string) error {
	switch {
	case len(refused) == 0 && len(malformed) == 0:
		return nil
	case len(malformed) == 0:
		return fmt.Errorf("warrant: reserved resources are not grantable: %s", strings.Join(refused, ", "))
	case len(refused) == 0:
		return fmt.Errorf("warrant: unparseable capabilities in grant: %s", strings.Join(malformed, ", "))
	}
	return fmt.Errorf("warrant: reserved resources are not grantable: %s; unparseable capabilities in grant: %s",
		strings.Join(refused, ", "), strings.Join(malformed, ", "))
}
