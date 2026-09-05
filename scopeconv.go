/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package warrant

import "strings"

// ScopeConversion describes how one realm's dotted RBAC scope strings become
// capabilities. A consumer supplies its own realm and resource vocabulary; this
// package supplies neither, so it never learns what any realm contains.
type ScopeConversion struct {
	// Realm is the capability realm these scopes belong to, e.g. "orbtr.ai".
	// A scope not prefixed with it converts to nothing.
	Realm string

	// KnownResources is the resource vocabulary a realm-wide wildcard expands
	// across. It is the ONLY thing that gives "<realm>.*" meaning, because a
	// capability has no resource-level wildcard — see ScopesToCapabilities.
	// A resource absent here is simply not granted: incomplete vocabulary
	// under-grants, it never over-grants.
	KnownResources []string

	// Reserved names resources a scope may NEVER mint into, however broad the
	// grant. They are conferred only by a direct, narrow mint. A realm-wide
	// wildcard skips them, and naming one explicitly converts to nothing, so
	// there is no scope path to a reserved family at all.
	Reserved map[string]struct{}
}

// ScopesToCapabilities converts held RBAC scope strings into the capabilities
// they confer, applying DENY SUBTRACTION: a scope prefixed "-" removes what it
// covers from the result, so a broad grant minus specific revocations —
// {"<realm>.*", "-<realm>.exec.run_as"} — yields the wildcard's capabilities
// without the revoked one.
//
// Subtracting here is equivalent to evaluating deny-precedence later, and it
// composes with it: the returned set contains no denied capability, so a plain
// CapabilitySet.Allows reaches the same verdict as a deny-aware one. Converting
// EARLY is preferable because it keeps the deny decision next to the vocabulary
// that gives a wildcard meaning.
//
// Every unrecognised shape converts to NOTHING rather than to something
// permissive: a scope outside the realm, a bare resource with no action, a
// deeper per-instance path, an empty segment, or a reserved resource. The
// failure direction is always under-granting.
func (c ScopeConversion) ScopesToCapabilities(scopes []string) []Capability {
	grants := map[string]struct{}{}
	denies := map[string]struct{}{}
	for _, s := range scopes {
		target := grants
		if strings.HasPrefix(s, "-") {
			s = s[1:]
			target = denies
		}
		for _, cap := range c.expand(s) {
			target[cap] = struct{}{}
		}
	}

	out := make([]Capability, 0, len(grants))
	for raw := range grants {
		if _, denied := denies[raw]; denied {
			continue
		}
		if cap, err := ParseCapability(raw); err == nil {
			out = append(out, cap)
		}
	}
	return out
}

// expand turns one positive scope into the capability strings it confers.
func (c ScopeConversion) expand(scope string) []string {
	// A realm-wide grant. A capability wildcards the ACTION only, so there is no
	// single capability meaning "everything in this realm" — it has to expand
	// across the known vocabulary here, which is why KnownResources exists.
	if scope == "*" || scope == c.Realm+".*" {
		out := make([]string, 0, len(c.KnownResources))
		for _, r := range c.KnownResources {
			if _, reserved := c.Reserved[r]; reserved {
				continue
			}
			out = append(out, c.Realm+":"+r+".*")
		}
		return out
	}

	rest := strings.TrimPrefix(scope, c.Realm+".")
	if rest == scope {
		return nil // another realm's scope confers nothing here
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		// A bare resource grants no action; a 3+ segment path is a
		// per-instance grant a capability cannot express. Both confer nothing.
		return nil
	}
	resource, action := parts[0], parts[1]
	if resource == "" || resource == "*" || action == "" {
		return nil
	}
	if _, reserved := c.Reserved[resource]; reserved {
		return nil
	}
	// action may be "*" — that IS expressible, as an action-wildcard capability.
	return []string{c.Realm + ":" + resource + "." + action}
}
