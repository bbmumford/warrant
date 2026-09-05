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
	//
	// The remainder after trimming it must be exactly <resource>.<action>, so
	// the realm has to be set to the FULL namespace root the scopes are built
	// on: scopes shaped "orbtr.io.storage.token.mint" need Realm
	// "orbtr.io.storage", not "orbtr.io".
	Realm string

	// KnownResources is the resource vocabulary a realm-wide wildcard expands
	// across. It is the ONLY thing that gives "<realm>.*" meaning, because a
	// capability has no resource-level wildcard — see ScopesToCapabilities.
	// A resource absent here is simply not granted: incomplete vocabulary
	// under-grants, it never over-grants.
	//
	// It bounds GRANTS ONLY. Revocations never consult it, so a resource missing
	// from this list cannot escape a revocation that covers it.
	KnownResources []string

	// Reserved names resources a scope may NEVER mint into, however broad the
	// grant. They are conferred only by a direct, narrow mint. A realm-wide
	// wildcard skips them, and naming one explicitly converts to nothing, so
	// there is no scope path to a reserved family at all.
	//
	// Reserved constrains GRANTS only. A deny naming a reserved resource is
	// still emitted: withholding it could only ever widen access.
	Reserved map[string]struct{}
}

// ScopesToCapabilities converts held RBAC scope strings into the capabilities
// they confer. A scope prefixed "-" is a revocation and is emitted as a
// NEGATIVE capability, which CapabilitySet.Allows refuses through — including
// through a positive terminal "*" that would otherwise cover it.
//
// THE RETURNED SLICE CONTAINS DENIES. Interpret it only by building a
// CapabilitySet and calling Allows; iterating it and treating any match as a
// grant reads every revocation as its opposite.
//
// A deny is NOT applied by removing the grants it matches. Subtraction can only
// remove a capability string that is present, and the two are routinely at
// different granularity: "<realm>.*" emits "token.*", so a deny of "token.mint"
// matches no emitted string, disappears, and the wildcard keeps conferring mint.
// Emitting the deny instead puts it where the wildcard cannot outrun it.
//
// The two directions are deliberately NOT symmetric, because their failure modes
// are not symmetric:
//
//   - An unrecognised GRANT converts to nothing. A scope outside the realm, a
//     bare resource with no action, a deeper per-instance path, an empty
//     segment, or a reserved resource confers no capability.
//   - An unrecognised DENY is WIDENED to the nearest capability that CAN be
//     expressed, never dropped. A per-instance revocation
//     "-<realm>.exec.run_as.system" has no capability-grammar form, so it is
//     emitted as a deny of "exec.run_as" entirely; a deny naming no single
//     resource is emitted against every KnownResources entry.
//
// So both directions fail toward less access. That also decides where the
// failure shows up: an over-broad deny breaks a legitimate call and fails a
// test, while a dropped deny leaves a live privilege escalation that builds and
// tests green. Only the first is recoverable by reading a test failure.
//
// A deny outside the realm is still ignored — it revokes nothing here because
// nothing here is in its realm.
func (c ScopeConversion) ScopesToCapabilities(scopes []string) []Capability {
	seen := map[string]struct{}{}
	out := make([]Capability, 0, len(scopes))
	add := func(raw string) {
		if _, dup := seen[raw]; dup {
			return
		}
		seen[raw] = struct{}{}
		if cap, err := ParseCapability(raw); err == nil {
			out = append(out, cap)
		}
	}

	for _, s := range scopes {
		if rest, isDeny := strings.CutPrefix(s, "-"); isDeny {
			for _, cap := range c.expandDeny(rest) {
				add("-" + cap)
			}
			continue
		}
		for _, cap := range c.expand(s) {
			add(cap)
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
		return c.everyResource("*")
	}

	resource, action, ok := c.split(scope)
	if !ok {
		// A bare resource grants no action; a 3+ segment path is a
		// per-instance grant a capability cannot express. Both confer nothing.
		return nil
	}
	if resource == "" || resource == "*" || action == "" {
		return nil
	}
	if _, reserved := c.Reserved[resource]; reserved {
		return nil
	}
	// action may be "*" — that IS expressible, as an action-wildcard capability.
	return []string{c.Realm + ":" + resource + "." + action}
}

// expandDeny turns one revocation into the capability strings it revokes,
// widening rather than dropping whenever the scope names something the
// capability grammar cannot express exactly. Every path either returns
// capabilities or belongs to another realm.
func (c ScopeConversion) expandDeny(scope string) []string {
	// A realm-wide revocation is emitted as ONE resource-wildcard capability rather than
	// expanded across KnownResources. Expanding it would make the revocation only as
	// complete as the caller's vocabulary: a resource the consumer forgot to list would
	// survive a deny that names the entire realm, which fails OPEN — the one direction
	// nothing here is allowed to fail in.
	if scope == "*" || scope == c.Realm+".*" {
		return []string{c.Realm + ":*.*"}
	}

	rest, ok := strings.CutPrefix(scope, c.Realm+".")
	if !ok {
		return nil // another realm's deny revokes nothing here
	}
	parts := strings.Split(rest, ".")

	// A bare resource names no action, so it revokes the whole resource.
	if len(parts) == 1 {
		if parts[0] == "" {
			return nil
		}
		if parts[0] == "*" {
			return []string{c.Realm + ":*.*"}
		}
		return []string{c.Realm + ":" + parts[0] + ".*"}
	}

	// Anything deeper than resource.action is a per-instance revocation with no
	// capability form. Widen to the resource.action prefix that does have one:
	// denying every instance is broader than intended and narrower than nothing.
	//
	// TODO: a role whose grant is "everything on this resource MINUS one
	// instance" cannot be expressed once its resource is in KnownResources —
	// widening revokes the action outright and takes the rest of the instances
	// with it. Reaching that point means Capability needs a fourth segment, not
	// that this widening should be relaxed. Until a resource in some consumer's
	// vocabulary carries such a revocation, the widened deny is inert: nothing
	// emits a capability for a resource nobody routes.
	resource, action := parts[0], parts[1]
	if action == "" {
		action = "*"
	}
	if resource == "" || resource == "*" {
		// No single resource is named, so the revocation lands on every resource in the
		// realm — expressed as a wildcard, not enumerated, for the reason above.
		return []string{c.Realm + ":*." + action}
	}
	return []string{c.Realm + ":" + resource + "." + action}
}

// everyResource emits one grant per known resource at the given action, skipping
// reserved ones. Only the GRANT path enumerates: a realm-wide grant has to name
// each resource because a positive capability has no resource wildcard, and an
// incomplete vocabulary there merely under-grants. Revocations use the wildcard
// instead, so a forgotten resource cannot escape them.
func (c ScopeConversion) everyResource(action string) []string {
	out := make([]string, 0, len(c.KnownResources))
	for _, r := range c.KnownResources {
		if _, reserved := c.Reserved[r]; reserved {
			continue
		}
		out = append(out, c.Realm+":"+r+"."+action)
	}
	return out
}

// split trims the realm and requires the remainder to be exactly
// <resource>.<action>.
func (c ScopeConversion) split(scope string) (resource, action string, ok bool) {
	rest, ok := strings.CutPrefix(scope, c.Realm+".")
	if !ok {
		return "", "", false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
