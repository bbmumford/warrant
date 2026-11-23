/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import "strings"

// MaxCapabilitiesPerSet bounds one held set. Authorize parses the sealed set on every
// request and CapabilitySet.Allows scans it twice per decision — once for denies, once
// for grants — so the length of the set is per-request work the minting edge would
// otherwise choose without a ceiling.
//
// It sits far above any enumerated holding: the broadest set a subject can be given is
// every resource of its realm at every action, plus the denies written against it, and
// a resource carries a handful of actions. A set past this length is a minting fault,
// and it is refused whole rather than truncated: truncation decides which elements
// survive, and the element it drops may be a deny, so a truncated set confers what the
// dropped deny withholds.
const MaxCapabilitiesPerSet = 512

// ParseHeldSet parses a sealed held set WHOLE. Every element must parse as a
// capability, the set must be within MaxCapabilitiesPerSet, and, when realm is
// non-empty, every element must name that realm. Any one failure returns ErrDenied and
// no set at all, so a caller never holds a partial reading of what was sealed.
//
// Whole-set refusal rather than skipping the element that does not parse, because that
// element may be a deny: a set holding a mistyped "-orbtr:token.mint" beside
// "orbtr:token.*" would confer token.mint through the wildcard, and the one thing the
// set did not carry would be the refusal the typo asked for. A refused set denies every
// requirement, which is the direction a misspelling may fail in.
//
// Authorize calls it for the capabilities the Verifier sealed, with the principal's own
// realm, so no cross-realm element reaches a decision. A judge reading the capabilities
// off a minted principal calls it with an empty realm when the principal legitimately
// holds more than one realm's capabilities and the judge compares realms itself through
// Allows. A grant list that mixes capabilities with another vocabulary's dotted strings
// is ParseGrantSet's, not this function's.
func ParseHeldSet(held []string, realm string) (CapabilitySet, error) {
	if len(held) > MaxCapabilitiesPerSet {
		return CapabilitySet{}, ErrDenied
	}
	caps := make([]Capability, 0, len(held))
	for _, s := range held {
		c, err := ParseCapability(s)
		if err != nil || (realm != "" && c.Realm() != realm) {
			return CapabilitySet{}, ErrDenied
		}
		caps = append(caps, c)
	}
	return NewCapabilitySet(caps...), nil
}

// ParseGrantSet reads the capability elements out of a grant list that carries two
// vocabularies at once — capabilities, which name their realm before a colon, and the
// dotted scope strings ScopeConversion reads — and returns the capabilities in realm.
//
// It is whole-set over what it owns. An element naming a realm before a colon is a
// capability and must parse; one that does not parse refuses the whole set, for the
// reason ParseHeldSet gives. An element with no colon is the dotted vocabulary's and no
// element of this set: a judge whose realm converts that vocabulary reads it through
// ScopeConversion, and refusing on it here would deny every caller whose grant list
// carries both at once.
//
// Leaving an element out here does not make it read elsewhere. ScopesToCapabilities
// widens a dotted deny it cannot express exactly, but it emits only widened forms
// ParseCapability accepts, and its realm-prefix cut reads nothing spelled in capability
// form; a realm whose grants are minted as capabilities rather than converted runs no
// conversion over the list at all. So a deny that has to bind must be spelled as a
// capability, where this function requires it to parse.
//
// MaxCapabilitiesPerSet bounds the whole list, dotted elements included, because the loop
// walks every element whichever vocabulary it belongs to.
//
// A well-formed capability of another realm is left out rather than refused. A
// principal holds capabilities of more than one realm at once, each realm's judge
// answers for its own realm, and realms do not subsume, so an element outside realm can
// neither satisfy nor spoil a requirement here.
//
// realm must be non-empty: an empty realm would make every held capability this judge's
// own, including the ones another realm's judge decides.
func ParseGrantSet(grants []string, realm string) (CapabilitySet, error) {
	if realm == "" || len(grants) > MaxCapabilitiesPerSet {
		return CapabilitySet{}, ErrDenied
	}
	caps := make([]Capability, 0, len(grants))
	for _, g := range grants {
		if !strings.Contains(g, ":") {
			continue // no realm separator: the dotted vocabulary, not a capability
		}
		c, err := ParseCapability(g)
		if err != nil {
			return CapabilitySet{}, ErrDenied
		}
		if c.Realm() != realm {
			continue
		}
		caps = append(caps, c)
	}
	return NewCapabilitySet(caps...), nil
}
