/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package warrant

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
)

// GrammarVersion names the capability grammar ParseCapability implements: the shape
// ["-"] realm ":" resource "." action, the token character set, the token length bound,
// and the one position a resource wildcard may stand in. A trust entry declares the
// grammar its realm's sets are written in (RealmTrust.GrammarVersion) and NewAuthorizer
// refuses an entry naming any other, so a set written under a grammar this build does
// not implement is refused whole instead of being read element by element under rules
// that are not the ones it was written to. The element whose meaning moves between
// grammars is a deny, and a deny read under the wrong rules withholds nothing.
//
// An entry that declares no grammar is read at this one: the grammar an entry does not
// name is the grammar its receiver implements, and only a declaration naming a
// different grammar is refused.
const GrammarVersion = "1"

// grammarVersion is the grammar an entry's sets are read under: what it declares, or
// GrammarVersion when it declares nothing. policyIdentityDigest and policyIdentityValid
// both read it, so a declared and an undeclared entry of the same realm digest alike.
func (rt RealmTrust) grammarVersion() string {
	if rt.GrammarVersion == "" {
		return GrammarVersion
	}
	return rt.GrammarVersion
}

// policyIdentityDigest is the value RealmTrust.PolicyDigest carries: a sha256 over the
// realm's policy identity — realm, issuer, audience, policy version, grammar version —
// length-prefixed per field so no two identities digest alike by running their fields
// together.
//
// It is one value standing for the whole identity. NewAuthorizer binds it per realm and
// trustAccepts compares the identity a sealed assertion presents against the bound
// value, so a principal sealed under another issuer, audience, policy version or
// grammar is refused on one comparison that cannot be passed by a field a later reader
// forgets to compare.
func (rt RealmTrust) policyIdentityDigest() string {
	var b []byte
	var n [8]byte
	for _, field := range []string{rt.Realm, rt.Issuer, rt.Audience, rt.PolicyVersion, rt.grammarVersion()} {
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		b = append(b, n[:]...)
		b = append(b, field...)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// policyIdentityValid reports whether an entry's declared grammar and digest can be
// trusted. The grammar must be the one ParseCapability implements, because a set written
// under another grammar cannot be read here at all. A declared digest must be the digest
// over the entry's own fields, so an entry whose ratified digest and ratified fields
// disagree is refused where the Authorizer is built rather than denying every request
// once it serves. RealmTrust.valid calls it, so every path that validates an entry
// validates these two.
//
// Declaring a digest is optional; declaring a wrong one is not. An entry that declares
// none is bound to the digest over its own fields by pinned.
func (rt RealmTrust) policyIdentityValid() bool {
	if rt.grammarVersion() != GrammarVersion {
		return false
	}
	return rt.PolicyDigest == "" || rt.PolicyDigest == rt.policyIdentityDigest()
}

// pinned returns the entry with its grammar version and policy digest written out, so
// every entry in the Authorizer's trust map carries the value trustAccepts compares and
// none of them is read at a default while it is being compared.
func (rt RealmTrust) pinned() RealmTrust {
	rt.GrammarVersion = rt.grammarVersion()
	rt.PolicyDigest = rt.policyIdentityDigest()
	return rt
}

// policyMatches reports whether the policy identity p presents digests to the value
// bound on this entry, compared in constant time. It is what trustAccepts asks instead
// of comparing issuer, audience and policy version one by one, and it binds the grammar
// version into the same comparison, so a receiver implementing one grammar cannot accept
// a set a realm issued under another.
//
// An entry whose digest was never bound compares as a different length and denies, so a
// trust entry that reached a decision without passing through pinned authorizes nothing.
func (rt RealmTrust) policyMatches(p VerifiedPrincipal) bool {
	presented := RealmTrust{
		Realm:          p.Realm(),
		Issuer:         p.Issuer(),
		Audience:       p.Audience(),
		PolicyVersion:  p.Version(),
		GrammarVersion: rt.grammarVersion(),
	}.policyIdentityDigest()
	return subtle.ConstantTimeCompare([]byte(rt.PolicyDigest), []byte(presented)) == 1
}

// pinnedTrust builds the Authorizer's trust map from the home entry and the foreign
// ones: it validates every entry, refuses a foreign entry that takes the home realm,
// names another audience or repeats a realm already present, and binds each entry's
// policy digest, so the value every later decision compares against is fixed where the
// Authorizer is constructed and no later change to a caller's copy of an entry moves it.
//
// NewAuthorizer is its one caller and returns ErrDenied on any refusal, which is why
// nothing here distinguishes the reasons.
func pinnedTrust(home RealmTrust, foreign []RealmTrust) (map[string]RealmTrust, error) {
	if !home.valid() {
		return nil, ErrDenied
	}
	trust := map[string]RealmTrust{home.Realm: home.pinned()}
	for _, e := range foreign {
		if !e.valid() || e.Realm == home.Realm || e.Audience != home.Audience {
			return nil, ErrDenied
		}
		if _, dup := trust[e.Realm]; dup {
			return nil, ErrDenied
		}
		trust[e.Realm] = e.pinned()
	}
	return trust, nil
}
