// Package mint is the receiver-pinned seal root of warrant (plan §16.1). The security
// guarantee is NOT the internal/ path boundary — that boundary is defeatable, because Go
// internal visibility is import-path ancestry, so a module named under
// github.com/bbmumford/warrant/... can still import this package. The guarantee is the
// SECRET: a Verifier holds a per-instance secret from crypto/rand, Mint stamps a copy of
// it into the principal's seal, and only a Verifier holding the SAME secret verifies it.
// A nested-path forger can import mint and call NewVerifier()+Mint, but it stamps ITS OWN
// secret; the real host Authorizer (a different Verifier) denies it. internal/ remains only
// as defense-in-depth (sibling/external modules cannot even import), never as the root.
package mint

import (
	"crypto/rand"
	"crypto/subtle"
)

// SubjectKind is scope-agnostic: no product allowlist is baked in. Validity is "non-empty",
// enforced at the authority seam (cortex user/service; io device/mesh_peer both pass).
type SubjectKind string

// Subject is the authenticated actor. Who, not what-they-may-do.
type Subject struct {
	ID   string
	Kind SubjectKind
}

// Assertion is the sealed evidence the TRUSTED edge presents at mint, derived from a
// completed real authentication. Every field becomes receiver-verified at Authorize; none
// is caller-authored at authorize time. Owner is the sealed partition (org); HasOwner
// distinguishes an owner-bound principal from a global (owner-less) one.
type Assertion struct {
	Subject        Subject
	PlatformTenant string
	HasOwner       bool
	Owner          string
	Capabilities   []string
	Issuer         string
	Audience       string
	Version        string
	Realm          string
	ExpiresAtMS    int64
	Nonce          string
}

// VerifiedPrincipal is opaque sealed proof of authentication. The seal is a copy of the
// minting Verifier's secret; it has NO accessor and never leaves this package, so no
// consumer can read it or forge one by struct literal (all fields unexported). Every other
// field is exposed read-only for the authority seam.
type VerifiedPrincipal struct {
	seal      []byte
	subject   Subject
	tenant    string
	hasOwner  bool
	owner     string
	caps      []string
	issuer    string
	audience  string
	version   string
	realm     string
	expiresMS int64
	nonce     string
}

const secretLen = 32

// Verifier holds a per-instance secret generated at construction from crypto/rand. The
// trusted host creates ONE and shares it between the edge adapter (which Mints principals
// from real auth) and the Authorizer (which Verifies). The secret is never exported,
// serialized, logged, or accessible — the receiver-pinned root of trust.
type Verifier struct {
	secret []byte
}

// NewVerifier generates a fresh per-instance secret. Two Verifiers never share a secret,
// so a principal minted by one is denied by the other.
func NewVerifier() (*Verifier, error) {
	s := make([]byte, secretLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return &Verifier{secret: s}, nil
}

// Mint stamps a principal with THIS verifier's secret plus the sealed assertion (claims and
// capabilities defensively copied so a later caller mutation cannot alter sealed evidence).
// Only code holding this *Verifier can produce a principal this verifier accepts.
func (v *Verifier) Mint(a Assertion) VerifiedPrincipal {
	seal := make([]byte, len(v.secret))
	copy(seal, v.secret)
	caps := make([]string, len(a.Capabilities))
	copy(caps, a.Capabilities)
	return VerifiedPrincipal{
		seal:      seal,
		subject:   a.Subject,
		tenant:    a.PlatformTenant,
		hasOwner:  a.HasOwner,
		owner:     a.Owner,
		caps:      caps,
		issuer:    a.Issuer,
		audience:  a.Audience,
		version:   a.Version,
		realm:     a.Realm,
		expiresMS: a.ExpiresAtMS,
		nonce:     a.Nonce,
	}
}

// Verify reports whether p was sealed by THIS verifier, using a CONSTANT-TIME comparison
// (R-2411 pin 4). A principal minted by any other Verifier — including a nested-path
// forger's own — fails, as does a zero-value principal (empty seal). This is the whole
// forgery closure: it depends on the secret, not on who could import this package.
func (v *Verifier) Verify(p VerifiedPrincipal) bool {
	if len(v.secret) != secretLen || len(p.seal) != secretLen {
		return false
	}
	return subtle.ConstantTimeCompare(p.seal, v.secret) == 1
}

// Read-only accessors. There is deliberately NO seal accessor and NO exported setter, so a
// principal a handler holds cannot be read for its secret nor mutated into a different one.

func (p VerifiedPrincipal) Subject() Subject       { return p.subject }
func (p VerifiedPrincipal) PlatformTenant() string { return p.tenant }
func (p VerifiedPrincipal) HasOwner() bool         { return p.hasOwner }
func (p VerifiedPrincipal) Owner() string          { return p.owner }

// Capabilities returns a defensive copy of the SEALED effective grants (edge-derived). The
// authority seam parses + matches against these; a consumer cannot add to them.
func (p VerifiedPrincipal) Capabilities() []string {
	out := make([]string, len(p.caps))
	copy(out, p.caps)
	return out
}

func (p VerifiedPrincipal) Issuer() string     { return p.issuer }
func (p VerifiedPrincipal) Audience() string    { return p.audience }
func (p VerifiedPrincipal) Version() string     { return p.version }
func (p VerifiedPrincipal) Realm() string       { return p.realm }
func (p VerifiedPrincipal) ExpiresAtMS() int64  { return p.expiresMS }
func (p VerifiedPrincipal) Nonce() string       { return p.nonce }
