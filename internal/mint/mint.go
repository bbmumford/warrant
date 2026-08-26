// Package mint is the UNFORGEABLE-provenance root of warrant (plan §16.1, closing
// risk R-2399 #1). VerifiedPrincipal lives here with the ONLY constructor that sets
// verified=true (Mint). Because this package is under internal/, only warrant's own
// packages (the edge adapter) can import it — an external module (a cortex/io handler
// package) gets a COMPILE ERROR if it tries to import mint, so it cannot call Mint.
// And because VerifiedPrincipal's fields are unexported, no external struct literal can
// set verified=true either. Forgery is therefore a package-boundary impossibility, not
// a convention. (The external-package forgery test proves both legs.)
package mint

// SubjectKind is scope-agnostic: the neutral module bakes in NO product allowlist.
// Consumers use their own kinds (cortex user/service; io device/mesh_peer). Validity
// is "non-empty", enforced at the authority seam, not a fixed enum here.
type SubjectKind string

// Subject is the authenticated actor. Who, not what-they-may-do.
type Subject struct {
	ID   string
	Kind SubjectKind
}

// VerifiedPrincipal is opaque proof of authentication. All fields unexported; the only
// way verified becomes true is Mint. External packages can construct only a zero value
// (verified=false), which the authority seam denies.
type VerifiedPrincipal struct {
	verified       bool
	subject        Subject
	platformTenant string            // axis 1: admission fact ("orbtr"); NOT a partition, NOT authority
	claims         map[string]string // defensively copied at mint; owner is a SEALED claim read by key
}

// Mint turns a completed authentication into a VerifiedPrincipal. Called ONLY by
// warrant's trusted edge adapter (same-module, may import internal/mint) after real
// verification — never by a handler package. Claims are defensively copied so a later
// caller mutation cannot alter the sealed evidence.
func Mint(subject Subject, platformTenant string, claims map[string]string) VerifiedPrincipal {
	cp := make(map[string]string, len(claims))
	for k, v := range claims {
		cp[k] = v
	}
	return VerifiedPrincipal{verified: true, subject: subject, platformTenant: platformTenant, claims: cp}
}

// Read-only accessors — the authority seam reads provenance through these; there is no
// exported setter, so a value obtained by a handler cannot be mutated into authority.

func (p VerifiedPrincipal) Verified() bool         { return p.verified }
func (p VerifiedPrincipal) Subject() Subject       { return p.subject }
func (p VerifiedPrincipal) PlatformTenant() string { return p.platformTenant }

// Claim reads a SEALED claim by key. ok=false for an absent key (the authority seam
// treats absent as deny for an owner-bound route). A handler cannot inject claims.
func (p VerifiedPrincipal) Claim(k string) (string, bool) {
	v, ok := p.claims[k]
	return v, ok
}
