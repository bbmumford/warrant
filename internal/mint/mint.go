// Package mint is the receiver-pinned seal root of warrant. Authenticity is a MAC,
// not a copied secret: a Verifier holds a per-instance HMAC key (crypto/rand), Mint stamps the
// principal with a TAG = HMAC(key, canonical(assertion)), and Verify recomputes the tag with the
// key and compares it in constant time. The KEY NEVER ENTERS A PRINCIPAL — a principal carries
// only the tag (a MAC output over public assertion fields) plus those fields, so reflecting/
// logging a principal (fmt %#v) discloses no key material and enables no forgery (forging a new
// assertion's tag requires the key, held only by the Verifier). This closes the secret-custody
// hole where a copied key leaked through ordinary formatting.
package mint

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// ErrMint is returned by Mint when the assertion is invalid at mint time (inconsistent partition
// representation, or an empty subject) — the trusted edge must not seal an inconsistent bundle.
var ErrMint = errors.New("mint: invalid assertion")

// Domain separation + versioning for the MAC input: the tag authenticates THIS assertion schema
// at THIS version, so a tag can never be reused across a different context or a future format.
const (
	canonicalContext = "warrant.assertion"
	canonicalVersion = uint64(1)
)

// SubjectKind is scope-agnostic: no product allowlist baked in.
type SubjectKind string

// Subject is the authenticated actor.
type Subject struct {
	ID   string
	Kind SubjectKind
}

// Assertion is the sealed evidence the trusted edge presents at mint. Partition is the opaque
// partition id; HasPartition distinguishes partition-bound from global. Consistency invariant:
// HasPartition must equal (Partition != "") — enforced by Consistent().
type Assertion struct {
	Subject      Subject
	Deployment   string
	HasPartition bool
	Partition    string
	Capabilities []string
	Issuer       string
	Audience     string
	Version      string
	Realm        string
	ExpiresAtMS  int64
	Nonce        string
}

// Consistent reports whether HasPartition agrees with Partition presence. The authority seam denies an
// inconsistent assertion (partition material on a would-be global, or a claimed partition with no value).
func (a Assertion) Consistent() bool { return a.HasPartition == (a.Partition != "") }

// VerifiedPrincipal is opaque proof. It carries the assertion fields plus the MAC tag — NOT the
// key. All fields unexported; there is no exported setter, and no accessor exposes the key
// (there is no key here to expose). Verifying requires the Verifier that holds the key.
type VerifiedPrincipal struct {
	subject      Subject
	deployment   string
	hasPartition bool
	partition    string
	caps         []string
	issuer       string
	audience     string
	version      string
	realm        string
	expiresMS    int64
	nonce        string
	tag          []byte // HMAC(key, canonical(assertion)); a non-secret MAC output, never the key
}

const keyLen = 32

// Verifier holds the per-instance HMAC key. The trusted host creates ONE and shares it between
// its authentication edge (Mint) and its Authorizer (Verify). The key is never exported,
// serialized, logged, or copied into a principal.
type Verifier struct {
	key []byte
}

// NewVerifier generates a fresh per-instance HMAC key.
func NewVerifier() (*Verifier, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &Verifier{key: k}, nil
}

// Mint stamps a principal with tag = HMAC(key, canonical(assertion)). It validates the assertion
// at mint time (partition-representation consistency + non-empty subject) and returns ErrMint on an
// invalid bundle, so the trusted edge cannot seal an inconsistent one. Claims/caps are defensively
// copied. The key is not stored in the principal.
func (v *Verifier) Mint(a Assertion) (VerifiedPrincipal, error) {
	if !a.Consistent() || a.Subject.ID == "" || a.Subject.Kind == "" {
		return VerifiedPrincipal{}, ErrMint
	}
	caps := make([]string, len(a.Capabilities))
	copy(caps, a.Capabilities)
	p := VerifiedPrincipal{
		subject:      a.Subject,
		deployment:   a.Deployment,
		hasPartition: a.HasPartition,
		partition:    a.Partition,
		caps:         caps,
		issuer:       a.Issuer,
		audience:     a.Audience,
		version:      a.Version,
		realm:        a.Realm,
		expiresMS:    a.ExpiresAtMS,
		nonce:        a.Nonce,
	}
	p.tag = v.mac(p.assertion())
	return p, nil
}

// GoString and String redact the key on the VALUE receiver (so both Verifier and *Verifier, and a
// dereferenced copy, redact) — ordinary formatting/logging discloses no minting material.
func (v Verifier) GoString() string { return "mint.Verifier{key:(redacted)}" }
func (v Verifier) String() string   { return "mint.Verifier{redacted}" }

// Verify recomputes the tag over the principal's fields with the Verifier's key and compares it
// in constant time. A principal minted by any other Verifier — or a zero value (nil tag) — fails.
func (v *Verifier) Verify(p VerifiedPrincipal) bool {
	if len(v.key) != keyLen || len(p.tag) != sha256.Size {
		return false
	}
	expected := v.mac(p.assertion())
	return subtle.ConstantTimeCompare(expected, p.tag) == 1
}

func (v *Verifier) mac(a Assertion) []byte {
	m := hmac.New(sha256.New, v.key)
	m.Write(canonical(a))
	return m.Sum(nil)
}

// assertion rebuilds the Assertion from the principal's fields (for tag recomputation).
func (p VerifiedPrincipal) assertion() Assertion {
	caps := make([]string, len(p.caps))
	copy(caps, p.caps)
	return Assertion{
		Subject: p.subject, Deployment: p.deployment, HasPartition: p.hasPartition, Partition: p.partition,
		Capabilities: caps, Issuer: p.issuer, Audience: p.audience, Version: p.version,
		Realm: p.realm, ExpiresAtMS: p.expiresMS, Nonce: p.nonce,
	}
}

// canonical is a deterministic, UNAMBIGUOUS length-prefixed encoding of every authority-bearing
// field, so the tag covers the whole assertion and no two distinct assertions collide (no
// delimiter ambiguity). Any field change invalidates the tag.
func canonical(a Assertion) []byte {
	var b bytes.Buffer
	writeStr(&b, canonicalContext)  // domain separation
	writeUint(&b, canonicalVersion) // schema version
	writeStr(&b, string(a.Subject.Kind))
	writeStr(&b, a.Subject.ID)
	writeStr(&b, a.Deployment)
	if a.HasPartition {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	writeStr(&b, a.Partition)
	writeUint(&b, uint64(len(a.Capabilities)))
	for _, c := range a.Capabilities {
		writeStr(&b, c)
	}
	writeStr(&b, a.Issuer)
	writeStr(&b, a.Audience)
	writeStr(&b, a.Version)
	writeStr(&b, a.Realm)
	writeUint(&b, uint64(a.ExpiresAtMS))
	writeStr(&b, a.Nonce)
	return b.Bytes()
}

func writeStr(b *bytes.Buffer, s string) {
	writeUint(b, uint64(len(s)))
	b.WriteString(s)
}

func writeUint(b *bytes.Buffer, n uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	b.Write(buf[:])
}

// Read-only accessors. There is NO tag accessor and NO key anywhere in the principal, so a value
// a handler holds discloses no minting material.
func (p VerifiedPrincipal) Subject() Subject   { return p.subject }
func (p VerifiedPrincipal) Deployment() string { return p.deployment }
func (p VerifiedPrincipal) HasPartition() bool { return p.hasPartition }
func (p VerifiedPrincipal) Partition() string  { return p.partition }

func (p VerifiedPrincipal) Capabilities() []string {
	out := make([]string, len(p.caps))
	copy(out, p.caps)
	return out
}

func (p VerifiedPrincipal) Issuer() string     { return p.issuer }
func (p VerifiedPrincipal) Audience() string   { return p.audience }
func (p VerifiedPrincipal) Version() string    { return p.version }
func (p VerifiedPrincipal) Realm() string      { return p.realm }
func (p VerifiedPrincipal) ExpiresAtMS() int64 { return p.expiresMS }
func (p VerifiedPrincipal) Nonce() string      { return p.nonce }
