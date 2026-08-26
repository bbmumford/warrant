// Package warrant is the scope-agnostic, receiver-pinned authority core for the ORBTR
// platform retirement (plan §16.1). Like loom it interprets NO axis itself; but the CORE —
// never a consumer — enforces every authority invariant, and authority is RECEIVER-
// VERIFIABLE at runtime, independent of caller-selected import path.
//
// The model (R-2407/R-2411): a trusted host builds ONE Verifier (a per-instance secret from
// crypto/rand) at boot and shares it between its authentication edge (which Mints principals
// from real auth) and its Authorizer (which Verifies). A forger — even a nested-path module
// that imports internal/mint — can mint, but stamps its OWN secret, and the real Authorizer
// denies it. The Authorizer is constructed once with pinned trust, an immutable route table
// keyed by server operation identity, its own clock, and replay state; Authorize accepts NO
// caller-supplied clock, nonce, trust, capability, or route authority.
//
// THREAT-MODEL SCOPE: this defeats path-based forgery, public-API injection, and caller-
// supplied-authority. It does NOT defend against a same-process module using unsafe/reflect
// to read the secret from memory — a fundamental Go limitation, explicitly out of scope;
// warrant's consumers are first-party endpoint code.
package warrant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/warrant/internal/mint"
)

// ErrDenied is the SINGLE non-disclosing deny. Every failure — forged/unverified seal, wrong
// platform tenant, unknown operation, untrusted/expired assertion, realm mismatch, absent or
// mismatched owner, unmet capability, replayed nonce, nil seam, malformed grammar — surfaces
// as this, so a refusal never discloses which leg failed.
var ErrDenied = errors.New("authorization denied")

// Re-exported from internal/mint. The types are usable by consumers; Mint (a Verifier method)
// and the seal live in internal/mint, and the seal has no accessor, so no consumer can read
// or forge a valid seal through this API.
type (
	VerifiedPrincipal = mint.VerifiedPrincipal
	Subject           = mint.Subject
	SubjectKind       = mint.SubjectKind
	Assertion         = mint.Assertion
	Verifier          = mint.Verifier
)

// NewVerifier builds the receiver-pinned Verifier. The trusted host calls this ONCE at boot
// and shares the returned *Verifier between its edge (Mint) and its Authorizer (NewAuthorizer).
func NewVerifier() (*Verifier, error) { return mint.NewVerifier() }

const maxTokenLen = 64

// ─────────────────────────────────────────────────────────────────────────────
// Canonical grammar. realm may contain "." (an RPC-namespace root, e.g. orbtr.ai) but never
// a leading/trailing/double dot; resource/action are single dotless segments; action may be
// a terminal "*".
// ─────────────────────────────────────────────────────────────────────────────

func validRealm(s string) bool {
	if s == "" || len(s) > maxTokenLen {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validSegment(label, false) {
			return false
		}
	}
	return true
}

func validSegment(s string, allowWildcard bool) bool {
	if allowWildcard && s == "*" {
		return true
	}
	if s == "" || len(s) > maxTokenLen {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validOwner(s string) bool { return validSegment(s, false) }

// Capability is realm-namespaced: "<realm>:<resource>.<action>". Unexported fields; only
// ParseCapability mints a valid one.
type Capability struct{ realm, resource, action string }

func ParseCapability(s string) (Capability, error) {
	realm, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Capability{}, ErrDenied
	}
	resource, action, ok := strings.Cut(rest, ".")
	if !ok {
		return Capability{}, ErrDenied
	}
	if !validRealm(realm) || !validSegment(resource, false) || !validSegment(action, true) {
		return Capability{}, ErrDenied
	}
	return Capability{realm: realm, resource: resource, action: action}, nil
}

func (c Capability) Realm() string { return c.realm }
func (c Capability) IsZero() bool  { return c.realm == "" }

// CapabilitySet — same-realm subsumption only; a terminal "*" action subsumes any action in
// the same realm+resource; cross-realm never subsumes; empty denies. This is where cross-
// realm requests fail: a route requiring orbtr.io:* is never met by an orbtr.ai capability.
type CapabilitySet struct{ held []Capability }

func NewCapabilitySet(held ...Capability) CapabilitySet { return CapabilitySet{held: held} }

func (s CapabilitySet) Allows(required Capability) bool {
	if required.IsZero() {
		return false
	}
	for _, h := range s.held {
		if h.realm != required.realm {
			continue
		}
		if h.resource == required.resource && (h.action == required.action || h.action == "*") {
			return true
		}
	}
	return false
}

func (s CapabilitySet) Subsumes(other CapabilitySet) bool {
	for _, o := range other.held {
		if !s.Allows(o) {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// OwnerScope — server-established {realm, owner}. No exported constructor: minted only
// inside Authorize from the SEALED owner, so a handler can only RECEIVE one.
// ─────────────────────────────────────────────────────────────────────────────

type OwnerScope struct {
	realm string
	owner string
}

func newOwnerScope(realm, owner string) OwnerScope { return OwnerScope{realm: realm, owner: owner} }

func (o OwnerScope) Realm() string { return o.realm }
func (o OwnerScope) Owner() string { return o.owner }

// IsZero denies unless BOTH realm and owner are non-empty (a partial scope is not a partition).
func (o OwnerScope) IsZero() bool { return o.realm == "" || o.owner == "" }

func (o OwnerScope) Equal(x OwnerScope) bool { return o.realm == x.realm && o.owner == x.owner }

// ─────────────────────────────────────────────────────────────────────────────
// Route — closed sum, keyed by SERVER operation identity (R-2411 pin 2). The Authorizer
// holds an immutable route table; a caller supplies only the operation being invoked (set
// server-side by the RPC dispatch), never a substituted weaker route.
// ─────────────────────────────────────────────────────────────────────────────

// OperationID names a server operation (an RPC method), not a caller-chosen route.
type OperationID string

type routeMode int

const (
	modeInvalid routeMode = iota
	modeOwnerBound
	modeGlobal
)

type Route struct {
	op       OperationID
	mode     routeMode
	required Capability
}

// OwnerBoundRoute: a per-owner op; the resolved OwnerScope's realm equals the capability's
// realm, and the sealed owner must equal the op's body owner.
func OwnerBoundRoute(op OperationID, required Capability) (Route, error) {
	if op == "" || required.IsZero() {
		return Route{}, ErrDenied
	}
	return Route{op: op, mode: modeOwnerBound, required: required}, nil
}

// GlobalRoute: a genuinely owner-less op; rejects any owner-bearing principal.
func GlobalRoute(op OperationID, required Capability) (Route, error) {
	if op == "" || required.IsZero() {
		return Route{}, ErrDenied
	}
	return Route{op: op, mode: modeGlobal, required: required}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Receiver-pinned trust (R-2411 pins 1/3). RealmTrust entries are owner-ratified, validated
// at construction, and consumed by the Authorizer's own clock — never a caller interface.
// ─────────────────────────────────────────────────────────────────────────────

// RealmTrust is an owner-ratified receiver-local trust entry. The home realm has one too;
// foreign realms add theirs. Audience is the receiver this realm issues tokens for.
type RealmTrust struct {
	Realm         string
	Issuer        string
	Audience      string
	PolicyVersion string
	ExpiresAtMS   int64
	Revoked       bool
}

func (rt RealmTrust) valid() bool {
	return validRealm(rt.Realm) && rt.Issuer != "" && rt.Audience != "" && rt.PolicyVersion != "" && rt.ExpiresAtMS > 0
}

// Clock returns the current time in unix-milliseconds. The Authorizer owns one; Authorize
// accepts no caller-supplied time (R-2411 pin 3).
type Clock func() int64

// replayStore holds consumed assertion identities. consume is atomic: two concurrent
// identical uses yield exactly ONE first-use success.
type replayStore struct {
	mu       sync.Mutex
	consumed map[string]struct{}
}

func newReplayStore() *replayStore { return &replayStore{consumed: map[string]struct{}{}} }

func (r *replayStore) consume(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, used := r.consumed[key]; used {
		return false
	}
	r.consumed[key] = struct{}{}
	return true
}

// Identity is what a handler receives from a successful Authorize.
type Identity struct {
	Subject      Subject
	OwnerScope   OwnerScope // zero for a Global route
	Capabilities CapabilitySet
}

// Authorizer is the ONE enforcement seam. It is constructed once by the trusted host with a
// paired Verifier, the expected platform tenant, pinned trust (home + foreign), an immutable
// route table, and a clock. Handlers receive it and call Authorize; they cannot construct or
// select it, nor supply a route, clock, nonce, trust, or capability.
type Authorizer struct {
	verifier       *mint.Verifier
	expectedTenant string
	audience       string
	trust          map[string]RealmTrust
	routes         map[OperationID]Route
	clock          Clock
	replay         *replayStore
}

// NewAuthorizer validates the receiver config, every trust entry, and every route at
// construction (fail-closed): nil verifier, empty tenant, invalid home trust, an invalid or
// audience-mismatched or home-colliding or duplicate foreign entry, or an invalid/duplicate
// route all reject. A nil clock defaults to real wall time.
func NewAuthorizer(verifier *Verifier, expectedTenant string, clock Clock, routes []Route, home RealmTrust, foreign ...RealmTrust) (*Authorizer, error) {
	if verifier == nil || expectedTenant == "" || !home.valid() {
		return nil, ErrDenied
	}
	trust := map[string]RealmTrust{home.Realm: home}
	for _, e := range foreign {
		if !e.valid() || e.Realm == home.Realm || e.Audience != home.Audience {
			return nil, ErrDenied
		}
		if _, dup := trust[e.Realm]; dup {
			return nil, ErrDenied
		}
		trust[e.Realm] = e
	}
	rm := make(map[OperationID]Route, len(routes))
	for _, r := range routes {
		if r.op == "" || r.mode == modeInvalid || r.required.IsZero() {
			return nil, ErrDenied
		}
		if _, dup := rm[r.op]; dup {
			return nil, ErrDenied
		}
		rm[r.op] = r
	}
	if clock == nil {
		clock = func() int64 { return time.Now().UnixMilli() }
	}
	return &Authorizer{
		verifier:       verifier,
		expectedTenant: expectedTenant,
		audience:       home.Audience,
		trust:          trust,
		routes:         rm,
		clock:          clock,
		replay:         newReplayStore(),
	}, nil
}

// trustAccepts verifies the principal's sealed assertion against pinned trust and the
// Authorizer's OWN clock: the principal's realm must have a live (unrevoked, unexpired) trust
// entry whose issuer/audience/version match the sealed assertion, the token must not be
// expired, and its audience must be this receiver's.
func (a *Authorizer) trustAccepts(p VerifiedPrincipal) bool {
	realm := p.Realm()
	if !validRealm(realm) {
		return false
	}
	e, ok := a.trust[realm]
	if !ok {
		return false
	}
	now := a.clock()
	if e.Revoked || e.ExpiresAtMS <= now {
		return false
	}
	if p.ExpiresAtMS() <= 0 || now >= p.ExpiresAtMS() {
		return false
	}
	if p.Audience() != a.audience {
		return false
	}
	return e.Issuer == p.Issuer() && e.Audience == p.Audience() && e.PolicyVersion == p.Version()
}

// Authorize enforces every invariant, in order: (1) seal verified against the receiver's own
// secret, constant-time; (2) subject validity + platform-tenant admission; (3) immutable
// server-operation route lookup; (4) sealed assertion trust + expiry against the owned clock;
// (5) sealed capabilities parsed + owner/realm/capability binding; (6) atomic replay consume
// LAST, only after every prior check passes, so a failed attempt cannot poison a nonce.
// Non-disclosing: every failure is ErrDenied. bodyOwner is the op-specific owner (compare-only).
func (a *Authorizer) Authorize(ctx context.Context, principal VerifiedPrincipal, op OperationID, bodyOwner string) (Identity, error) {
	_ = ctx
	// nil-seam fail-closed.
	if a == nil || a.verifier == nil || a.replay == nil || a.clock == nil {
		return Identity{}, ErrDenied
	}
	// (1) receiver-pinned seal — a principal minted by any other Verifier is denied.
	if !a.verifier.Verify(principal) {
		return Identity{}, ErrDenied
	}
	// (2) subject validity + admission binding.
	if principal.Subject().ID == "" || principal.Subject().Kind == "" || principal.PlatformTenant() != a.expectedTenant {
		return Identity{}, ErrDenied
	}
	// (3) immutable server-operation route — caller cannot substitute a weaker route.
	route, ok := a.routes[op]
	if !ok {
		return Identity{}, ErrDenied
	}
	// (4) sealed assertion trust + expiry against the Authorizer's own clock.
	if !a.trustAccepts(principal) {
		return Identity{}, ErrDenied
	}
	// (5) sealed capabilities parsed here (never caller-authored); a malformed grant denies.
	caps := make([]Capability, 0, len(principal.Capabilities()))
	for _, s := range principal.Capabilities() {
		c, err := ParseCapability(s)
		if err != nil {
			return Identity{}, ErrDenied
		}
		caps = append(caps, c)
	}
	held := NewCapabilitySet(caps...)
	id := Identity{Subject: principal.Subject(), Capabilities: held}
	switch route.mode {
	case modeOwnerBound:
		owner := principal.Owner()
		if !principal.HasOwner() || !validOwner(owner) || owner != bodyOwner {
			return Identity{}, ErrDenied
		}
		os := newOwnerScope(route.required.Realm(), owner)
		if os.IsZero() || !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
		id.OwnerScope = os
	case modeGlobal:
		if principal.HasOwner() || bodyOwner != "" {
			return Identity{}, ErrDenied
		}
		if !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
	default:
		return Identity{}, ErrDenied
	}
	// (6) atomic replay consume LAST — a failed attempt above never reaches here, so it
	// cannot poison the nonce; two concurrent identical uses yield exactly one success.
	if n := principal.Nonce(); n != "" {
		key := principal.Issuer() + "|" + principal.Audience() + "|" + principal.Version() + "|" + principal.Realm() + "|" + n
		if !a.replay.consume(key) {
			return Identity{}, ErrDenied
		}
	}
	return id, nil
}
