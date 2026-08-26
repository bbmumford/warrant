// Package warrant is the scope-agnostic authority core for the ORBTR platform
// retirement (plan §16.1). Like loom it interprets NO axis itself: meaning is supplied
// by the consumer via a CapabilityPolicy. But the CORE — never the consumer — enforces
// every authority invariant, and provenance is UNFORGEABLE from outside the module by
// construction (VerifiedPrincipal + Mint live in internal/mint; see that package).
//
// v3 closes risk R-2399's six gaps: (1) internal/mint boundary makes forgery a compile
// error for external modules; (2) the owner is a SEALED claim read by key from the
// verified principal, never a raw policy string; (3) Authorize binds partition realm ==
// capability realm and forbids a global-route owner; (4) principal validity is checked;
// (5) a concrete receiver-local TrustEvaluator gates foreign-realm grants; (6) realm and
// capability grammar is canonically validated. Every leg has an executable hostile.
package warrant

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/bbmumford/warrant/internal/mint"
)

// ErrDenied is the SINGLE non-disclosing deny. Every failure — forged/unverified
// principal, nil policy, invalid route, absent/foreign owner, realm mismatch, unmet
// capability, untrusted foreign realm, malformed input, policy error — surfaces as this,
// so a refusal never discloses which leg failed (#R-896).
var ErrDenied = errors.New("authorization denied")

// VerifiedPrincipal and Subject are re-exported from internal/mint by ALIAS: the type is
// usable here and by consumers, but Mint (which sets verified=true) is reachable ONLY
// from within this module. An external module can construct a zero-value VerifiedPrincipal
// (verified=false → denied) and nothing more.
type (
	VerifiedPrincipal = mint.VerifiedPrincipal
	Subject           = mint.Subject
	SubjectKind       = mint.SubjectKind
)

const maxTokenLen = 64

// ─────────────────────────────────────────────────────────────────────────────
// OwnerScope — server-established {realm, owner}. No exported constructor: minted only
// inside Authorize from the SEALED claim, so a handler can only RECEIVE one, never
// fabricate one from a body value.
// ─────────────────────────────────────────────────────────────────────────────

type OwnerScope struct {
	realm string
	owner string
}

func newOwnerScope(realm, owner string) OwnerScope { return OwnerScope{realm: realm, owner: owner} }

func (o OwnerScope) Realm() string { return o.realm }
func (o OwnerScope) Owner() string { return o.owner }

// IsZero denies unless BOTH realm and owner are non-empty (R-2399 #4: a partial scope is
// not a partition).
func (o OwnerScope) IsZero() bool { return o.realm == "" || o.owner == "" }

// Equal is the collision-safe partition comparison (field-wise, not string concat).
func (o OwnerScope) Equal(x OwnerScope) bool { return o.realm == x.realm && o.owner == x.owner }

// ─────────────────────────────────────────────────────────────────────────────
// (R-2399 #6) Canonical grammar. realm may contain "." (an RPC-namespace root, e.g.
// orbtr.ai) but never a leading/trailing/double dot; resource/action are single
// segments with no dots; action may be a terminal "*".
// ─────────────────────────────────────────────────────────────────────────────

// validRealm: dotted lower token, no empty label (rejects "", ".", ".x", "x.", "x..y").
func validRealm(s string) bool {
	if s == "" || len(s) > maxTokenLen {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validSegment(label, false) { // each dotted label is a plain segment
			return false
		}
	}
	return true
}

// validSegment: non-empty lower alnum + _ - ; optionally the terminal "*".
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

// validOwner: an owner key is a single non-empty segment (no dots).
func validOwner(s string) bool { return validSegment(s, false) }

// Capability is realm-namespaced: "<realm>:<resource>.<action>". Unexported fields;
// only ParseCapability mints a valid one.
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

// ─────────────────────────────────────────────────────────────────────────────
// CapabilitySet — concrete, same-realm subsumption only, empty denies.
// ─────────────────────────────────────────────────────────────────────────────

type CapabilitySet struct{ held []Capability }

func NewCapabilitySet(held ...Capability) CapabilitySet { return CapabilitySet{held: held} }

// Allows: same-realm only; a held terminal "*" action subsumes any action in the same
// realm+resource. Cross-realm never subsumes. An empty/zero required denies.
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

// Subsumes: the first-class child clamp — every capability other holds, this holds.
func (s CapabilitySet) Subsumes(other CapabilitySet) bool {
	for _, o := range other.held {
		if !s.Allows(o) {
			return false
		}
	}
	return true
}

// realms returns the distinct realms of the held capabilities (for trust gating).
func (s CapabilitySet) realms() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, h := range s.held {
		if _, ok := seen[h.realm]; !ok {
			seen[h.realm] = struct{}{}
			out = append(out, h.realm)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// (R-2399 #3) Route — closed sum; no contradictory flags.
// ─────────────────────────────────────────────────────────────────────────────

type routeMode int

const (
	modeInvalid routeMode = iota
	modeOwnerBound
	modeGlobal
	modeExplicitNone
)

type Route struct {
	mode     routeMode
	required Capability
}

// OwnerBoundRoute: a per-owner op; requires a valid capability; the resolved OwnerScope
// binds every selector, and its realm must equal the capability's realm.
func OwnerBoundRoute(required Capability) (Route, error) {
	if required.IsZero() {
		return Route{}, ErrDenied
	}
	return Route{mode: modeOwnerBound, required: required}, nil
}

// GlobalRoute: a genuinely owner-less op; requires its explicit capability; rejects any
// per-owner/body binding.
func GlobalRoute(required Capability) (Route, error) {
	if required.IsZero() {
		return Route{}, ErrDenied
	}
	return Route{mode: modeGlobal, required: required}, nil
}

// ExplicitNoneRoute: a deliberate enforcement opt-out (token-as-authority routes keep
// their own mandatory handler gate).
func ExplicitNoneRoute() Route { return Route{mode: modeExplicitNone} }

// ─────────────────────────────────────────────────────────────────────────────
// (R-2399 #2) Consumer policy — returns a sealed claim KEY, never a raw owner string.
// ─────────────────────────────────────────────────────────────────────────────

// ClaimKey is a member of the CLOSED owner-claim vocabulary. A policy names WHICH sealed
// claim carries the owner; the core reads it from the verified principal. A policy can
// never hand back a raw (potentially body-derived) owner string.
type ClaimKey string

const (
	ClaimOrg  ClaimKey = "org"
	ClaimUser ClaimKey = "user"
)

func (k ClaimKey) valid() bool { return k == ClaimOrg || k == ClaimUser }

// Resolution is what a CapabilityPolicy returns — ROUTING only, never grants. Realm is
// the consumer's own realm (a canonical constant it operates). OwnerKey names the sealed
// claim the owner is read from (empty for a Global route). The effective CAPABILITIES are
// NOT here: they are sealed into the VerifiedPrincipal at mint, so a policy cannot inject
// them (R-2405 #1).
type Resolution struct {
	Realm    string
	OwnerKey ClaimKey
}

// CapabilityPolicy is the CONSUMER-SUPPLIED routing interpretation — warrant ships none.
// It reads only the VerifiedPrincipal (never a request body), returns a Resolution
// (routing), and CANNOT author capabilities or the owner. It does not enforce invariants
// or do the body compare — those are the Authorizer's job.
type CapabilityPolicy interface {
	Resolve(ctx context.Context, principal VerifiedPrincipal, route Route) (Resolution, error)
}

// Identity is what a handler receives from Authorize.
type Identity struct {
	Subject      Subject
	OwnerScope   OwnerScope // zero for a Global route
	Capabilities CapabilitySet
}

// ─────────────────────────────────────────────────────────────────────────────
// (R-2405 #2/#3) Receiver-local realm trust — a CONCRETE owner-ratified store, not an
// external interface; entries are validated at construction; replay is real state.
// ─────────────────────────────────────────────────────────────────────────────

// RealmTrust is an owner-ratified receiver-local trust entry for a foreign realm.
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

// trustStore is concrete (not an interface a caller can make always-true). It holds
// owner-ratified entries + real replay state (consumed nonces).
type trustStore struct {
	home     string
	entries  map[string]RealmTrust
	mu       sync.Mutex
	seen     map[string]struct{} // consumed replay nonces (real state, not a static bool)
	audience string              // this receiver's expected audience
}

// trusts reports whether realm is trusted right now. Home realm is always trusted. A
// foreign realm needs a live, unrevoked, unexpired, audience-matching entry, and — when
// the assertion carries a nonce — that nonce must be first-use (consumed here).
func (t *trustStore) trusts(realm string, nowMS int64, nonce string) bool {
	if realm == t.home {
		return true
	}
	e, ok := t.entries[realm]
	if !ok || e.Revoked || e.ExpiresAtMS <= nowMS || e.Audience != t.audience {
		return false // fail closed: absent, revoked, expired, wrong audience
	}
	if nonce != "" { // replay: first use succeeds, an identical second use is denied
		t.mu.Lock()
		defer t.mu.Unlock()
		if _, used := t.seen[nonce]; used {
			return false
		}
		t.seen[nonce] = struct{}{}
	}
	return true
}

// Authorizer binds the receiver-local configuration — expected platform tenant, home
// realm, audience, and owner-ratified trust — at construction. All of it is validated;
// there is no external-implementable trust hook. This is the ONE enforcement seam.
type Authorizer struct {
	expectedPlatformTenant string
	home                   string
	trust                  *trustStore
}

// NewAuthorizer validates the receiver config + every trust entry (R-2405 #2/#4). It
// fails if the platform tenant or home realm is empty/non-canonical or any entry is
// invalid — owner-ratified config, checked, not caller-trusted at use time.
func NewAuthorizer(expectedPlatformTenant, homeRealm, audience string, entries ...RealmTrust) (*Authorizer, error) {
	if expectedPlatformTenant == "" || !validRealm(homeRealm) || audience == "" {
		return nil, ErrDenied
	}
	m := make(map[string]RealmTrust, len(entries))
	for _, e := range entries {
		if !e.valid() || e.Realm == homeRealm {
			return nil, ErrDenied
		}
		m[e.Realm] = e
	}
	return &Authorizer{
		expectedPlatformTenant: expectedPlatformTenant,
		home:                   homeRealm,
		trust:                  &trustStore{home: homeRealm, entries: m, seen: map[string]struct{}{}, audience: audience},
	}, nil
}

// Authorize resolves the server-established Identity and enforces every invariant in the
// core. bodyOwner is the op-specific owner field (compare-only). nonce is an optional
// replay nonce for a presented trust assertion. Non-disclosing: every failure is ErrDenied.
func (a *Authorizer) Authorize(ctx context.Context, policy CapabilityPolicy, principal VerifiedPrincipal, route Route, bodyOwner string, nowMS int64, nonce string) (Identity, error) {
	if a == nil || policy == nil || route.mode == modeInvalid {
		return Identity{}, ErrDenied
	}
	// (#4) principal validity + admission: verified, non-empty subject, and the platform
	// tenant must be the receiver's EXPECTED tenant (a foreign non-empty value is denied).
	if !principal.Verified() || principal.Subject().ID == "" || principal.Subject().Kind == "" || principal.PlatformTenant() != a.expectedPlatformTenant {
		return Identity{}, ErrDenied
	}
	// (#1) effective capabilities come from the SEALED principal, parsed here — never from
	// the policy. A malformed sealed grant denies the whole request (fail closed).
	caps := make([]Capability, 0, len(principal.Capabilities()))
	for _, s := range principal.Capabilities() {
		c, err := ParseCapability(s)
		if err != nil {
			return Identity{}, ErrDenied
		}
		caps = append(caps, c)
	}
	held := NewCapabilitySet(caps...)
	res, err := policy.Resolve(ctx, principal, route)
	if err != nil {
		return Identity{}, ErrDenied // non-disclosing
	}
	// (#2/#3) every held capability's realm must be trusted (home, or a live owner-ratified
	// entry with first-use nonce).
	for _, r := range held.realms() {
		if !a.trust.trusts(r, nowMS, nonce) {
			return Identity{}, ErrDenied
		}
	}
	id := Identity{Subject: principal.Subject(), Capabilities: held}
	switch route.mode {
	case modeOwnerBound:
		if !res.OwnerKey.valid() || !validRealm(res.Realm) || res.Realm != route.required.Realm() {
			return Identity{}, ErrDenied // (#3) partition realm bound to capability realm
		}
		owner, ok := principal.Claim(string(res.OwnerKey)) // (#2) owner from sealed claim
		if !ok || !validOwner(owner) {
			return Identity{}, ErrDenied
		}
		os := newOwnerScope(res.Realm, owner)
		if os.IsZero() {
			return Identity{}, ErrDenied
		}
		if bodyOwner != "" && bodyOwner != os.Owner() { // body compare-only
			return Identity{}, ErrDenied
		}
		if !held.Allows(route.required) { // sealed caps must cover the route
			return Identity{}, ErrDenied
		}
		id.OwnerScope = os
	case modeGlobal:
		// (#3/#5) no per-owner binding; the global route's realm is bound to the capability.
		if bodyOwner != "" || res.OwnerKey != "" || res.Realm != route.required.Realm() {
			return Identity{}, ErrDenied
		}
		if !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
	case modeExplicitNone:
		// enforcement opt-out; the handler's own token gate is separate.
	default:
		return Identity{}, ErrDenied
	}
	return id, nil
}
