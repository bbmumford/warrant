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

const (
	// maxPrincipalTTLms caps how far in the future an assertion may expire — bounds how long a
	// consumed nonce must be retained for replay defense (R-2422 (3) long-horizon).
	maxPrincipalTTLms = int64(24 * 60 * 60 * 1000) // 24h
	// maxReplayEntries caps live consumed-nonce storage; at capacity, consume FAILS CLOSED rather
	// than evicting an unexpired entry to admit reuse (R-2422 (3) capacity).
	maxReplayEntries = 1 << 20
)

// monoClock wraps a Clock with a monotonic high-water mark: a rolled-back wall clock never yields
// a time earlier than one already observed, so an expired/evicted principal cannot resurrect and
// a consumed nonce cannot be un-expired (R-2422 (3) rollback-safe).
type monoClock struct {
	mu    sync.Mutex
	clock Clock
	hw    int64
}

func (m *monoClock) now() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.clock(); t > m.hw {
		m.hw = t
	}
	return m.hw
}

// A request principal MUST carry a non-empty, bounded replay nonce (assurance HOLD 2): replay is
// never caller-optional. Bounds reject an empty or oversize nonce.
const (
	minNonceLen = 8
	maxNonceLen = 128
)

// replayKey is a TYPED, unambiguous consumed-assertion identity (no delimiter concatenation).
type replayKey struct {
	issuer, audience, version, realm, nonce string
}

// replayStore holds consumed identities keyed to their assertion expiry, so storage is bounded: a
// nonce is dead once its assertion expires (it is also denied at the trust/expiry check). consume is
// atomic — two concurrent identical uses yield exactly ONE first-use success — and reclaims expired
// entries through a min-heap ordered by expiry, so an ordinary consume never traverses the live set.
// A full-map scan per authorization was a CPU-exhaustion surface: with a large live set an attacker
// supplying fresh valid nonces forced O(live) work per request. Here every expired entry sits at the
// heap root, so a consume with nothing expired does zero pops; each entry is pushed once and popped
// once (amortized O(log n)). The map and heap stay 1:1 — a key is inserted only while live, and its
// heap entry is popped (and the map entry deleted) once its expiry passes, before any re-insertion.
type replayEntry struct {
	key    replayKey
	expiry int64
}

type replayStore struct {
	mu         sync.Mutex
	consumed   map[replayKey]int64 // key → assertion expiry (ms); only LIVE entries survive a consume
	heap       []replayEntry       // min-heap by expiry: bounded eviction, never a full live-set scan
	maxEntries int
	// evictInspections counts entries the eviction step inspected (heap-root peeks). It is an
	// operation-count witness: per consume it is O(expired)+1, INDEPENDENT of the live-set size, so a
	// test can prove eviction never ranges over all live entries (a regression to a full-map scan
	// would make it O(live)). Not part of the authority decision.
	evictInspections int64
}

func newReplayStore() *replayStore {
	return &replayStore{consumed: map[replayKey]int64{}, maxEntries: maxReplayEntries}
}

// consume records key (valid until expiryMS) and returns true on FIRST use, using the single decision
// instant nowMS the caller already sampled — never its own clock read, so admission and consume agree
// on one instant. It evicts ONLY entries whose assertion has expired at nowMS (from the heap root
// outward), then enforces exactly-once and a fail-closed capacity that never evicts an UNEXPIRED entry
// to admit reuse.
func (r *replayStore) consume(key replayKey, expiryMS, nowMS int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.heap) > 0 {
		r.evictInspections++ // inspect the root only; O(expired)+1 per consume, never O(live)
		if r.heap[0].expiry > nowMS {
			break
		}
		e := r.heapPop()
		// Lazy 1:1 delete: drop the map entry only for the same insertion this heap node recorded.
		if cur, ok := r.consumed[e.key]; ok && cur == e.expiry {
			delete(r.consumed, e.key)
		}
	}
	if _, used := r.consumed[key]; used {
		return false
	}
	if len(r.consumed) >= r.maxEntries {
		return false // fail-closed at capacity; never evict an UNEXPIRED entry to admit reuse
	}
	r.consumed[key] = expiryMS
	r.heapPush(replayEntry{key: key, expiry: expiryMS})
	return true
}

// heapPush/heapPop keep r.heap a binary min-heap ordered by expiry. Hand-rolled so the consumed
// identities stay unboxed on the authorization hot path (no container/heap interface conversion).
func (r *replayStore) heapPush(e replayEntry) {
	r.heap = append(r.heap, e)
	for i := len(r.heap) - 1; i > 0; {
		parent := (i - 1) / 2
		if r.heap[parent].expiry <= r.heap[i].expiry {
			break
		}
		r.heap[parent], r.heap[i] = r.heap[i], r.heap[parent]
		i = parent
	}
}

func (r *replayStore) heapPop() replayEntry {
	n := len(r.heap) - 1
	top := r.heap[0]
	r.heap[0] = r.heap[n]
	r.heap = r.heap[:n]
	for i := 0; ; {
		l, rr, smallest := 2*i+1, 2*i+2, i
		if l < n && r.heap[l].expiry < r.heap[smallest].expiry {
			smallest = l
		}
		if rr < n && r.heap[rr].expiry < r.heap[smallest].expiry {
			smallest = rr
		}
		if smallest == i {
			break
		}
		r.heap[i], r.heap[smallest] = r.heap[smallest], r.heap[i]
		i = smallest
	}
	return top
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
	mono           *monoClock
	replay         *replayStore
}

// GoString and String redact the handler-facing Authorizer: it holds the Verifier (and thus the
// minting key), so ordinary formatting/logging must never expand it into its fields (R-2422 (1)).
func (a *Authorizer) GoString() string { return "warrant.Authorizer{redacted: holds Verifier key}" }
func (a *Authorizer) String() string   { return "warrant.Authorizer{redacted}" }

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
		mono:           &monoClock{clock: clock},
		replay:         newReplayStore(),
	}, nil
}

// trustAccepts verifies the principal's sealed assertion against pinned trust and the
// Authorizer's OWN clock: the principal's realm must have a live (unrevoked, unexpired) trust
// entry whose issuer/audience/version match the sealed assertion, the token must not be
// expired, and its audience must be this receiver's.
func (a *Authorizer) trustAccepts(p VerifiedPrincipal, now int64) bool {
	realm := p.Realm()
	if !validRealm(realm) {
		return false
	}
	e, ok := a.trust[realm]
	if !ok {
		return false
	}
	if e.Revoked || e.ExpiresAtMS <= now {
		return false
	}
	// expired, no-expiry, OR a TTL beyond the cap (bounds replay-map retention; R-2422 (3)).
	if p.ExpiresAtMS() <= 0 || now >= p.ExpiresAtMS() || p.ExpiresAtMS() > now+maxPrincipalTTLms {
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
	if a == nil || a.verifier == nil || a.replay == nil || a.mono == nil {
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
	// (2a) representation consistency — HasOwner must agree with Owner presence (assurance HOLD 4).
	if principal.HasOwner() != (principal.Owner() != "") {
		return Identity{}, ErrDenied
	}
	// (2b) MANDATORY bounded replay nonce — replay is never caller-optional (assurance HOLD 2).
	if n := principal.Nonce(); len(n) < minNonceLen || len(n) > maxNonceLen {
		return Identity{}, ErrDenied
	}
	// (3) immutable server-operation route — caller cannot substitute a weaker route.
	route, ok := a.routes[op]
	if !ok {
		return Identity{}, ErrDenied
	}
	// (3a) REALM BINDING — the principal's realm must equal the route's realm (assurance HOLD 1);
	// a foreign-realm assertion cannot authorize a home route even carrying a home-realm capability.
	if principal.Realm() != route.required.Realm() {
		return Identity{}, ErrDenied
	}
	// (4) sealed capabilities parsed here (never caller-authored); a malformed grant denies. Every
	// capability MUST be in the principal's realm (assurance HOLD 1) — no cross-realm capability. This
	// and the owner/global binding below are DETERMINISTIC (no clock), so they run BEFORE the single
	// time sample: a malformed/unmet-capability or wrong-owner denial reads the clock ZERO times, and
	// only a decision that has passed EVERY deterministic authority check reaches the clock — so no
	// capability-bundle work can age the decision instant between admission and consume.
	caps := make([]Capability, 0, len(principal.Capabilities()))
	for _, s := range principal.Capabilities() {
		c, err := ParseCapability(s)
		if err != nil || c.Realm() != principal.Realm() {
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
		// global routes deny ANY owner material (assurance HOLD 4).
		if principal.HasOwner() || principal.Owner() != "" || bodyOwner != "" {
			return Identity{}, ErrDenied
		}
		if !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
	default:
		return Identity{}, ErrDenied
	}
	// (5) ONE authoritative decision instant, sampled EXACTLY ONCE here — after every DETERMINISTIC
	// authority check above (seal, subject, tenant, representation, nonce, route, realm, capability,
	// owner/global) and immediately before the two time-dependent steps, which share it. A single
	// monotonic read per decision: a deterministic denial never reads the clock, and nothing between
	// admission and consume can age the instant. monoClock keeps it rollback-safe; trustAccepts denies
	// at now >= ExpiresAtMS (exact-expiry).
	nowMS := a.mono.now()
	if !a.trustAccepts(principal, nowMS) {
		return Identity{}, ErrDenied
	}
	// (6) atomic replay consume LAST — after every prior check INCLUDING trust, so a failed check
	// never poisons the nonce; the nonce is mandatory (2b) so every request is exactly-once, and two
	// concurrent identical uses yield exactly one success. Typed key, expiry-bounded storage.
	key := replayKey{principal.Issuer(), principal.Audience(), principal.Version(), principal.Realm(), principal.Nonce()}
	if !a.replay.consume(key, principal.ExpiresAtMS(), nowMS) {
		return Identity{}, ErrDenied
	}
	return id, nil
}
