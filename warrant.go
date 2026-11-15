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
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/warrant/internal/mint"
)

// ErrDenied is the SINGLE non-disclosing deny. Every failure — forged/unverified seal, wrong
// deployment, unknown operation, untrusted/expired assertion, realm mismatch, absent or
// mismatched partition, unmet capability, replayed nonce, nil seam, malformed grammar — surfaces
// as this or unwraps to it (a *DeniedError), so a refusal never discloses which leg failed.
//
// It unwraps to loom's scope.ErrDenied, so a denial a handler returns is a refusal of the
// caller's authority wherever loom carries it: loom's registry reports it as the handler's
// denial, dispatch.StampDenial stamps it on a response crossing the mesh, and the RPC HTTP
// bridge answers it 403 in its own process and through a proxy (classifyHandlerStatus,
// classifyMeshError), which read no other error as a refusal of the caller. The status is then
// one for every leg, as the text is.
var ErrDenied error = denial{}

// denial is ErrDenied's type: its text, and the scope.ErrDenied it unwraps to.
type denial struct{}

func (denial) Error() string { return "authorization denied" }

func (denial) Unwrap() error { return scope.ErrDenied }

// DeniedError is Authorize's refusal of an operation its route table holds: it names the
// capability that operation's route requires and unwraps to ErrDenied, so callers keep testing
// errors.Is(err, ErrDenied). Authorize returns the same DeniedError for every leg that fails on
// one operation, so its text names what the operation requires and never which leg failed.
// cortex's handlers.Authorized prefixes the operation's name to it and the RPC bridge returns
// that text to the caller, so a refused caller reads the capability it was judged against; the
// operation's advert on the mesh already names the same requirement (loom's peer record
// requirement tag), so naming it here discloses nothing a mesh peer cannot read.
type DeniedError struct {
	Required string // the route's required capability, in Capability.String's canonical form
}

func (e *DeniedError) Error() string { return ErrDenied.Error() + ": requires " + e.Required }

func (e *DeniedError) Unwrap() error { return ErrDenied }

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
// Canonical grammar. realm may contain "." (e.g. orbtr.control) but never
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

func validPartition(s string) bool { return validSegment(s, false) }

// Capability is realm-namespaced: "<realm>:<resource>.<action>", optionally followed by one
// parameter in parentheses, "<realm>:<resource>.<action>(<parameter>)". A leading "-" makes it a
// NEGATIVE capability — a deny that overrides any positive match in the same set (see
// CapabilitySet.Allows). Unexported fields; only ParseCapability mints a valid one.
//
// A terminal "*" action covers every action on the resource. The RESOURCE may also be "*",
// but only on a revocation: "-<realm>:*.*" refuses a whole realm, which a positive
// capability deliberately cannot express.
//
// The parameter names the one instance of an action a grant reaches, such as the class an
// approver may approve ("orbtr:exec.approve(fs_delete)") or the mode a subject may run as
// ("orbtr:exec.run_as(elevated)"), so a role can hold an action for one instance without the
// rest. A capability with no parameter covers its action for every parameter, a deny included,
// so "-orbtr:exec.approve" revokes every class; one with a parameter covers that parameter only.
// A "*" action takes no parameter.
type Capability struct {
	realm, resource, action, param string
	deny                           bool
}

// ParseCapability parses "<realm>:<resource>.<action>", or "-<realm>:<resource>.<action>" for a
// negative capability, each optionally ending in one "(<parameter>)". The parameter is one token
// of the resource alphabet; an empty, unclosed or nested parameter, a parameter on a "*" action
// and anything after the closing parenthesis are refused.
//
// The leading "-" MUST be stripped before validation rather than left on the realm: validSegment
// admits "-" as an ordinary character, so "-orbtr:exec.run_as" would otherwise parse as a
// capability in a realm literally named "-orbtr" — which matches nothing and therefore denies
// nothing, silently turning a revocation into a no-op.
func ParseCapability(s string) (Capability, error) {
	deny := strings.HasPrefix(s, "-")
	if deny {
		s = s[1:]
	}
	realm, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Capability{}, ErrDenied
	}
	resource, action, ok := strings.Cut(rest, ".")
	if !ok {
		return Capability{}, ErrDenied
	}
	// A resource wildcard is admitted ONLY on a revocation. Widening a deny can never
	// grant anything, whereas a positive "<realm>:*.<action>" would confer a whole realm
	// in one token and is refused. This is what lets a realm-wide revocation be exact
	// instead of only as complete as the caller's resource vocabulary.
	param := ""
	if open := strings.IndexByte(action, '('); open >= 0 {
		inner, closed := strings.CutSuffix(action[open+1:], ")")
		if !closed || action[:open] == "*" || !validSegment(inner, false) {
			return Capability{}, ErrDenied
		}
		action, param = action[:open], inner
	}
	if !validRealm(realm) || !validSegment(resource, deny) || !validSegment(action, true) {
		return Capability{}, ErrDenied
	}
	return Capability{realm: realm, resource: resource, action: action, param: param, deny: deny}, nil
}

func (c Capability) Realm() string { return c.realm }
func (c Capability) IsZero() bool  { return c.realm == "" }

// IsDeny reports whether c is a negative capability (a revocation).
func (c Capability) IsDeny() bool { return c.deny }

// Param returns c's parameter, or "" when c covers its action for every parameter.
func (c Capability) Param() string { return c.param }

// String renders the canonical form ParseCapability accepts — "<realm>:<resource>.<action>",
// followed by "(<parameter>)" when c carries one and prefixed "-" for a negative capability — so
// ParseCapability(c.String()) reproduces c for every
// capability ParseCapability can mint. That round trip is what lets a set cross a []string
// boundary, such as a mint input, without losing what it holds.
//
// THE REVOCATION IS CARRIED IN THE STRING, which is the point and the hazard together. A caller
// that compares these strings, or tests one for membership in a held list, reads "-realm:res.act"
// as a capability it holds rather than one it is refused. Parse them back and ask
// CapabilitySet.Allows; never match on the text.
//
// A zero Capability renders "" rather than ":.", because it names nothing and ":." would be a
// string ParseCapability rejects — an empty element is at least visibly empty at the boundary it
// crosses.
func (c Capability) String() string {
	if c.IsZero() {
		return ""
	}
	s := c.realm + ":" + c.resource + "." + c.action
	if c.param != "" {
		s += "(" + c.param + ")"
	}
	if c.deny {
		s = "-" + s
	}
	return s
}

// covers reports whether c's realm/resource/action pattern matches required, treating a terminal
// "*" action as covering any action in the same realm+resource, and c with no parameter as covering
// its action for every parameter; c with a parameter covers required only when required names the
// same one, so a request with no parameter, which asks for the action for every parameter, is not
// covered by a grant of one. It ignores the deny flag on both sides: callers decide what a match
// MEANS. Allows tests it in both directions for a deny, which is what makes a parameterless deny
// refuse every parameter and a deny of one parameter refuse a request for all of them.
func (c Capability) covers(required Capability) bool {
	return c.realm == required.realm &&
		(c.resource == required.resource || c.resource == "*") &&
		(c.action == required.action || c.action == "*") &&
		(c.param == "" || c.param == required.param)
}

// CapabilitySet — same-realm subsumption only; a terminal "*" action subsumes any action in
// the same realm+resource; cross-realm never subsumes; empty denies. This is where cross-
// realm requests fail: an orbtr capability never meets a route requiring an orbtr.control one.
type CapabilitySet struct{ held []Capability }

func NewCapabilitySet(held ...Capability) CapabilitySet { return CapabilitySet{held: held} }

// Allows reports whether the set confers required, applying DENY PRECEDENCE: a negative
// capability covering required refuses it however the set grants it, including through a
// terminal "*". That ordering is the point — a role written as a broad grant minus specific
// revocations (e.g. {"orbtr:exec.*", "-orbtr:exec.run_as", "-orbtr:exec.mode"}) can only
// express the revocation if the deny outranks the wildcard that confers it.
//
// A set holding no negative capability behaves exactly as it did before deny existed: the deny
// scan matches nothing and the positive scan decides.
//
// The deny scan tests coverage in BOTH directions, because a request can be broader than the
// revocation that spoils it. Asking for a terminal "*" asks for every action on the resource,
// so a deny of any single one of them means the set does not confer it: required "token.*"
// against held "-token.mint" is refused even though the deny covers only part of the request.
// One-directional matching would let a caller widen its own request past a revocation.
//
// required must itself be positive. A negative required is refused rather than inverted, so a
// caller cannot ask "am I denied?" and read the answer as permission.
func (s CapabilitySet) Allows(required Capability) bool {
	if required.IsZero() || required.deny {
		return false
	}
	for _, h := range s.held {
		if h.deny && (h.covers(required) || required.covers(h)) {
			return false
		}
	}
	for _, h := range s.held {
		if !h.deny && h.covers(required) {
			return true
		}
	}
	return false
}

// Subsumes reports whether s confers everything other confers. A negative capability in other
// refuses the comparison outright rather than being skipped: "does this set cover that set" has
// no meaning once that set contains a revocation, and silently ignoring it would let an
// attenuated set claim to subsume one whose denies it does not reproduce.
func (s CapabilitySet) Subsumes(other CapabilitySet) bool {
	for _, o := range other.held {
		if o.deny {
			return false
		}
		if !s.Allows(o) {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Partition — server-established {realm, id}. No exported constructor: minted
// only inside Authorize from the sealed principal, so a handler can only
// RECEIVE one and can never name a partition it was not given.
// ─────────────────────────────────────────────────────────────────────────────

type Partition struct {
	realm string
	id    string
}

func newPartition(realm, id string) Partition { return Partition{realm: realm, id: id} }

func (o Partition) Realm() string     { return o.realm }
func (o Partition) Partition() string { return o.id }

// IsZero denies unless BOTH realm and id are non-empty; a half-populated value
// is not a partition and must not satisfy a partition-bound route.
func (o Partition) IsZero() bool { return o.realm == "" || o.id == "" }

func (o Partition) Equal(x Partition) bool { return o.realm == x.realm && o.id == x.id }

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
	modePartitionBound
	modeGlobal
)

type Route struct {
	op       OperationID
	mode     routeMode
	required Capability
}

// PartitionBoundRoute: a per-partition op; the resolved Partition's realm equals the capability's
// realm, and the sealed partition must equal the op's body partition.
func PartitionBoundRoute(op OperationID, required Capability) (Route, error) {
	if op == "" || required.IsZero() {
		return Route{}, ErrDenied
	}
	return Route{op: op, mode: modePartitionBound, required: required}, nil
}

// GlobalRoute: a genuinely partition-less op; rejects any partition-bearing principal.
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
// GrammarVersion is the capability grammar this realm's sets are written in and
// PolicyDigest the one value standing for the whole policy identity: both are read in
// realmpolicy.go, bound by NewAuthorizer and compared by trustAccepts.
type RealmTrust struct {
	Realm          string
	Issuer         string
	Audience       string
	PolicyVersion  string
	GrammarVersion string
	PolicyDigest   string
	ExpiresAtMS    int64
	Revoked        bool
}

func (rt RealmTrust) valid() bool {
	return validRealm(rt.Realm) && rt.Issuer != "" && rt.Audience != "" && rt.PolicyVersion != "" && rt.ExpiresAtMS > 0 && rt.policyIdentityValid()
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
	// Zero the vacated tail slot before reslicing: the popped entry's replayKey strings would
	// otherwise stay referenced by the backing array until a later push overwrites the index, so at
	// low post-spike traffic the memory an expired nonce holds is not reclaimed though it is evicted.
	r.heap[n] = replayEntry{}
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
	Partition    Partition // zero for a Global route
	Capabilities CapabilitySet
}

// Authorizer is the ONE enforcement seam. It is constructed once by the trusted host with a
// paired Verifier, the deployment it serves, pinned trust (home + foreign), an immutable
// route table, and a clock. Handlers receive it and call Authorize; they cannot construct or
// select it, nor supply a route, clock, nonce, trust, or capability.
type Authorizer struct {
	verifier           *mint.Verifier
	expectedDeployment string
	audience           string
	trust              map[string]RealmTrust
	routes             map[OperationID]Route
	mono               *monoClock
	replay             *replayStore
}

// GoString and String redact the handler-facing Authorizer: it holds the Verifier (and thus the
// minting key), so ordinary formatting/logging must never expand it into its fields (R-2422 (1)).
func (a *Authorizer) GoString() string { return "warrant.Authorizer{redacted: holds Verifier key}" }
func (a *Authorizer) String() string   { return "warrant.Authorizer{redacted}" }

// NewAuthorizer validates the receiver config, every trust entry, and every route at
// construction (fail-closed): nil verifier, empty deployment, invalid home trust, an invalid or
// audience-mismatched or home-colliding or duplicate foreign entry, or an invalid/duplicate
// route all reject. pinnedTrust also BINDS each entry's policy digest here, so the value
// Authorize compares is fixed at construction. A nil clock defaults to real wall time.
func NewAuthorizer(verifier *Verifier, expectedDeployment string, clock Clock, routes []Route, home RealmTrust, foreign ...RealmTrust) (*Authorizer, error) {
	if verifier == nil || expectedDeployment == "" {
		return nil, ErrDenied
	}
	trust, err := pinnedTrust(home, foreign)
	if err != nil {
		return nil, err
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
		verifier:           verifier,
		expectedDeployment: expectedDeployment,
		audience:           home.Audience,
		trust:              trust,
		routes:             rm,
		mono:               &monoClock{clock: clock},
		replay:             newReplayStore(),
	}, nil
}

// trustAccepts verifies the principal's sealed assertion against pinned trust and the
// Authorizer's OWN clock: the principal's realm must have a live (unrevoked, unexpired) trust
// entry whose bound policy digest matches the identity the assertion presents — realm, issuer,
// audience and policy version in one comparison (policyMatches) — the token must not be
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
	return e.policyMatches(p)
}

// Authorize enforces every invariant, in order: (1) seal verified against the receiver's own
// secret, constant-time; (2) subject validity + deployment admission; (3) immutable
// server-operation route lookup; (4) sealed assertion trust + expiry against the owned clock;
// (5) sealed capabilities parsed + partition/realm/capability binding; (6) atomic replay consume
// LAST, only after every prior check passes, so a failed attempt cannot poison a nonce.
// Non-disclosing: every failure is the one denial of op (denial), whichever check refused it.
// bodyPartition is the op-specific partition (compare-only).
func (a *Authorizer) Authorize(ctx context.Context, principal VerifiedPrincipal, op OperationID, bodyPartition string) (Identity, error) {
	id, err := a.authorize(ctx, principal, op, bodyPartition)
	if err != nil {
		return Identity{}, a.denial(op)
	}
	return id, nil
}

// denial is Authorize's one refusal of op: a *DeniedError naming the capability op's route
// requires when the route table holds op, and the bare ErrDenied for an unwired Authorizer or
// an operation it holds no route for, which has no capability to name. It reads only the
// immutable route table, so it depends on nothing the failed check saw.
func (a *Authorizer) denial(op OperationID) error {
	if a == nil {
		return ErrDenied
	}
	route, ok := a.routes[op]
	if !ok {
		return ErrDenied
	}
	return &DeniedError{Required: route.required.String()}
}

// authorize runs Authorize's checks in the order its doc gives and returns ErrDenied from the
// first that fails; Authorize turns that into op's one denial.
func (a *Authorizer) authorize(ctx context.Context, principal VerifiedPrincipal, op OperationID, bodyPartition string) (Identity, error) {
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
	if principal.Subject().ID == "" || principal.Subject().Kind == "" || principal.Deployment() != a.expectedDeployment {
		return Identity{}, ErrDenied
	}
	// (2a) representation consistency — HasPartition must agree with Partition presence (assurance HOLD 4).
	if principal.HasPartition() != (principal.Partition() != "") {
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
	// (4) sealed capabilities parsed here (never caller-authored) as ONE set: a malformed element, a
	// cross-realm element (assurance HOLD 1) or a set past MaxCapabilitiesPerSet denies the whole set
	// rather than part of it (ParseHeldSet). This and the partition/global binding below are
	// DETERMINISTIC (no clock), so they run BEFORE the single time sample: a malformed/unmet-capability
	// or wrong-partition denial reads the clock ZERO times, and only a decision that has passed EVERY
	// deterministic authority check reaches the clock — so no capability-bundle work can age the
	// decision instant between admission and consume.
	held, err := ParseHeldSet(principal.Capabilities(), principal.Realm())
	if err != nil {
		return Identity{}, ErrDenied
	}
	id := Identity{Subject: principal.Subject(), Capabilities: held}
	switch route.mode {
	case modePartitionBound:
		partition := principal.Partition()
		if !principal.HasPartition() || !validPartition(partition) || partition != bodyPartition {
			return Identity{}, ErrDenied
		}
		os := newPartition(route.required.Realm(), partition)
		if os.IsZero() || !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
		id.Partition = os
	case modeGlobal:
		// global routes deny ANY partition material (assurance HOLD 4).
		if principal.HasPartition() || principal.Partition() != "" || bodyPartition != "" {
			return Identity{}, ErrDenied
		}
		if !held.Allows(route.required) {
			return Identity{}, ErrDenied
		}
	default:
		return Identity{}, ErrDenied
	}
	// (5) ONE authoritative decision instant, sampled EXACTLY ONCE here — after every DETERMINISTIC
	// authority check above (seal, subject, deployment, representation, nonce, route, realm, capability,
	// partition/global) and immediately before the two time-dependent steps, which share it. A single
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
