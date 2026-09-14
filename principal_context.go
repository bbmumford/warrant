/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package warrant

import "context"

// principalKeyT keys the minted principal on a request context. It is a private
// type with no exported value, so only this package can put a principal on a
// context or take one off: a caller cannot inject one, and a handler cannot be
// handed a principal by anything except the edge that minted it.
type principalKeyT struct{}

var principalKey principalKeyT

// WithPrincipal returns ctx carrying a minted principal. The trusted edge calls
// it once, after Mint, on a request whose authentication has completed;
// handlers only read.
//
// It lives here rather than in either product because a principal that crosses
// a product boundary must be read by the same key it was written with. A
// per-product carrier would mean a caller's held authority depends on which
// product answers, which is the same failure as a per-site resource vocabulary:
// the authority is real in one place and absent in another, and nothing reports
// the difference.
func WithPrincipal(ctx context.Context, p VerifiedPrincipal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext returns the minted principal and whether one is present.
//
// ok==false means no principal was minted onto this request, and a caller MUST
// treat that as unauthenticated rather than as an empty-but-valid identity.
// AuthorizeFromContext does exactly that; a caller reading this directly owns
// the same obligation.
func PrincipalFromContext(ctx context.Context) (VerifiedPrincipal, bool) {
	p, ok := ctx.Value(principalKey).(VerifiedPrincipal)
	return p, ok
}

// AuthorizeFromContext is the handler-facing seam: it takes the minted principal
// off ctx and runs it through az for one operation and that operation's
// body-supplied partition.
//
// A nil Authorizer and an absent principal are both ErrDenied, so a handler
// reached on a path where the edge never minted — a route mounted outside the
// authenticating middleware, or an authorizer left unwired at composition —
// denies instead of proceeding on a zero identity. Both are configuration
// mistakes, and each one fails closed on its own rather than relying on the
// other being present.
func AuthorizeFromContext(ctx context.Context, az *Authorizer, op OperationID, bodyPartition string) (Identity, error) {
	if az == nil {
		return Identity{}, ErrDenied
	}
	p, ok := PrincipalFromContext(ctx)
	if !ok {
		return Identity{}, ErrDenied
	}
	return az.Authorize(ctx, p, op, bodyPartition)
}
