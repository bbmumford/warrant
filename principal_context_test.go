/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package warrant

import (
	"context"
	"testing"
)

// A principal written to a context is readable from it, and authorizes exactly
// as the same principal passed directly. This is the leg that proves the carrier
// works: it writes, reads back, and reaches a real allow through the authorizer
// rather than asserting a denial that several unrelated faults also produce.
func TestAuthorizeFromContext_MintedPrincipalIsAllowed(t *testing.T) {
	v, _ := NewVerifier()
	az := newAuthz(t, v, fixedClock(5000))
	ctx := WithPrincipal(context.Background(), mustMint(t, v, baseAssertion()))

	id, err := AuthorizeFromContext(ctx, az, "device.read", "acme")
	if err != nil {
		t.Fatalf("a minted principal on the context must authorize: %v", err)
	}
	if id.Partition.Partition() != "acme" {
		t.Fatalf("partition = %q, want acme — the carrier must not alter the identity", id.Partition.Partition())
	}
}

// A context that never carried a principal reports absence rather than a zero
// principal. The distinction is the reason the carrier returns a second value:
// a zero-but-present principal reads as a subject holding nothing, which a
// caller can mistake for a valid caller with an empty grant.
func TestPrincipalContext_AbsentReportsNotPresent(t *testing.T) {
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("a bare context must report no principal")
	}
}

// An unwired Authorizer denies. Like the absent-principal case below, this has
// two causes: Authorize opens with its own nil-seam check, so deleting the guard
// in AuthorizeFromContext leaves this test green. Both tests state a contract a
// caller may rely on; neither pins the line that implements it.
func TestAuthorizeFromContext_NilAuthorizerDenies(t *testing.T) {
	ctx := WithPrincipal(context.Background(), mustMint(t, mustVerifier(t), baseAssertion()))
	if _, err := AuthorizeFromContext(ctx, nil, "device.read", "acme"); err != ErrDenied {
		t.Fatalf("err = %v, want ErrDenied when the authorizer is unwired", err)
	}
}

// An absent principal denies. The Authorizer independently refuses a zero-value
// principal, so this denial also has two causes and removing the context guard
// does not turn it red.
//
// Both guards are kept anyway, and the redundancy is the point: AuthorizeFromContext
// would otherwise depend on Authorize's internal nil-seam and zero-principal
// handling staying as they are, which is a coupling to another type's internals
// that nothing here would notice breaking. What no test at this layer can do is
// tell the two causes apart — measured by mutation, not assumed.
func TestAuthorizeFromContext_AbsentPrincipalDenies(t *testing.T) {
	v, _ := NewVerifier()
	az := newAuthz(t, v, fixedClock(5000))
	if _, err := AuthorizeFromContext(context.Background(), az, "device.read", "acme"); !denied(err) {
		t.Fatalf("err = %v, want denied when no principal was minted", err)
	}
}

func mustVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}
