/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package warrant

import (
	"context"
	"strings"
	"testing"
)

// A denial of a routed operation names the capability its route requires, and
// names it the same way on every leg, so the text still never says which leg
// failed: an unmet capability, a partition that is not the body's, a forged seal
// and a spent nonce all read alike. ErrDenied stays what every denial unwraps
// to. An operation the route table does not hold has no capability to name and
// is refused with the bare ErrDenied.
func TestADenialNamesTheRouteCapabilityAlikeOnEveryLeg(t *testing.T) {
	v := mustVerifier(t)
	az := newAuthz(t, v, fixedClock(1_000))
	ctx := context.Background()

	unmet := baseAssertion()
	unmet.Capabilities = []string{"orbtr.io:device.admin"}
	unmet.Nonce = "nonce-unmet-01"

	other, _ := NewVerifier()
	legs := map[string]func() error{
		"unmet capability": func() error {
			_, err := az.Authorize(ctx, mustMint(t, v, unmet), "device.read", "acme")
			return err
		},
		"partition not the body's": func() error {
			_, err := az.Authorize(ctx, mustMint(t, v, withNonce(baseAssertion(), "nonce-part-01")), "device.read", "other")
			return err
		},
		"seal from another verifier": func() error {
			_, err := az.Authorize(ctx, mustMint(t, other, withNonce(baseAssertion(), "nonce-forg-01")), "device.read", "acme")
			return err
		},
		"spent nonce": func() error {
			p := mustMint(t, v, withNonce(baseAssertion(), "nonce-spent-1"))
			if _, err := az.Authorize(ctx, p, "device.read", "acme"); err != nil {
				t.Fatalf("first use: %v", err)
			}
			_, err := az.Authorize(ctx, p, "device.read", "acme")
			return err
		},
	}
	texts := map[string]bool{}
	for name, leg := range legs {
		err := leg()
		if !denied(err) {
			t.Fatalf("%s: err = %v, want a denial unwrapping to ErrDenied", name, err)
		}
		if !strings.Contains(err.Error(), "orbtr.io:device.read") {
			t.Errorf("%s: denial %q does not name the route's capability orbtr.io:device.read", name, err.Error())
		}
		texts[err.Error()] = true
	}
	if len(texts) != 1 {
		t.Errorf("the legs' denials read %d ways, want one: %v", len(texts), texts)
	}

	_, err := az.Authorize(ctx, mustMint(t, v, withNonce(baseAssertion(), "nonce-unk-001")), "device.unknown", "acme")
	if err != ErrDenied {
		t.Errorf("unrouted operation: err = %v, want the bare ErrDenied", err)
	}
}
