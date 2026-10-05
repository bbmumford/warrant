/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package warrant

import (
	"context"
	"fmt"
	"testing"
)

// heldSetOf builds n distinct well-formed capabilities of realm, so a test can stand a
// set at the limit beside one past it with nothing else different between them.
func heldSetOf(realm string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s:res%d.read", realm, i))
	}
	return out
}

func TestParseHeldSet_WholeSetOrNothing(t *testing.T) {
	cases := []struct {
		name  string
		held  []string
		realm string
		ok    bool
	}{
		{"a set of the realm's capabilities parses", []string{"orbtr.io:device.read", "-orbtr.io:device.admin"}, homeRealm, true},
		{"an empty set parses and confers nothing", nil, homeRealm, true},
		{"a malformed element refuses the whole set", []string{"orbtr.io:device.read", "orbtr.io:device"}, homeRealm, false},
		{"a mistyped deny refuses the whole set", []string{"orbtr.io:token.*", "-orbtr.io:token.MINT"}, homeRealm, false},
		{"a cross-realm element refuses the set when a realm is named", []string{"orbtr.io:device.read", "orbtr.ai:device.read"}, homeRealm, false},
		{"an empty realm accepts every realm", []string{"orbtr.io:device.read", "orbtr.ai:device.read"}, "", true},
		{"a set at the limit parses", heldSetOf(homeRealm, MaxCapabilitiesPerSet), homeRealm, true},
		{"a set one past the limit refuses", heldSetOf(homeRealm, MaxCapabilitiesPerSet+1), homeRealm, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := ParseHeldSet(c.held, c.realm)
			if c.ok {
				if err != nil {
					t.Fatalf("ParseHeldSet(%d elements, realm %q) = %v, want a set", len(c.held), c.realm, err)
				}
				return
			}
			if !denied(err) {
				t.Fatalf("ParseHeldSet(%d elements, realm %q) = %v, want ErrDenied", len(c.held), c.realm, err)
			}
			if set.Allows(mustCap(t, "orbtr.io:device.read")) {
				t.Fatal("a refused set conferred a capability")
			}
		})
	}
}

// One malformed element denies a capability the valid elements beside it would admit, and
// the same set with that element spelled correctly admits it: the pair is what makes the
// refusal whole-set rather than a parse that happens to drop one string.
func TestParseHeldSet_MalformedElementDeniesWhatTheRestWouldAdmit(t *testing.T) {
	required := mustCap(t, "orbtr.io:device.read")
	good, err := ParseHeldSet([]string{"orbtr.io:device.read", "orbtr.io:token.mint"}, homeRealm)
	if err != nil || !good.Allows(required) {
		t.Fatalf("a well-formed set must admit device.read: err=%v", err)
	}
	spoiled, err := ParseHeldSet([]string{"orbtr.io:device.read", "orbtr.io:token..mint"}, homeRealm)
	if !denied(err) || spoiled.Allows(required) {
		t.Fatal("one malformed element must deny the capability the valid elements admit")
	}
}

func TestParseGrantSet_ReadsCapabilitiesBesideTheDottedVocabulary(t *testing.T) {
	required := mustCap(t, "orbtr.io:device.read")
	cases := []struct {
		name   string
		grants []string
		realm  string
		admits bool
		denied bool
	}{
		{"a capability of the realm admits", []string{"orbtr.io:device.read"}, homeRealm, true, false},
		{"a dotted scope string beside it is not an element",
			[]string{"orbtr.io.device.write", "orbtr.io:device.read"}, homeRealm, true, false},
		{"a dotted deny beside it is not an element either",
			[]string{"-orbtr.io.device.read", "orbtr.io:device.read"}, homeRealm, true, false},
		{"another realm's capability is left out, not refused",
			[]string{"orbtr.ai:device.read", "orbtr.io:device.read"}, homeRealm, true, false},
		{"a capability-shaped element that does not parse refuses the whole set",
			[]string{"orbtr.io:device.read", "orbtr.io:device"}, homeRealm, false, true},
		{"a mistyped deny refuses the whole set",
			[]string{"orbtr.io:device.*", "-orbtr.io:device.READ"}, homeRealm, false, true},
		{"a set one past the limit refuses", heldSetOf(homeRealm, MaxCapabilitiesPerSet+1), homeRealm, false, true},
		{"no realm refuses", []string{"orbtr.io:device.read"}, "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := ParseGrantSet(c.grants, c.realm)
			if c.denied != denied(err) {
				t.Fatalf("ParseGrantSet(%v, %q) err = %v, want denied=%v", c.grants, c.realm, err, c.denied)
			}
			if got := set.Allows(required); got != c.admits {
				t.Fatalf("ParseGrantSet(%v, %q).Allows(device.read) = %v, want %v", c.grants, c.realm, got, c.admits)
			}
		})
	}
}

// Through Authorize: a sealed set at the limit authorizes its route and the same set with
// one more element denies, so the limit is enforced where a decision is made and not only
// in the parser.
func TestAuthorize_SetPastTheLimitDenied(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))

	atLimit := baseAssertion()
	atLimit.Capabilities = append(heldSetOf(homeRealm, MaxCapabilitiesPerSet-1), "orbtr.io:device.read")
	atLimit.Nonce = "nonce-at-limit"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, atLimit), "device.read", "acme"); err != nil {
		t.Fatalf("a set at MaxCapabilitiesPerSet must authorize: %v", err)
	}

	past := baseAssertion()
	past.Capabilities = append(heldSetOf(homeRealm, MaxCapabilitiesPerSet), "orbtr.io:device.read")
	past.Nonce = "nonce-past-limit"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, past), "device.read", "acme"); !denied(err) {
		t.Fatal("a set past MaxCapabilitiesPerSet must be DENIED")
	}
}

// Through Authorize: one malformed element in the sealed set denies a route the valid
// elements beside it satisfy.
func TestAuthorize_MalformedSealedElementDeniesWholeSet(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))

	as := baseAssertion()
	as.Capabilities = []string{"orbtr.io:device.read", "-orbtr.io:device.ADMIN"}
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("a malformed element must deny the route the valid elements satisfy")
	}
}
