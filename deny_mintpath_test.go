package warrant

import (
	"context"
	"testing"
)

// A REVOCATION MUST SURVIVE THE SEAL. Capabilities cross the mint as opaque
// strings and are parsed back inside Authorize, so a negative capability is only
// honoured if the "-" survives sealing AND the parse feeds CapabilitySet.Allows
// rather than any string comparison. Nothing else in this file's suite carries a
// deny through a minted principal — Allows is tested directly, which cannot show
// that the string reaches it intact.
//
// This is the path a scope converter's output takes: ScopesToCapabilities now
// emits denies, so they land in an Assertion's capability list and reach a real
// authorization decision here.
func TestSealedNegativeCapabilityDeniesTheRoute(t *testing.T) {
	withCaps := func(caps []string, nonce string) Assertion {
		as := baseAssertion()
		as.Capabilities = caps
		as.Nonce = nonce
		return as
	}

	// Positive control FIRST: without the revocation, the wildcard confers read.
	// Without this leg a later denial could just as easily be the wildcard
	// failing to reach the route at all.
	t.Run("wildcard alone confers the action", func(t *testing.T) {
		v, _ := NewVerifier()
		a := newAuthz(t, v, fixedClock(5000))
		as := withCaps([]string{"orbtr.io:device.*"}, "nonce-deny-control")
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); err != nil {
			t.Fatalf("wildcard should confer device.read through the seal; got %v", err)
		}
	})

	t.Run("a sealed deny beats the wildcard that would confer it", func(t *testing.T) {
		v, _ := NewVerifier()
		a := newAuthz(t, v, fixedClock(5000))
		as := withCaps([]string{"orbtr.io:device.*", "-orbtr.io:device.read"}, "nonce-deny-read")
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
			t.Fatal("a sealed negative capability was not honoured: the wildcard conferred a " +
				"revoked action through the mint path")
		}
	})

	t.Run("the deny reaches only the action it names", func(t *testing.T) {
		v, _ := NewVerifier()
		a := newAuthz(t, v, fixedClock(5000))
		as := withCaps([]string{"orbtr.io:device.*", "-orbtr.io:device.read"}, "nonce-deny-admin")
		if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.admin", "acme"); err != nil {
			t.Fatalf("revoking device.read must not revoke device.admin; got %v", err)
		}
	})
}

// A deny is realm-checked like any other capability. Authorize rejects a
// principal holding a capability outside its own realm, and stripping "-" before
// validation is what makes a negative capability's realm readable at all: left
// on, the realm parses as "-orbtr.io" and this leg would pass by naming a realm
// that exists nowhere.
func TestSealedNegativeCapabilityIsRealmChecked(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	as := baseAssertion()
	as.Capabilities = []string{"orbtr.io:device.read", "-orbtr.ai:device.read"}
	as.Nonce = "nonce-deny-foreign-realm"
	if _, err := a.Authorize(context.Background(), mustMint(t, v, as), "device.read", "acme"); !denied(err) {
		t.Fatal("a capability outside the principal's realm must deny the whole bundle, " +
			"whether positive or negative")
	}
}
