/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package warrant

import (
	"strings"
	"testing"
)

func reservedQoS() GrantPolicy {
	return GrantPolicy{Reserved: map[string]struct{}{"qos": {}}}
}

// A role authored with a reserved capability does not confer it. This is the
// leg that matters once grants are authored rather than derived: a role is an
// open set a tenant may write, so naming the reserved family directly is the
// path that reaches authority, and nothing upstream filters it.
func TestGrant_AuthoredReservedCapabilityIsNotConferred(t *testing.T) {
	got, err := reservedQoS().Grant([]string{
		"orbtr.ai:conversation.read",
		"orbtr.ai:qos.unrestricted",
	})
	if err == nil {
		t.Fatal("authoring a reserved capability must report an error")
	}
	if !strings.Contains(err.Error(), "orbtr.ai:qos.unrestricted") {
		t.Errorf("error must name the refused entry, got %q", err)
	}

	set := NewCapabilitySet(got...)
	reserved, _ := ParseCapability("orbtr.ai:qos.unrestricted")
	if set.Allows(reserved) {
		t.Fatal("a reserved capability was conferred by an authored grant")
	}

	// The positive leg: the rest of the role still works, so the refusal is
	// narrow rather than a blanket rejection of the whole grant.
	ordinary, _ := ParseCapability("orbtr.ai:conversation.read")
	if !set.Allows(ordinary) {
		t.Fatal("refusing one reserved entry must not drop the rest of the grant")
	}
}

// The guard does not depend on the caller reading err. A consumer that logs and
// proceeds still does not confer the reserved family, so a forgotten error check
// cannot reopen the hole.
func TestGrant_ReservedIsAbsentEvenWhenErrorIsIgnored(t *testing.T) {
	got, _ := reservedQoS().Grant([]string{"orbtr.ai:qos.unrestricted"})
	if len(got) != 0 {
		t.Fatalf("returned set must contain no reserved capability, got %v", got)
	}
}

// A deny naming a reserved resource is kept. Withholding a revocation could only
// widen access, and a grant that revokes what it could not have granted costs
// nothing.
func TestGrant_ReservedDenyIsKept(t *testing.T) {
	got, err := reservedQoS().Grant([]string{"-orbtr.ai:qos.unrestricted"})
	if err != nil {
		t.Fatalf("a reserved deny must be admitted: %v", err)
	}
	if len(got) != 1 || !got[0].IsDeny() {
		t.Fatalf("expected one deny capability, got %v", got)
	}
}

// An unparseable entry is reported rather than silently dropped, so a typo in a
// stored role is visible at load instead of as an unexplained denial later.
func TestGrant_UnparseableIsReported(t *testing.T) {
	got, err := reservedQoS().Grant([]string{"orbtr.ai:conversation.read", "not-a-capability"})
	if err == nil || !strings.Contains(err.Error(), "not-a-capability") {
		t.Fatalf("unparseable entry must be named in the error, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the parseable entry must survive, got %v", got)
	}
}

// With no reserved family configured the policy admits every well-formed grant,
// so a consumer that reserves nothing behaves exactly as one that parses the
// list itself.
func TestGrant_NoReservedFamilyAdmitsEverything(t *testing.T) {
	got, err := GrantPolicy{}.Grant([]string{"orbtr.ai:qos.unrestricted", "orbtr.ai:conversation.read"})
	if err != nil {
		t.Fatalf("an empty reserved set must admit every valid capability: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected both capabilities, got %v", got)
	}
}

// A reserved resource is refused however the action is written, including the
// action wildcard — otherwise naming qos.* would confer the family the exact
// spelling is refused for.
func TestGrant_ReservedRefusedUnderAnyAction(t *testing.T) {
	for _, s := range []string{"orbtr.ai:qos.unrestricted", "orbtr.ai:qos.*", "orbtr.ai:qos.anything"} {
		got, err := reservedQoS().Grant([]string{s})
		if err == nil {
			t.Errorf("%s: must be refused", s)
		}
		if len(got) != 0 {
			t.Errorf("%s: conferred %v, want nothing", s, got)
		}
	}
}
