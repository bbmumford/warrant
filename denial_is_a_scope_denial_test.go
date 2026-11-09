/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package warrant

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bbmumford/loom/pkg/rpc/scope"
)

// Every denial is a refusal of the caller's authority as loom reads one: it
// unwraps to scope.ErrDenied, which loom's registry reports as the handler's
// denial, dispatch.StampDenial stamps on a response crossing the mesh, and the
// HTTP bridge answers 403, in its own process and through a proxy: the bridge's
// classifyHandlerStatus and classifyMeshError read only scope.ErrDenied as a
// refusal of the caller, and answer any other error a handler returns 500 in
// process and 400 through a proxy. Its text and its identity under errors.Is
// stay as they read.
func TestEveryDenialIsALoomScopeDenialAndReadsAsBefore(t *testing.T) {
	named := &DeniedError{Required: "orbtr.ai:assistants.read"}
	for name, err := range map[string]error{
		"the bare denial":                      ErrDenied,
		"a denial naming the capability":       named,
		"a denial behind the operation's name": fmt.Errorf("%s: %w", "orbtr.assistant.List", named),
	} {
		if !errors.Is(err, scope.ErrDenied) {
			t.Errorf("%s: %v does not unwrap to scope.ErrDenied", name, err)
		}
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v does not unwrap to ErrDenied", name, err)
		}
	}
	if got := ErrDenied.Error(); got != "authorization denied" {
		t.Errorf("ErrDenied reads %q, want %q", got, "authorization denied")
	}
	if got := named.Error(); got != "authorization denied: requires orbtr.ai:assistants.read" {
		t.Errorf("DeniedError reads %q", got)
	}
	if errors.Is(scope.ErrDenied, ErrDenied) {
		t.Errorf("scope.ErrDenied unwraps to ErrDenied: a loom scope refusal is not a warrant denial")
	}
}
