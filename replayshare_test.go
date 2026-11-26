/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import (
	"context"
	"fmt"
	"testing"
)

// One subject driving fresh nonces cannot fill the replay store and refuse everyone: past half its
// capacity the store refuses that subject's surplus, and another subject is still authorized.
func TestOneSubjectCannotFillTheReplayStoreForEveryone(t *testing.T) {
	v, _ := NewVerifier()
	a := newAuthz(t, v, fixedClock(5000))
	a.replay = &replayStore{consumed: map[replayKey]int64{}, maxEntries: 8}
	flood := 0
	for i := 0; i < 32; i++ {
		p := mustMint(t, v, withNonce(baseAssertion(), fmt.Sprintf("flood-%02d", i)))
		if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err == nil {
			flood++
		}
	}
	if flood == 0 || flood >= 8 {
		t.Fatalf("the flooding subject was admitted %d times, want some and fewer than the capacity", flood)
	}
	other := baseAssertion()
	other.Subject = Subject{ID: "u2", Kind: "user"}
	for i := 0; i < 2; i++ {
		p := mustMint(t, v, withNonce(other, fmt.Sprintf("other-%02d", i)))
		if _, err := a.Authorize(context.Background(), p, "device.read", "acme"); err != nil {
			t.Fatalf("another subject was refused after one subject's flood: %v", err)
		}
	}
	if n := len(a.replay.consumed); n > 8 {
		t.Fatalf("the store holds %d live entries, over its capacity 8", n)
	}
}
