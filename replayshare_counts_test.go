/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package warrant

import "testing"

// At capacity every new nonce is refused, whoever presents it, and the held counts follow the
// evictions.
func TestTheReplayStoreFairShareFollowsEvictions(t *testing.T) {
	r := &replayStore{consumed: map[replayKey]int64{}, maxEntries: 4}
	k := func(n string) replayKey { return replayKey{issuer, aud, ver, homeRealm, n} }
	if !r.consumeFor(k("a1"), "a", 100, 10) || !r.consumeFor(k("a2"), "a", 100, 10) {
		t.Fatal("below half capacity a subject is admitted")
	}
	if r.consumeFor(k("a3"), "a", 100, 10) {
		t.Fatal("past half capacity the only subject holding entries kept being admitted")
	}
	if !r.consumeFor(k("b1"), "b", 100, 10) || !r.consumeFor(k("c1"), "c", 100, 10) {
		t.Fatal("a subject holding no entry was refused below capacity")
	}
	if r.consumeFor(k("d1"), "d", 100, 10) {
		t.Fatal("at capacity a new nonce was admitted")
	}
	if !r.consumeFor(k("a4"), "a", 500, 200) {
		t.Fatal("once every entry expired the subject was still refused")
	}
	if len(r.held) != 1 || r.held["a"] != 1 || len(r.owner) != 1 {
		t.Fatalf("held=%v owner=%d after the evictions, want only a's one entry", r.held, len(r.owner))
	}
}
