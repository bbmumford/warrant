package warrant

import "testing"

func paramCap(t *testing.T, s string) Capability {
	t.Helper()
	c, err := ParseCapability(s)
	if err != nil {
		t.Fatalf("ParseCapability(%q): %v", s, err)
	}
	return c
}

// A parameter parses as one token in parentheses after a concrete action, carries
// through the canonical string, and is refused in every malformed shape.
func TestParseCapability_Parameter(t *testing.T) {
	for _, s := range []string{
		"orbtr:exec.approve(fs_delete)",
		"-orbtr:exec.approve(fs_delete)",
		"orbtr:exec.run_as(elevated)",
		"orbtr:exec.approve",
	} {
		if got := paramCap(t, s).String(); got != s {
			t.Errorf("round trip of %q gives %q", s, got)
		}
	}
	if got := paramCap(t, "orbtr:exec.run_as(user)").Param(); got != "user" {
		t.Errorf("Param = %q, want user", got)
	}
	if got := paramCap(t, "orbtr:exec.run_as").Param(); got != "" {
		t.Errorf("Param of a parameterless capability = %q, want empty", got)
	}
	for _, bad := range []string{
		"orbtr:exec.approve()",
		"orbtr:exec.approve(fs_delete",
		"orbtr:exec.approve(fs_delete)x",
		"orbtr:exec.approve(a(b))",
		"orbtr:exec.approve(FS)",
		"orbtr:exec.approve(a.b)",
		"orbtr:exec.*(fs_delete)",
		"orbtr:exec(x).approve",
		"orbtr:exec.approve)(",
	} {
		if _, err := ParseCapability(bad); err == nil {
			t.Errorf("ParseCapability(%q) admitted a malformed parameter", bad)
		}
	}
}

// A grant with no parameter covers its action for every parameter; a grant with a
// parameter covers that parameter only, and not a request for the action as a whole.
// A deny with no parameter refuses every parameter; a deny with one refuses that
// parameter and any request for the action as a whole, and leaves the others.
func TestCapabilitySet_Parameter(t *testing.T) {
	set := func(held ...string) CapabilitySet {
		caps := make([]Capability, 0, len(held))
		for _, h := range held {
			caps = append(caps, paramCap(t, h))
		}
		return NewCapabilitySet(caps...)
	}
	cases := []struct {
		name     string
		held     []string
		required string
		want     bool
	}{
		{"parameterless grant covers a parameter", []string{"orbtr:exec.approve"}, "orbtr:exec.approve(fs_delete)", true},
		{"parameter grant covers its own parameter", []string{"orbtr:exec.approve(fs_delete)"}, "orbtr:exec.approve(fs_delete)", true},
		{"parameter grant does not cover another", []string{"orbtr:exec.approve(fs_delete)"}, "orbtr:exec.approve(shell_exec)", false},
		{"parameter grant does not cover the whole action", []string{"orbtr:exec.approve(fs_delete)"}, "orbtr:exec.approve", false},
		{"action wildcard covers a parameter", []string{"orbtr:exec.*"}, "orbtr:exec.run_as(system)", true},
		{"another action's parameter is not covered", []string{"orbtr:exec.run_as(user)"}, "orbtr:exec.approve(user)", false},
		{"parameterless deny refuses every parameter", []string{"orbtr:exec.*", "-orbtr:exec.run_as"}, "orbtr:exec.run_as(user)", false},
		{"parameter deny refuses its parameter", []string{"orbtr:exec.*", "-orbtr:exec.run_as(system)"}, "orbtr:exec.run_as(system)", false},
		{"parameter deny leaves another parameter", []string{"orbtr:exec.*", "-orbtr:exec.run_as(system)"}, "orbtr:exec.run_as(user)", true},
		{"parameter deny refuses a request for the whole action", []string{"orbtr:exec.run_as", "-orbtr:exec.run_as(system)"}, "orbtr:exec.run_as", false},
		{"realm-wide deny refuses a parameter", []string{"orbtr:exec.approve", "-orbtr:*.*"}, "orbtr:exec.approve(fs_delete)", false},
	}
	for _, c := range cases {
		if got := set(c.held...).Allows(paramCap(t, c.required)); got != c.want {
			t.Errorf("%s: %v allows %s = %v, want %v", c.name, c.held, c.required, got, c.want)
		}
	}
	if !set("orbtr:exec.approve").Subsumes(set("orbtr:exec.approve(fs_delete)", "orbtr:exec.approve(shell_exec)")) {
		t.Error("a parameterless grant must subsume grants of its parameters")
	}
	if set("orbtr:exec.approve(fs_delete)").Subsumes(set("orbtr:exec.approve")) {
		t.Error("a grant of one parameter must not subsume the whole action")
	}
}

// The dotted member spelling carries the parameter through the scope conversion:
// a role's "orbtr.exec.approve(fs_delete)" becomes the capability with that parameter,
// and a dotted deny of one parameter becomes a deny of that parameter alone.
func TestScopeConversion_CarriesTheParameter(t *testing.T) {
	conv := ScopeConversion{Realm: "orbtr", KnownResources: []string{"exec"}}
	caps := conv.ScopesToCapabilities([]string{"orbtr.exec.approve(fs_delete)", "orbtr.exec.run_as", "-orbtr.exec.run_as(system)"})
	got := map[string]bool{}
	for _, c := range caps {
		got[c.String()] = true
	}
	for _, want := range []string{"orbtr:exec.approve(fs_delete)", "orbtr:exec.run_as", "-orbtr:exec.run_as(system)"} {
		if !got[want] {
			t.Errorf("conversion lost %s: got %v", want, got)
		}
	}
	held := NewCapabilitySet(caps...)
	if !held.Allows(paramCap(t, "orbtr:exec.run_as(user)")) || held.Allows(paramCap(t, "orbtr:exec.run_as(system)")) {
		t.Error("the converted set must allow run_as(user) and refuse run_as(system)")
	}
}
