package checkroutemetadata

import (
	"testing"

	"github.com/prufyx/prufyx-cli/internal/constraintengine"
)

// TestProjectFilterUsesTheSharedMatcher: version filters select by anchor or
// reviewed range, never by a separate string comparison.
func TestProjectFilterUsesTheSharedMatcher(t *testing.T) {
	exact := constraintengine.RuleTransition{Component: "pkg:github/kubernetes/kubernetes", From: "1.24.0", To: "1.25.0"}
	ranged := exact
	ranged.Range = &constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"}, To: constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"}}
	cases := []struct {
		name, project, from, to string
		subject                 constraintengine.RuleTransition
		excluded                bool
	}{
		{"no filter", "", "", "", exact, false},
		{"other project", "etcd", "", "", exact, true},
		{"exact anchor", "kubernetes", "1.24.0", "1.25.0", exact, false},
		{"exact patch pair", "kubernetes", "1.24.17", "1.25.3", exact, true},
		{"ranged patch pair", "kubernetes", "1.24.17", "1.25.3", ranged, false},
		{"ranged crossing violation", "kubernetes", "1.25.1", "1.25.4", ranged, true},
		{"ranged from only", "kubernetes", "1.24.17", "", ranged, false},
		{"exact from only", "kubernetes", "1.24.17", "", exact, true},
		{"ranged to only outside", "kubernetes", "", "1.26.0", ranged, true},
	}
	for _, tc := range cases {
		if got := projectFilter(tc.project, tc.from, tc.to, "kubernetes", tc.subject); got != tc.excluded {
			t.Errorf("%s: excluded=%v want %v", tc.name, got, tc.excluded)
		}
	}
}

// TestDiscoverPatchPairOnUnrangedPack: with no reviewed range published, a
// patch pair finds no rule, and the anchor pair is unchanged.
func TestDiscoverPatchPairOnUnrangedPack(t *testing.T) {
	patch, err := Discover("kubernetes", "1.24.17", "1.25.3")
	if err != nil {
		t.Fatal(err)
	}
	if patch.RuleCoverageState != "NO_MATCHING_EMBEDDED_RULE" || len(patch.Checks) != 0 {
		t.Fatalf("patch pair=%+v", patch)
	}
	anchor, err := Discover("kubernetes", "1.24.0", "1.25.0")
	if err != nil {
		t.Fatal(err)
	}
	if anchor.RuleCoverageState != "MATCHED" || len(anchor.Checks) != 7 {
		t.Fatalf("anchor checks=%d", len(anchor.Checks))
	}
	for _, check := range anchor.Checks {
		if check.Range != nil || check.MatchMode != "" {
			t.Fatalf("unranged check carries range fields: %+v", check)
		}
	}
}
