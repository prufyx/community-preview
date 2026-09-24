package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/constraintengine"
)

const cronJobRuleID = "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"

// anchorOnlyRange returns a range that licenses nothing beyond the anchor
// pair: from [anchor.from, anchor.from+1 patch), to [anchor.to, anchor.to+1
// patch), every bound ANCHOR_ONLY. It exercises the ranged schema, contract
// and plumbing without widening any reviewed claim.
func anchorOnlyRange(t *testing.T, rule json.RawMessage) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(rule, &value); err != nil {
		t.Fatal(err)
	}
	subject := value["subject"].(map[string]any)
	source := value["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["id"].(string)
	next := func(version string) string {
		parts := strings.Split(version, ".")
		if parts[2] != "0" {
			t.Fatalf("fixture expects a .0 anchor, got %s", version)
		}
		return parts[0] + "." + parts[1] + ".1"
	}
	bounds := []any{}
	for _, name := range []string{"from.gte", "from.lt", "to.gte", "to.lt"} {
		bounds = append(bounds, map[string]any{"bound": name, "basis": constraintengine.BasisAnchorOnly, "sourceId": source})
	}
	value["range"] = map[string]any{
		"from":   map[string]any{"gte": subject["from"], "lt": next(subject["from"].(string))},
		"to":     map[string]any{"gte": subject["to"], "lt": next(subject["to"].(string))},
		"bounds": bounds,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withAnchorOnlyRange(t *testing.T, pack rulePack, ruleID string) rulePack {
	t.Helper()
	entries := append([]Entry(nil), pack.Entries...)
	changed := false
	for index, entry := range entries {
		var shape struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) == nil && shape.ID == ruleID {
			entries[index].Rule = anchorOnlyRange(t, entry.Rule)
			changed = true
		}
	}
	if !changed {
		t.Fatalf("rule %s missing", ruleID)
	}
	pack.Entries = entries
	return pack
}

func kubernetesInput(t *testing.T, from, to string, cronJobPresent bool) []byte {
	t.Helper()
	value := "false"
	if cronJobPresent {
		value = "true"
	}
	return []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + from + `","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + to + `","facts":[{"id":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","state":"declared","boolValue":` + value + `}]}]}}`)
}

var rangeReviewClock = time.Date(2026, 9, 23, 12, 36, 0, 0, time.UTC)

// TestPackSchemaStatesRangeUse: the embedded pack has no range and keeps the
// original schema; a pack that gains a range must carry the new schema, and a
// pack without one may not.
func TestPackSchemaStatesRangeUse(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if base.pack.Schema != packSchema || !validPackSchema(base.pack) {
		t.Fatalf("embedded pack schema=%s", base.pack.Schema)
	}
	ranged := withAnchorOnlyRange(t, base.pack, cronJobRuleID)
	if validPackSchema(ranged) {
		t.Fatal("ranged pack accepted under the exact-only schema")
	}
	ranged.Schema = packSchemaRanged
	if !validPackSchema(ranged) {
		t.Fatal("ranged pack rejected under the ranged schema")
	}
	exact := base.pack
	exact.Schema = packSchemaRanged
	if validPackSchema(exact) {
		t.Fatal("exact-only pack accepted under the ranged schema")
	}
}

// TestExternalBundleRangeSchemaGate: an external bundle carrying a range is
// admitted only under the ranged pack schema. Binaries that predate ranges
// compare the pack schema with the exact-only string and reject the bundle;
// under that string this binary rejects it too.
func TestExternalBundleRangeSchemaGate(t *testing.T) {
	entry := ruleEntry(t, "kubernetes", cronJobRuleID)
	pack := withAnchorOnlyRange(t, rulePack{Entries: []Entry{entry}}, cronJobRuleID)
	// externalFixture upgrades the schema for ranged packs, so force the
	// exact-only schema here to prove the parser itself refuses a range.
	var document externalFixtureDocument
	if err := json.Unmarshal(externalFixture(t, pack.Entries), &document); err != nil {
		t.Fatal(err)
	}
	document.Pack.Schema = packSchema
	rawExact, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseExternalBundle(rawExact); err == nil {
		t.Fatal("range admitted under the exact-only pack schema")
	}
	document.Pack.Schema = packSchemaRanged
	rawRanged, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExternalBundle(rawRanged)
	if err != nil {
		t.Fatalf("ranged external bundle rejected: %v", err)
	}
	report, err := parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || report.Check.EngineContractDigest != constraintengine.EngineContractDigestRanged() {
		t.Fatalf("report=%+v", report.Check)
	}
	// Still exact-only in effect: the anchor-only range matches nothing wider.
	report, err = parsed.EvaluateRule("kubernetes", cronJobRuleID, kubernetesInput(t, "1.24.17", "1.25.3", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" || report.Check.Claims[0].ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" {
		t.Fatalf("report=%+v", report.Check)
	}
}

// TestRangeAwarePrefilterSelectsThroughTheMatcher: the per-project path narrows
// the pack with the shared matcher and renders the document under the schema
// its selection requires.
func TestRangeAwarePrefilterSelectsThroughTheMatcher(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	ranged := base
	ranged.pack = withAnchorOnlyRange(t, base.pack, cronJobRuleID)
	ranged.pack.Schema = packSchemaRanged
	report, err := ranged.check("kubernetes", "", kubernetesInput(t, "1.24.0", "1.25.0", true), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, claim := range report.Check.Claims {
		if claim.Status == "BLOCKED" {
			blocked++
		}
	}
	if blocked != 1 || report.Check.EngineContractDigest != constraintengine.EngineContractDigestRanged() {
		t.Fatalf("claims=%+v digest=%s", report.Check.Claims, report.Check.EngineContractDigest)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
	// Rules selected without the ranged rule render under the exact schema.
	exactOnly, err := ranged.rulesForAdmittedInput("kubernetes", kubernetesInput(t, "1.21.0", "1.22.0", true))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := constraintengine.Evaluate(mustInput(t, ranged, kubernetesInput(t, "1.21.0", "1.22.0", true)), exactOnly, rangeReviewClock)
	if err != nil || engine.EngineContractDigest != constraintengine.EngineContractDigest() {
		t.Fatalf("exact selection digest=%s err=%v", engine.EngineContractDigest, err)
	}
}

func mustInput(t *testing.T, b bundle, raw []byte) constraintengine.Input {
	t.Helper()
	input, err := constraintengine.ParseInput(raw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// TestUnrangedPackNeverWidens: with the published pack, an in-range patch pair
// such as 1.24.17 -> 1.25.3 decides nothing. Every claim stays UNKNOWN and the
// exit code stays UNKNOWN, whatever the declared fact says.
func TestUnrangedPackNeverWidens(t *testing.T) {
	for _, present := range []bool{false, true} {
		report, err := Check("kubernetes", kubernetesInput(t, "1.24.17", "1.25.3", present), rangeReviewClock)
		if err != nil {
			t.Fatal(err)
		}
		for _, claim := range report.Check.Claims {
			if claim.Status != "UNKNOWN" || claim.SubjectMatch != nil {
				t.Fatalf("claim=%+v", claim)
			}
		}
		if ClaimExit(report) != 11 || report.Check.EngineContractDigest != constraintengine.EngineContractDigest() {
			t.Fatalf("exit=%d digest=%s", ClaimExit(report), report.Check.EngineContractDigest)
		}
	}
	scoped := strings.Replace(string(kubernetesInput(t, "1.24.17", "1.25.3", false)), `}]}]}}`, `}]}]},"scope":{"declaration":"`+constraintengine.ScopeDeclaration+`","components":["pkg:github/kubernetes/kubernetes"]}}`, 1)
	scope, err := AssessScope([]byte(scoped), rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%s", scope.Assessment)
	}
	if _, err := Check("kubernetes", kubernetesInput(t, "v1.24.17", "1.25.3", true), rangeReviewClock); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v-prefixed version err=%v", err)
	}
}
