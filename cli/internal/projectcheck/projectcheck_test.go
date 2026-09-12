package projectcheck

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/constraintengine"
	"github.com/prufyx/prufyx-cli/internal/projectprepare"
)

func TestClosedRegistryAndScopedResults(t *testing.T) {
	projects, err := Projects()
	if err != nil || len(projects) != 6 || projects[0] != "argo-workflows" || projects[1] != "ceph" || projects[2] != "fluent-bit" || projects[3] != "grafana" || projects[4] != "kibana" || projects[5] != "loki" {
		t.Fatalf("projects=%v err=%v", projects, err)
	}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		project, raw string
		want         int
	}{
		{"grafana", "[alerting]\nenabled=true\n", 10},
		{"grafana", "[unified_alerting]\nenabled=true\n", 0},
		{"kibana", "xpack.reporting.roles.allow: [reporting_user]\n", 10},
		{"kibana", "server.host: localhost\n", 0},
		{"loki", "compactor:\n  shared_store: filesystem\n", 10},
		// Generic Check evaluates every reviewed rule for the transition; the
		// effective-config route uses CheckRule to preserve its single-rule UX.
		{"loki", "compactor:\n  working_directory: /var/loki\n", 11},
	} {
		prepared, err := projectprepare.PrepareEffectiveConfig(tc.project, []byte(tc.raw), map[string]string{"grafana": "10.4.0", "kibana": "8.18.0", "loki": "2.9.8"}[tc.project], map[string]string{"grafana": "11.0.0", "kibana": "9.0.0", "loki": "3.0.0"}[tc.project], true, true)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Check(tc.project, prepared.CanonicalInputJSON, now)
		if err != nil {
			t.Fatal(err)
		}
		if got := ClaimExit(report); got != tc.want {
			t.Fatalf("%s exit=%d want=%d", tc.project, got, tc.want)
		}
		raw, err := MarshalReport(report)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("reporting_user")) || bytes.Contains(raw, []byte("localhost")) {
			t.Fatal("private raw value leaked")
		}
		if report.Assessment != "UNKNOWN" || report.KnowledgeOrigin != "embedded_only" || report.RuntimeReproduced != 0 || report.NetworkUsed {
			t.Fatalf("authority fields=%+v", report)
		}
	}
}

func TestCheckRuleSealsNativeLokiSelection(t *testing.T) {
	prepared, err := projectprepare.PrepareLokiStructuredMetadata([]byte("limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"), projectprepare.LokiFrom, projectprepare.LokiTo, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckRule(projectprepare.LokiProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 2, 0, 0, 0, time.UTC), projectprepare.LokiStructuredMetadataRuleID)
	if err != nil || ClaimExit(report) != 0 || report.RequestedRuleID != projectprepare.LokiStructuredMetadataRuleID || report.SelectedRuleID != projectprepare.LokiStructuredMetadataRuleID || len(report.Check.Claims) != 1 {
		t.Fatalf("selected report=%+v err=%v", report, err)
	}
	encoded, err := MarshalReport(report)
	if err != nil || bytes.Contains(encoded, []byte("2024-01-01")) || bytes.Contains(encoded, []byte("boltdb-shipper")) {
		t.Fatalf("sealed report leaked input: err=%v bytes=%s", err, encoded)
	}
	if _, err := CheckRule(projectprepare.LokiProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 2, 0, 0, 0, time.UTC), "loki.unknown"); err != ErrInvalid {
		t.Fatalf("unknown requested route should be rejected: %v", err)
	}
	if _, err := CheckRule("grafana", prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 2, 0, 0, 0, time.UTC), "grafana.legacy-alerting-config.10-4-to-11-0"); err != ErrInvalid {
		t.Fatalf("cross-project requested route should be rejected: %v", err)
	}
	if _, err := CheckRule(projectprepare.LokiProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 2, 0, 0, 0, time.UTC), ""); err != ErrInvalid {
		t.Fatalf("blank requested route should be rejected: %v", err)
	}
	wrongPair, err := projectprepare.PrepareLokiStructuredMetadata([]byte("limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"), "2.9.7", projectprepare.LokiTo, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	wrongReport, err := CheckRule(projectprepare.LokiProject, wrongPair.CanonicalInputJSON, time.Date(2026, 9, 12, 2, 0, 0, 0, time.UTC), projectprepare.LokiStructuredMetadataRuleID)
	if err != nil || ClaimExit(wrongReport) != 11 || wrongReport.RequestedRuleID != projectprepare.LokiStructuredMetadataRuleID || wrongReport.SelectedRuleID != "" || len(wrongReport.Check.Claims) != 0 {
		t.Fatalf("wrong-pair ownership=%+v err=%v", wrongReport, err)
	}
	if _, err := MarshalReport(wrongReport); err != nil {
		t.Fatalf("wrong-pair sealed UNKNOWN should marshal: %v", err)
	}
	mutated := report
	mutated.RequestedRuleID = "loki.compactor-shared-store.2-9-to-3-0"
	if _, err := MarshalReport(mutated); err != ErrIntegrity {
		t.Fatalf("requested/selected identity mutation should fail seal: %v", err)
	}
	mutated = report
	mutated.SelectedRuleID = "loki.compactor-shared-store.2-9-to-3-0"
	if _, err := MarshalReport(mutated); err != ErrIntegrity {
		t.Fatalf("selected identity mutation should fail seal: %v", err)
	}
}

func TestFluentBitHTTP2SettingScope(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		raw                                  string
		complete, current, preserve, blocked bool
	}{
		{"[OUTPUT]\n  Name opentelemetry\n  http2 on\n", true, true, true, false},
		{"[OUTPUT]\n  Name opentelemetry\n  http2 force\n", true, true, true, false},
		{"[OUTPUT]\n  Name opentelemetry\n  http2 off\n", true, true, true, true},
		{"[OUTPUT]\n  Name opentelemetry\n", true, true, true, true},
		{"[OUTPUT]\n  Name opentelemetry\n  http2 on\n", true, false, true, false},
	} {
		prepared, err := projectprepare.PrepareFluentBit([]byte(tc.raw), projectprepare.FluentBitFrom, projectprepare.FluentBitTo, tc.complete, tc.current, tc.preserve)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Check(projectprepare.FluentBitProject, prepared.CanonicalInputJSON, now)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if tc.blocked {
			want = 10
		}
		if !tc.current {
			want = 11
		}
		if got := ClaimExit(report); got != want {
			t.Fatalf("raw=%q exit=%d want=%d report=%+v", tc.raw, got, want, report)
		}
	}
}

func TestFluentBitDuplicateInputRemainsUnknown(t *testing.T) {
	prepared, err := projectprepare.PrepareFluentBit([]byte("[OUTPUT]\n  Name opentelemetry\n  http2 on\n  http2 off\n"), projectprepare.FluentBitFrom, projectprepare.FluentBitTo, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check(projectprepare.FluentBitProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if got := ClaimExit(report); got != 11 || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "UNKNOWN" {
		t.Fatalf("duplicate input report=%+v", report)
	}
}

func TestArgoWorkflowsScopedResultAndWrongPair(t *testing.T) {
	now := time.Date(2026, 9, 11, 21, 0, 0, 0, time.UTC)
	workload := func(args string) []byte {
		return []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","command":["argo"],"args":[` + args + `],"env":[]}]}}}}`)
	}
	for _, tc := range []struct {
		args string
		want int
	}{
		{`"server","--basehref=/argo"`, 10},
		{`"server","--base-href=/argo"`, 0},
	} {
		prepared, err := projectprepare.PrepareWorkload(projectprepare.ArgoWorkflowsProject, workload(tc.args), projectprepare.ArgoWorkflowsFrom, projectprepare.ArgoWorkflowsTo, true)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Check(projectprepare.ArgoWorkflowsProject, prepared.CanonicalInputJSON, now)
		if err != nil || ClaimExit(report) != tc.want || len(report.Check.Claims) != 1 {
			t.Fatalf("args=%q report=%+v err=%v", tc.args, report, err)
		}
	}
	prepared, err := projectprepare.PrepareWorkload(projectprepare.ArgoWorkflowsProject, workload(`"server"`), "3.5.1", projectprepare.ArgoWorkflowsTo, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check(projectprepare.ArgoWorkflowsProject, prepared.CanonicalInputJSON, now)
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 0 {
		t.Fatalf("wrong pair report=%+v err=%v", report, err)
	}
}

func TestCephCurrentSideScopedResult(t *testing.T) {
	now := time.Date(2026, 9, 11, 21, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		store string
		want  int
	}{
		{"filestore", 10},
		{"bluestore", 0},
	} {
		prepared, err := projectprepare.PrepareSelectedOSDMetadata(projectprepare.CephProject, []byte(`{"id":7,"osd_objectstore":"`+tc.store+`"}`), "7", projectprepare.CephFrom, projectprepare.CephTo, true)
		if err != nil {
			t.Fatal(err)
		}
		report, err := Check(projectprepare.CephProject, prepared.CanonicalInputJSON, now)
		if err != nil || ClaimExit(report) != tc.want || len(report.Check.Claims) != 1 {
			t.Fatalf("store=%s report=%+v err=%v", tc.store, report, err)
		}
		if report.Check.Claims[0].RuleID != "ceph.selected-osd-filestore.17-2-to-18-2" {
			t.Fatalf("unexpected claim %+v", report.Check.Claims[0])
		}
	}
}

func TestWrongPairIncompleteAndUnknownProject(t *testing.T) {
	now := time.Date(2026, 9, 11, 20, 0, 0, 0, time.UTC)
	prepared, err := projectprepare.PrepareEffectiveConfig("grafana", []byte("[alerting]\nenabled=true\n"), "10.5.0", "11.1.0", true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check("grafana", prepared.CanonicalInputJSON, now)
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 0 || !bytes.Contains([]byte(report.NextAction), []byte("no reviewed rule matches")) {
		t.Fatalf("wrong pair report=%+v err=%v", report, err)
	}
	incomplete, err := projectprepare.PrepareEffectiveConfig("grafana", []byte("[alerting]\nenabled=true\n"), "10.4.0", "11.0.0", false, false)
	if err != nil {
		t.Fatal(err)
	}
	report, err = Check("grafana", incomplete.CanonicalInputJSON, now)
	if err != nil || ClaimExit(report) != 11 || report.Check.Claims[0].ReasonCode != "RULE_FACT_UNAVAILABLE" {
		t.Fatalf("incomplete report=%+v err=%v", report, err)
	}
	if _, err := Check("prometheus", prepared.CanonicalInputJSON, now); err == nil {
		t.Fatal("unreviewed project accepted")
	}
}

func TestLokiUnreviewedTransitionIsUnknown(t *testing.T) {
	prepared, err := projectprepare.PrepareEffectiveConfig(projectprepare.LokiProject, []byte("compactor: {}\n"), "2.9.7", projectprepare.LokiTo, true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check(projectprepare.LokiProject, prepared.CanonicalInputJSON, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 0 || !bytes.Contains([]byte(report.NextAction), []byte("no reviewed rule matches")) {
		t.Fatalf("unreviewed Loki transition report=%+v err=%v", report, err)
	}
}

func TestMultipleRulesPerProjectSelectExactTransition(t *testing.T) {
	b := syntheticMultiRuleBundle(t)
	now := time.Date(2026, 9, 11, 20, 0, 0, 0, time.UTC)
	input := multiRuleInput(t, "10.4.0", "11.0.0", true, false)
	report, err := checkWithBundle(b, "grafana", input, now)
	if err != nil || len(report.Check.Claims) != 2 {
		t.Fatalf("same-transition report=%+v err=%v", report, err)
	}
	statuses := map[string]string{}
	for _, claim := range report.Check.Claims {
		statuses[claim.RuleID] = claim.Status
	}
	if statuses["grafana.legacy-alerting-config.10-4-to-11-0"] != "BLOCKED" || statuses["grafana.second-guard.10-4-to-11-0"] != "PASS" {
		t.Fatalf("independent claims=%v", statuses)
	}

	later, err := checkWithBundle(b, "grafana", multiRuleInput(t, "10.5.0", "11.1.0", false, false), now)
	if err != nil || len(later.Check.Claims) != 1 || later.Check.Claims[0].RuleID != "grafana.third-transition.10-5-to-11-1" || later.Check.Claims[0].Status != "PASS" || ClaimExit(later) != 0 {
		t.Fatalf("later transition poisoned by unrelated rules: %+v err=%v", later, err)
	}

	unreviewed, err := checkWithBundle(b, "grafana", multiRuleInput(t, "10.6.0", "11.2.0", false, false), now)
	if err != nil || len(unreviewed.Check.Claims) != 0 || ClaimExit(unreviewed) != 11 || !bytes.Contains([]byte(unreviewed.NextAction), []byte("no reviewed rule matches")) {
		t.Fatalf("unreviewed transition=%+v err=%v", unreviewed, err)
	}
}

func syntheticMultiRuleBundle(t *testing.T) bundle {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	clone := func(source entry) entry {
		raw, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		var result entry
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	mutateRule := func(candidate *entry, id, from, to, factID string) {
		var rule map[string]any
		if err := json.Unmarshal(candidate.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		rule["id"] = id
		subject := rule["subject"].(map[string]any)
		subject["from"], subject["to"] = from, to
		condition := rule["condition"].(map[string]any)
		condition["factId"] = factID
		candidate.Rule, err = json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		candidate.RequiredFacts[0].ID = factID
		candidate.RequiredFacts[0].Description = "Synthetic test-only independently compiled predicate."
	}
	var grafana entry
	other := make([]entry, 0, len(base.pack.Entries)-1)
	for _, candidate := range base.pack.Entries {
		if candidate.Project == "grafana" {
			grafana = clone(candidate)
		} else {
			other = append(other, clone(candidate))
		}
	}
	if grafana.Project == "" {
		t.Fatal("pack has no Grafana rule")
	}
	second := clone(grafana)
	mutateRule(&second, "grafana.second-guard.10-4-to-11-0", "10.4.0", "11.0.0", "component.grafana.second_guard")
	third := clone(grafana)
	mutateRule(&third, "grafana.third-transition.10-5-to-11-1", "10.5.0", "11.1.0", projectprepare.GrafanaFact)
	pack := base.pack
	pack.Revision = "synthetic-multi-rule-test"
	pack.Entries = append(other, grafana, second, third)
	sort.Slice(pack.Entries, func(i, j int) bool {
		if pack.Entries[i].Project != pack.Entries[j].Project {
			return pack.Entries[i].Project < pack.Entries[j].Project
		}
		var left, right ruleBinding
		_ = json.Unmarshal(pack.Entries[i].Rule, &left)
		_ = json.Unmarshal(pack.Entries[j].Rule, &right)
		return left.ID < right.ID
	})
	registryRaw, _ := packaged.ReadFile("data/projects.json")
	packRaw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	defs := append(definitions(), constraintengine.FactDefinition{ID: "component.grafana.second_guard", Component: projectprepare.GrafanaComponent, Type: constraintengine.FactBool})
	result, err := loadRaw(registryRaw, packRaw, defs)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func multiRuleInput(t *testing.T, from, to string, first, second bool) []byte {
	t.Helper()
	document := map[string]any{
		"schema": constraintengine.InputSchema, "authority": constraintengine.InputAuthority,
		"current": map[string]any{"components": []any{map[string]any{"component": projectprepare.GrafanaComponent, "version": from, "facts": []any{}}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": projectprepare.GrafanaComponent, "version": to, "facts": []any{
			map[string]any{"id": projectprepare.GrafanaFact, "state": "declared", "boolValue": first},
			map[string]any{"id": "component.grafana.second_guard", "state": "declared", "boolValue": second},
		}}}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReportSealRejectsMutation(t *testing.T) {
	prepared, _ := projectprepare.PrepareEffectiveConfig("grafana", []byte("[unified_alerting]\nenabled=true\n"), "10.4.0", "11.0.0", true, true)
	report, err := Check("grafana", prepared.CanonicalInputJSON, time.Date(2026, 9, 11, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	report.NextAction = "forged"
	if _, err := MarshalReport(report); err == nil {
		t.Fatal("mutated report accepted")
	}
}

func TestEvidenceExpiryReturnsUnknown(t *testing.T) {
	prepared, err := projectprepare.PrepareEffectiveConfig("grafana", []byte("[alerting]\nenabled=true\n"), "10.4.0", "11.0.0", true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Check("grafana", prepared.CanonicalInputJSON, time.Date(2026, 12, 10, 19, 30, 0, 0, time.UTC))
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 1 || report.Check.Claims[0].ReasonCode != "RULE_EVIDENCE_STALE" {
		t.Fatalf("expired report=%+v err=%v", report, err)
	}
}
