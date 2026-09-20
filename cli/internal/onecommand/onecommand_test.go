package onecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx-cli/internal/localcollector"
)

// fakeRunner answers every kubectl invocation with a synthetic response built
// from the requested resource, so classification can be tested without a
// real cluster or kubectl binary. It never receives a real credential: the
// collector itself resolves and snapshots the kubeconfig before any Runner
// call, exactly as it does in production.
type fakeRunner struct {
	t *testing.T
	// failQuery, when non-empty, makes every call whose argv contains this
	// substring fail, producing a partial collection.
	failQuery string
}

func (f *fakeRunner) Run(_ context.Context, argv, _ []string, timeout time.Duration) (localcollector.CommandResult, error) {
	f.t.Helper()
	joined := strings.Join(argv, " ")
	if f.failQuery != "" && strings.Contains(joined, f.failQuery) {
		return localcollector.CommandResult{Exit: 1, Class: "authorization_rbac_forbidden"}, nil
	}
	return localcollector.CommandResult{Stdout: fakeKubectlResponse(joined), Exit: 0}, nil
}

// fakeKubectlResponse mirrors the shape localcollector's fake test runner
// uses: every base query gets an empty, well-formed list except the ones
// this test cares about (server version and Deployments, which carry one
// synthetic Prometheus workload at a known version).
func fakeKubectlResponse(joined string) []byte {
	var value any
	switch {
	case strings.Contains(joined, "--raw=/version"):
		value = map[string]any{"gitVersion": "v1.31.0"}
	case strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
	case strings.Contains(joined, "--raw=/apis"):
		value = map[string]any{"groups": []any{}}
	case strings.Contains(joined, "--raw=/api") && !strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"versions": []any{"v1"}}
	case strings.Contains(joined, " deployments.apps "):
		value = map[string]any{"items": []any{
			map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"containers": []any{map[string]any{
						"image": "quay.io/prometheus/prometheus:2.55.1",
						"args":  []any{"--log.level=info"},
					}},
				}}},
			},
		}}
	default:
		value = map[string]any{"items": []any{}}
	}
	raw, _ := json.Marshal(value)
	return raw
}

const testKubeconfigYAML = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"

func writeFakeKubeconfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(testKubeconfigYAML+"# test-kubeconfig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseTestOptions(t *testing.T, runner localcollector.Runner) Options {
	t.Helper()
	return Options{
		OutputRoot:          t.TempDir(),
		Kubeconfig:          writeFakeKubeconfig(t),
		Contexts:            []string{"test-context"},
		AcknowledgeExecRisk: true,
		Kubectl:             os.Args[0],
		Now:                 func() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) },
		Random:              strings.NewReader(strings.Repeat("r", 64)),
		Runner:              runner,
	}
}

func findCheck(t *testing.T, checks []CheckAssessment, project, from string) CheckAssessment {
	t.Helper()
	for _, c := range checks {
		if c.Project == project && c.From == from {
			return c
		}
	}
	t.Fatalf("no check found for project=%s from=%s", project, from)
	return CheckAssessment{}
}

func TestRunClassifiesThreeWaySplit(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t})
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
	}
	if report.RouteCatalog.TotalNativeRoutes != 166 {
		t.Fatalf("totalNativeRoutes=%d want 166", report.RouteCatalog.TotalNativeRoutes)
	}
	if report.Aggregate.Assessment != "UNKNOWN" {
		t.Fatalf("aggregate assessment=%q, must never be anything but UNKNOWN in this build", report.Aggregate.Assessment)
	}
	if len(report.Contexts) != 1 {
		t.Fatalf("contexts=%d want 1", len(report.Contexts))
	}
	ctxReport := report.Contexts[0]
	if ctxReport.CollectionStatus != "complete_for_declared_surface" {
		t.Fatalf("collectionStatus=%q", ctxReport.CollectionStatus)
	}
	if len(ctxReport.Checks) != 166 {
		t.Fatalf("checks=%d want 166", len(ctxReport.Checks))
	}

	// Prometheus is observed at exactly 2.55.1 with a recognized predicate
	// (--log.level), so the alertmanager-api-v1-removed check at that exact
	// origin is applicable but needs the declarations the collector cannot
	// supply (an Alertmanager config file, plus completeness declarations).
	promCheck := findCheck(t, ctxReport.Checks, "prometheus", "2.55.1")
	if promCheck.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("prometheus 2.55.1 applicability=%q reason=%q", promCheck.Applicability, promCheck.Reason)
	}
	if promCheck.ObservedVersion != "2.55.1" {
		t.Fatalf("prometheus observedVersion=%q", promCheck.ObservedVersion)
	}
	foundFileFlag := false
	for _, d := range promCheck.MissingDeclarations {
		if d.Flag == "--alertmanager-config" && d.Kind == "file_placeholder" {
			foundFileFlag = true
		}
	}
	if !foundFileFlag {
		t.Fatalf("expected --alertmanager-config in missing declarations: %+v", promCheck.MissingDeclarations)
	}

	// Prometheus origins other than 2.55.1 do not match what was observed.
	mismatch := findCheck(t, ctxReport.Checks, "prometheus", "3.9.1")
	if mismatch.Applicability != NotApplicableVersionMismatch {
		t.Fatalf("prometheus 3.9.1 applicability=%q", mismatch.Applicability)
	}

	// Cilium was never observed in this synthetic cluster at all.
	for _, c := range ctxReport.Checks {
		if c.Project != "cilium" {
			continue
		}
		if c.Applicability != NotApplicableComponentAbsent {
			t.Fatalf("cilium %s applicability=%q, want NOT_APPLICABLE_COMPONENT_ABSENT", c.RuleID, c.Applicability)
		}
	}

	// Kubernetes itself was observed at 1.31.0, matching the one registered
	// kubernetes-project check's origin.
	kube := findCheck(t, ctxReport.Checks, "kubernetes", "1.31.0")
	if kube.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("kubernetes 1.31.0 applicability=%q reason=%q", kube.Applicability, kube.Reason)
	}

	// A project the collector's adapter registry has no identity for at all
	// (e.g. grafana) is always indeterminate, never a claimed absence.
	for _, c := range ctxReport.Checks {
		if c.Project == "grafana" && c.Applicability != IndeterminateNotObservable {
			t.Fatalf("grafana %s applicability=%q, want INDETERMINATE_NOT_OBSERVABLE", c.RuleID, c.Applicability)
		}
	}

	// Summary counts must add up to the total.
	s := ctxReport.Summary
	total := s.ApplicableFullySatisfied + s.ApplicableNeedsDeclaration + s.NotApplicableVersionMismatch + s.NotApplicableComponentAbsent + s.IndeterminateNotObservable + s.IndeterminatePartialCollection
	if total != 166 {
		t.Fatalf("summary total=%d want 166 (%+v)", total, s)
	}
	if s.ApplicableFullySatisfied != 0 {
		t.Fatalf("applicableFullySatisfied=%d, want 0 for the current catalog (see TestNoNativeRouteIsFullySatisfiedByVersionAlone)", s.ApplicableFullySatisfied)
	}

	raw, err := MarshalReport(report)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("MarshalReport: %v", err)
	}
	// Never write raw context names into the report.
	if strings.Contains(string(raw), "test-context") {
		t.Fatal("raw context name escaped into the report")
	}
}

func TestRunRejectsEmptyContexts(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t})
	opts.Contexts = nil
	var stdout, stderr bytes.Buffer
	_, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("code=%d want ExitUsage", code)
	}
}

func TestRunPartialCollectionDefaultsToRefusing(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t, failQuery: "storageclasses.storage.k8s.io"})
	var stdout, stderr bytes.Buffer
	_, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitPartial {
		t.Fatalf("code=%d want ExitPartial; stderr=%s", code, stderr.String())
	}
}

func TestRunPartialCollectionDowngradesAbsenceButNotPositiveEvidence(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t, failQuery: "storageclasses.storage.k8s.io"})
	opts.AllowPartial = true
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	checks := report.Contexts[0].Checks
	for _, c := range checks {
		if c.Project == "cilium" && c.Applicability != IndeterminatePartialCollection {
			t.Fatalf("cilium %s applicability=%q, want INDETERMINATE_PARTIAL_COLLECTION under partial collection", c.RuleID, c.Applicability)
		}
	}
	// A component that WAS positively observed keeps its conclusion; a
	// failed, unrelated read elsewhere does not weaken positive evidence.
	prom := findCheck(t, checks, "prometheus", "2.55.1")
	if prom.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("prometheus 2.55.1 applicability=%q under unrelated partial collection, want unchanged", prom.Applicability)
	}
}

// TestNoNativeRouteIsFullySatisfiedByVersionAlone documents and enforces a
// core finding of the design: every one of the 166 native check routes
// requires at least one caller declaration (a file, a name, or a boolean
// intent flag) beyond the --from/--to version pair. If this ever stops being
// true, ApplicableFullySatisfied stops being a dead bucket and the design
// note's "0 of 166" claim needs updating alongside this test.
func TestNoNativeRouteIsFullySatisfiedByVersionAlone(t *testing.T) {
	result, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	routes := nativeRoutes(result)
	if len(routes) != 166 {
		t.Fatalf("native routes=%d want 166", len(routes))
	}
	for _, route := range routes {
		if len(missingDeclarations(route.NativeDescriptor.Command)) == 0 {
			t.Fatalf("route %s/%s is fully satisfiable by version alone; update onecommand's fully-satisfied handling and the design note", route.Project, route.RuleID)
		}
	}
}

func TestMissingDeclarationsSkipsLiteralsAndTimestamps(t *testing.T) {
	command := []checkroutemetadata.Argument{
		{Kind: "literal", Literal: "check"},
		{Kind: "literal", Literal: "cncf"},
		{Kind: "literal", Literal: "--project"},
		{Kind: "literal", Literal: "widget"},
		{Name: "--widget-config", Kind: "file_placeholder"},
		{Name: "--widget-name", Kind: "name_placeholder"},
		{Name: "--widget-required", Kind: "boolean_operator_declaration", AllowedValues: []string{"true", "false"}},
		{Name: "--now", Kind: "timestamp_placeholder"},
	}
	declarations := missingDeclarations(command)
	if len(declarations) != 3 {
		t.Fatalf("declarations=%+v want 3", declarations)
	}
	byFlag := map[string]Declaration{}
	for _, d := range declarations {
		byFlag[d.Flag] = d
	}
	if byFlag["--widget-config"].Kind != "file_placeholder" || byFlag["--widget-config"].Description == "" {
		t.Fatalf("file declaration missing or undescribed: %+v", byFlag["--widget-config"])
	}
	if byFlag["--widget-name"].Kind != "name_placeholder" {
		t.Fatalf("name declaration wrong: %+v", byFlag["--widget-name"])
	}
	if byFlag["--widget-required"].Kind != "boolean_operator_declaration" {
		t.Fatalf("boolean declaration wrong: %+v", byFlag["--widget-required"])
	}
}

func TestRenderCommandSubstitutesPlaceholders(t *testing.T) {
	command := []checkroutemetadata.Argument{
		{Kind: "literal", Literal: "check"},
		{Name: "--widget-config", Kind: "file_placeholder"},
		{Name: "--widget-name", Kind: "name_placeholder"},
		{Name: "--widget-required", Kind: "boolean_operator_declaration"},
		{Name: "--now", Kind: "timestamp_placeholder"},
	}
	got := renderCommand(command)
	want := []string{"check", "--widget-config", "FILE", "--widget-name", "NAME", "--widget-required=true|false", "--now", "RFC3339"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
}
