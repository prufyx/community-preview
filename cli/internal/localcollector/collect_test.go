package localcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	t       *testing.T
	private string
	calls   [][]string
}

type oneFailureRunner struct{ fakeRunner }

type paginatedCRDRunner struct {
	t        *testing.T
	timeouts []time.Duration
}

func (f *paginatedCRDRunner) Run(ctx context.Context, argv, _ []string, timeout time.Duration) (CommandResult, error) {
	f.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || timeout <= 0 || timeout > time.Until(deadline)+time.Millisecond {
		f.t.Fatalf("page timeout %s is not bounded by parent deadline %v", timeout, deadline)
	}
	f.timeouts = append(f.timeouts, timeout)
	continuation := "next"
	if len(f.timeouts) == 2 {
		continuation = ""
	}
	value := map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": continuation}, "items": []any{}}
	raw, _ := json.Marshal(value)
	return CommandResult{Stdout: raw, Exit: 0}, nil
}

func (f *oneFailureRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	if strings.Contains(strings.Join(argv, " "), "storageclasses.storage.k8s.io") {
		return CommandResult{Exit: 1, Class: "authorization_rbac_forbidden"}, nil
	}
	return f.fakeRunner.Run(ctx, argv, env, timeout)
}

func (f *fakeRunner) Run(_ context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	f.t.Helper()
	f.calls = append(f.calls, append([]string(nil), argv...))
	joined := strings.Join(argv, "\x00")
	if !strings.Contains(joined, "--context\x00"+f.private) || timeout != requestTimeout {
		f.t.Fatalf("kubectl authority missing: %q timeout=%s", argv, timeout)
	}
	for _, value := range env {
		if strings.HasPrefix(value, "TOKEN=") {
			f.t.Fatal("undeclared token reached kubectl environment")
		}
	}
	return CommandResult{Stdout: fakeResponse(argv), Exit: 0}, nil
}

func fakeResponse(argv []string) []byte {
	joined := strings.Join(argv, " ")
	var value any
	switch {
	case strings.Contains(joined, "--raw=/version"):
		value = map[string]any{"gitVersion": "v1.34.1"}
	case strings.Contains(joined, " nodes "):
		value = map[string]any{"items": []any{}}
	case strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
	case strings.Contains(joined, "--raw=/apis"):
		value = map[string]any{"groups": []any{}}
	case strings.Contains(joined, "--raw=/api") && !strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"versions": []any{"v1"}}
	default:
		value = map[string]any{"items": []any{}}
	}
	raw, _ := json.Marshal(value)
	return raw
}

func TestCollectWithFakeKubectl(t *testing.T) {
	t.Setenv("TOKEN", "private-token-canary")
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "private-kubeconfig-canary")
	if err := os.WriteFile(kubeconfig, []byte("private-kubeconfig-content-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(tmp, "out")
	fake := &fakeRunner{t: t, private: "private-context-canary"}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: fake}).Collect(context.Background(), Options{
		OutputRoot: output, Kubeconfig: kubeconfig, Contexts: []string{fake.private},
		AcknowledgeExecRisk: true, AllowPartial: false, Kubectl: "/not-executed",
		IncludeComponentConfiguration: true, ComponentConfigurationProfile: "v3",
		ExecEnv: proxyEnvironmentNames, Now: func() time.Time { return time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC) },
		Random: strings.NewReader(strings.Repeat("r", 32)),
	}, &stdout, &stderr)
	if code != 0 {
		omissions, _ := os.ReadFile(filepath.Join(dir, "000", "omissions.tsv"))
		t.Fatalf("Collect exit=%d stderr=%q omissions=%q", code, stderr.String(), omissions)
	}
	if len(fake.calls) != len(baseQueries)+1 {
		t.Fatalf("kubectl calls=%d want=%d", len(fake.calls), len(baseQueries)+1)
	}
	for _, path := range []string{filepath.Join(dir, "index.json"), filepath.Join(dir, "MANIFEST.sha256"), filepath.Join(dir, "000", "server-version.json"), filepath.Join(dir, "000", "crd-api-surface.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private output %s: %v mode=%v", path, err, info.Mode().Perm())
		}
	}
	for _, name := range []string{"index.json", "MANIFEST.sha256", filepath.Join("000", "snapshot-metadata.json"), filepath.Join("000", "omissions.tsv")} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{fake.private, "private-token-canary", "private-kubeconfig-canary", "private-kubeconfig-content-canary"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatalf("private value %q escaped in %s", private, name)
			}
		}
	}
	if strings.Contains(stdout.String(), fake.private) || strings.Contains(stderr.String(), fake.private) {
		t.Fatal("raw context escaped through status streams")
	}
	var metadata map[string]any
	metadataRaw, err := os.ReadFile(filepath.Join(dir, "000", "snapshot-metadata.json"))
	if err != nil || json.Unmarshal(metadataRaw, &metadata) != nil {
		t.Fatal("read collector metadata")
	}
	if metadata["componentConfigurationFilterDigest"] != digest(componentFilterContract("v3")) || metadata["kubectlBoundedRunnerDigest"] != digest(boundedRunnerContract) {
		t.Fatalf("behavior-contract digests not bound: %#v", metadata)
	}
	var surface map[string]any
	surfaceRaw, err := os.ReadFile(filepath.Join(dir, "000", "component-configuration-surface.json"))
	if err != nil || json.Unmarshal(surfaceRaw, &surface) != nil {
		t.Fatal("read component surface")
	}
	if at(surface, "metadata", "filterDigest") != digest(componentFilterContract("v3")) || at(surface, "metadata", "aggregateDigest") != digest(componentAggregateContract("v3")) {
		t.Fatalf("surface contract digests not bound: %#v", at(surface, "metadata"))
	}
}

func TestCaptureCRDsUsesOnePaginationDeadline(t *testing.T) {
	runner := &paginatedCRDRunner{t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	omissions := []omission{}
	histogram := map[string]int{}
	failed := (Collector{Runner: runner}).captureCRDs(ctx, nil, Options{Kubeconfig: "/not-opened"}, "private-context", t.TempDir(), &omissions, histogram)
	if failed || len(omissions) != 0 || len(runner.timeouts) != 2 {
		t.Fatalf("failed=%v omissions=%#v timeouts=%v", failed, omissions, runner.timeouts)
	}
	if runner.timeouts[0] >= requestTimeout || runner.timeouts[1] > runner.timeouts[0] {
		t.Fatalf("pagination timeouts do not share the parent budget: %v", runner.timeouts)
	}
}

func TestRemainingRequestTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	if got, ok := remainingRequestTimeout(now, now.Add(5*time.Second), requestTimeout); !ok || got != 5*time.Second {
		t.Fatalf("remaining timeout=(%s,%v)", got, ok)
	}
	if got, ok := remainingRequestTimeout(now, now, requestTimeout); ok || got != 0 {
		t.Fatalf("expired timeout=(%s,%v)", got, ok)
	}
}

func TestValidateOptionsRejectsKubeconfigLinksAndAcknowledgement(t *testing.T) {
	tmp := t.TempDir()
	original := filepath.Join(tmp, "config")
	if err := os.WriteFile(original, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(tmp, "linked")
	if err := os.Link(original, linked); err != nil {
		t.Fatal(err)
	}
	base := Options{OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: linked, Contexts: []string{"private"}, AcknowledgeExecRisk: true, Kubectl: "/bin/false"}
	if err := validateOptions(&base); err == nil {
		t.Fatal("hard-linked kubeconfig accepted")
	}
	base.Kubeconfig = original
	base.AcknowledgeExecRisk = false
	if err := validateOptions(&base); err == nil {
		t.Fatal("missing exec-risk acknowledgement accepted")
	}
}

func TestCollectPartialIsBoundedAndRedacted(t *testing.T) {
	t.Setenv("TOKEN", "private-token-canary")
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	config := filepath.Join(tmp, "config")
	if err := os.WriteFile(config, []byte("private-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &oneFailureRunner{fakeRunner: fakeRunner{t: t, private: "private-context"}}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: fake}).Collect(context.Background(), Options{OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: config, Contexts: []string{"private-context"}, AcknowledgeExecRisk: true, Kubectl: "/not-executed", ExecEnv: proxyEnvironmentNames, Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("x", 32))}, &stdout, &stderr)
	if code != 6 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "000", "omissions.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("kubernetes_api_read_failed_authorization_rbac_forbidden")) {
		t.Fatalf("omissions=%q", raw)
	}
	combined := stdout.String() + stderr.String() + string(raw)
	for _, private := range []string{"private-context", "private-token-canary", "private-config"} {
		if strings.Contains(combined, private) {
			t.Fatalf("private value %q escaped", private)
		}
	}
}
