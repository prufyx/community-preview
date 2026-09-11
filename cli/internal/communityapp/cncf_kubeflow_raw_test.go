package communityapp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func kubeflowCLIPython(t *testing.T) string {
	t.Helper()
	if value := os.Getenv("PRUFYX_TEST_PYTHON"); value != "" {
		if !filepath.IsAbs(value) {
			t.Fatalf("PRUFYX_TEST_PYTHON must be absolute: %q", value)
		}
		return value
	}
	value, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for KubeflowKFP raw-source tests")
	}
	value, err = filepath.Abs(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func kubeflowRawArgs(t *testing.T, path, from, to, format string) []string {
	t.Helper()
	return []string{"check", "cncf", "--project", "kubeflow", "--python-source", path, "--python-ast-interpreter", kubeflowCLIPython(t), "--from", from, "--to", to, "--now", "2026-09-10T22:00:00Z", "--format", format}
}

func TestKubeflowKFPRawSourceEditAndRepeatWithoutSourceExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.py")
	canary := filepath.Join(dir, "MUST_NOT_EXIST")
	beforeRaw := []byte(fmt.Sprintf("from kfp.components import create_component_from_func\nopen(%q, 'w').write('executed')\n@create_component_from_func\ndef PRIVATE_COMPONENT(value: str):\n    return value\n", canary))
	writeCNCFFileAt(t, path, beforeRaw)
	args := kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "create_component_from_func") || !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "does not modify, import, or execute") || !strings.Contains(before, "CPython 3.") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertKubeflowKFPRedacted(t, before, path, canary)
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("supplied source was executed")
	}
	afterRaw := []byte(fmt.Sprintf("from kfp import dsl\nopen(%q, 'w').write('executed')\n@dsl.component\ndef PRIVATE_COMPONENT(value: str):\n    return value\n", canary))
	writeCNCFFileAt(t, path, afterRaw)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "dsl.component") || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "aggregate: UNKNOWN") || !strings.Contains(after, "separately validate component inputs") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertKubeflowKFPRedacted(t, after, path, canary)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestKubeflowKFPRawUnknownPrivacyAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.py")
	tests := []struct{ name, source, from, to, category string }{
		{"alias", "from kfp.components import create_component_from_func as PrivateAlias\n@PrivateAlias\ndef private_component(): pass\n", "1.8.22", "2.0.0", "binding_missing"},
		{"except handler rebound", "from kfp import dsl\ntry:\n    pass\nexcept Exception as dsl:\n    pass\n@dsl.component\ndef private_component(): pass\n", "1.8.22", "2.0.0", "binding_rebound"},
		{"decorator call", "from kfp import dsl\n@dsl.component()\ndef private_component(): pass\n", "1.8.22", "2.0.0", "candidate_definition_count"},
		{"multiple", "from kfp import dsl\n@dsl.component\ndef one(): pass\n@dsl.component\ndef two(): pass\n", "1.8.22", "2.0.0", "candidate_definition_count"},
		{"wrong pair", "from kfp.components import create_component_from_func\n@create_component_from_func\ndef private_component(): pass\n", "1.8.21", "2.0.0", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, []byte(tc.source))
			code, out, errout := runCNCFCLI(t, kubeflowRawArgs(t, path, tc.from, tc.to, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") || (tc.category != "" && !strings.Contains(out, tc.category)) {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertKubeflowKFPRedacted(t, out, path)
		})
	}
	writeCNCFFileAt(t, path, []byte("def broken(:\n"))
	code, out, errout := runCNCFCLI(t, kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: SELECTED_KUBEFLOW_KFP_PYTHON_INTERPRETER_COULD_NOT_PARSE_SOURCE\n" {
		t.Fatalf("syntax code=%d stdout=%q stderr=%q", code, out, errout)
	}
	raw := []byte("from kfp import dsl\n@dsl.component\ndef private_component(): pass\n")
	writeCNCFFileAt(t, path, raw)
	base := kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "json")
	matching := append(append([]string{}, base...), "--python-source-digest", digestCommunityBytes(raw))
	code, out, errout = runCNCFCLI(t, matching...)
	if code != ExitOK || errout != "" || !json.Valid([]byte(out)) || strings.Contains(out, "private.invalid") {
		t.Fatalf("matching code=%d stderr=%q output=%s", code, errout, out)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	code, out, errout = runCNCFCLI(t, append(base, "--python-source-digest", badDigest)...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, out, errout)
	}
	for _, extra := range [][]string{{"--input", path}, {"--service", path}, {"--in-toto-run-argv", path}, {"--metanode-config", path}, {"--knowledge-db", dir}, {"--replay-report", path}} {
		args := append(append([]string{}, base...), extra...)
		code, out, errout = runCNCFCLI(t, args...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
			t.Fatalf("extra=%v code=%d out=%q err=%q", extra, code, out, errout)
		}
	}
	badInterpreter := append([]string{}, base...)
	for i := range badInterpreter {
		if badInterpreter[i] == "--python-ast-interpreter" {
			badInterpreter[i+1] = "/usr/bin/false"
		}
	}
	code, out, errout = runCNCFCLI(t, badInterpreter...)
	if code != ExitUsage || out != "" || errout != "prufyx: KUBEFLOW_KFP_PYTHON_AST_INTERPRETER_UNAVAILABLE_OR_UNSUPPORTED\n" {
		t.Fatalf("runtime code=%d stdout=%q stderr=%q", code, out, errout)
	}
}

func assertKubeflowKFPRedacted(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range append(forbidden, "PRIVATE_COMPONENT", "private.invalid") {
		if strings.Contains(output, value) {
			t.Fatalf("private Python source crossed output: %q in %s", value, output)
		}
	}
}
