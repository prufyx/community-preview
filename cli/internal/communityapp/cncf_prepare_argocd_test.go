package communityapp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func argoCDPreparationResource(t *testing.T, value any, include bool) []byte {
	t.Helper()
	data := map[string]any{"private": "argo-canary-never-retain"}
	if include {
		data["server.rbac.disableApplicationFineGrainedRBACInheritance"] = value
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "argocd-cm", "namespace": "private-argo"},
		"data":     data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func argoCDPreparationArgs(path string) []string {
	return []string{"prepare", "cncf", "--project", "argo-cd", "--input", path, "--from", "2.14.0", "--to", "3.0.0"}
}

func TestArgoCDPreparationFeedsScopedExistingRule(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		value                  any
		include, requires      bool
		prepareCode, checkCode int
		status                 string
	}{
		{"true plus required inheritance blocks", "true", true, true, ExitOK, ExitBlocked, "BLOCKED"},
		{"false preserves scoped predicate", "false", true, true, ExitOK, ExitOK, "PASS"},
		{"field absent remains unknown", "true", false, true, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"intent omitted remains unknown", "true", true, false, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"malformed setting remains unknown", "False", true, true, ExitUnknown, ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := argoCDPreparationResource(t, tc.value, tc.include)
			path := writeCNCFFile(t, "argocd-cm.json", raw, 0o600)
			args := argoCDPreparationArgs(path)
			if tc.requires {
				args = append(args, "--requires-inherited-application-permissions", "true")
			}
			code, input, stderr := runCNCFCLI(t, append(args, "--format", "input", "--input-digest", cncfDigest(raw))...)
			if code != tc.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, "argo-canary-never-retain") || strings.Contains(input, "private-argo") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "argo-cd", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-09T06:00:00Z", "--format", "json")
			if code != tc.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, "argo-canary-never-retain") || strings.Contains(report, "private-argo") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestArgoCDPreparationRejectsUnsafeFlagsAndBadPin(t *testing.T) {
	raw := argoCDPreparationResource(t, "true", true)
	path := writeCNCFFile(t, "argocd-cm.json", raw, 0o600)
	for _, extra := range [][]string{
		{"--requires-inherited-application-permissions", "yes"},
		{"--container", "private"},
		{"--distribution", "official_upstream"},
		{"--schema-validation", "required"},
		{"--target-policy-crd-admission", "required"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(argoCDPreparationArgs(path), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private") {
			t.Fatalf("extra=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, append(argoCDPreparationArgs(path), "--requires-inherited-application-permissions", "true", "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("bad pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, format := range []string{"human", "json", "input"} {
		var stderr bytes.Buffer
		code := Run(nil, append(append(argoCDPreparationArgs(path), "--requires-inherited-application-permissions", "true", "--format", format), []string{}...), failedPreparationWriter{}, &stderr, "test")
		if code != ExitIntegrity || stderr.String() != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
			t.Fatalf("format=%s output failure code=%d stderr=%q", format, code, stderr.String())
		}
	}
}
