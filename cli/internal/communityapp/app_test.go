package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertManagerRouteReturnsScopedExitAndSafeOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret-name-values.json")
	if err := os.WriteFile(path, []byte(`{"prometheus":{"servicemonitor":{"path":"private-custom-value"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", path, "--format", "json"}, &stdout, &stderr, "test")
	if code != ExitBlocked {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, forbidden := range []string{path, "secret-name-values", "private-custom-value"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("output leaked %q: %s", forbidden, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), `"status":"BLOCKED"`) || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) {
		t.Fatalf("output=%s", stdout.String())
	}
}

func TestCertManagerCleanRouteReturnsScopedPass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, []byte(`{"prometheus":{"servicemonitor":{"enabled":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", path}, &stdout, &stderr, "test")
	if code != ExitOK || !strings.Contains(stdout.String(), "aggregate: UNKNOWN") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestPrometheusDemoPreservesAggregateUnknownExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"check", "prometheus-mode", "--demo", "--format", "json"}, &stdout, &stderr, "test")
	if code != ExitUnknown || !strings.Contains(stdout.String(), `"aggregate":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestLegacyPrometheusDemoEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"community-preview", "demo-prometheus-mode"}, &stdout, &stderr, "test")
	if code != ExitUnknown || !strings.Contains(stdout.String(), `"schemaVersion":"prufyx.io/prometheus-mode-synthetic-demo/v1alpha1"`) || !strings.Contains(stdout.String(), `"reasonCode":"prometheus_mode_synthetic_demo_completed"`) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestVersionUsesValidatedBuildIdentityEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"version"}, &stdout, &stderr, "ignored")
	if code != ExitOK || !strings.Contains(stdout.String(), `"schemaVersion":"prufyx.io/v1alpha1"`) || !strings.Contains(stdout.String(), `"reasonCode":"build_identity_reported"`) || !strings.Contains(stdout.String(), `"releaseState":"development"`) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestCheckHelpAndUnsupportedTransition(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"check", "--help"}, &stdout, &stderr, "test"); code != ExitOK || !strings.Contains(stdout.String(), "cert-manager-values") {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Run(context.Background(), []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.22.0", "--values", path, "--format", "json"}, &stdout, &stderr, "test")
	if code != ExitUnknown || !strings.Contains(stdout.String(), `"reasonCode":"CERT_MANAGER_TRANSITION_NOT_REVIEWED"`) || strings.Contains(stdout.String(), "1.22.0") {
		t.Fatalf("code=%d output=%s err=%s", code, stdout.String(), stderr.String())
	}
}

func TestDisabledSchemaValidationReturnsAttention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, []byte(`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", path, "--schema-validation", "disabled", "--format", "json"}, &stdout, &stderr, "test")
	if code != ExitUnknown || !strings.Contains(stdout.String(), `"status":"ATTENTION"`) || !strings.Contains(stdout.String(), `"schemaValidation":"disabled"`) {
		t.Fatalf("code=%d output=%s err=%s", code, stdout.String(), stderr.String())
	}
}

func TestHelpNamesPublicBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, &stdout, &stderr, "test"); code != ExitOK {
		t.Fatal(code)
	}
	if strings.Contains(stdout.String(), "prufyx-community") || !strings.Contains(stdout.String(), "prufyx check") {
		t.Fatalf("help=%q", stdout.String())
	}
}

func TestPrometheusRouteClassifiesProposedAdmissionErrors(t *testing.T) {
	valid := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[]}}}}`)
	malformed := []byte(`{bad-json`)
	dir := t.TempDir()
	observationRoot := filepath.Join(dir, "observation")
	if err := os.Mkdir(observationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	digest := func(raw []byte) string {
		return "sha256:" + fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	privateValid := write("valid.json", valid, 0o600)
	malformedPath := write("malformed-private-value.json", malformed, 0o600)
	permissivePath := write("permissive-private-value.json", valid, 0o644)
	symlinkPath := filepath.Join(dir, "linked-private-value.json")
	if err := os.Symlink(privateValid, symlinkPath); err != nil {
		t.Fatal(err)
	}
	base := []string{"--observation-root", observationRoot, "--captured-at", "2026-09-07T10:00:00Z", "--now", "2026-09-07T10:01:00Z", "--max-age", "1h"}
	cases := []struct {
		name   string
		prefix []string
		path   string
		pin    string
		want   int
	}{
		{name: "malformed new route", prefix: []string{"check", "prometheus-mode"}, path: malformedPath, pin: digest(malformed), want: ExitUsage},
		{name: "permissive new route", prefix: []string{"check", "prometheus-mode"}, path: permissivePath, pin: digest(valid), want: ExitUsage},
		{name: "symlink new route", prefix: []string{"check", "prometheus-mode"}, path: symlinkPath, pin: digest(valid), want: ExitUsage},
		{name: "digest mismatch new route", prefix: []string{"check", "prometheus-mode"}, path: privateValid, pin: "sha256:" + strings.Repeat("0", 64), want: ExitIntegrity},
		{name: "malformed legacy route", prefix: []string{"community-preview", "validate-prometheus-mode"}, path: malformedPath, pin: digest(malformed), want: ExitIntegrity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{}, tc.prefix...)
			args = append(args, base...)
			args = append(args, "--proposed-workload", tc.path, "--proposed-digest", tc.pin)
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), args, &stdout, &stderr, "test"); code != tc.want {
				t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, tc.want, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != "prufyx: proposed workload failed local verification\n" {
				t.Fatalf("unsafe or unstable output stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			for _, private := range []string{dir, "private-value", string(malformed)} {
				if strings.Contains(stdout.String(), private) || strings.Contains(stderr.String(), private) {
					t.Fatalf("output leaked private input %q", private)
				}
			}
		})
	}
}
