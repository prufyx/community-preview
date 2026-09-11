package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectCLIEndToEndAndPrivacy(t *testing.T) {
	now := "2026-09-11T20:00:00Z"
	for _, tc := range []struct {
		name, project, from, to, body string
		want                          int
	}{
		{"grafana-blocked", "grafana", "10.4.0", "11.0.0", "[server]\nroot_url=https://secret.invalid\n[alerting]\nenabled=true\n", ExitBlocked},
		{"grafana-pass", "grafana", "10.4.0", "11.0.0", "[unified_alerting]\nenabled=true\n", ExitOK},
		{"kibana-blocked", "kibana", "8.18.0", "9.0.0", "xpack.reporting.roles.allow: [private-role]\n", ExitBlocked},
		{"kibana-pass", "kibana", "8.18.0", "9.0.0", "server.host: private-host\n", ExitOK},
		{"wrong-pair", "kibana", "8.17.0", "9.0.0", "server.host: private-host\n", ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePrivateProjectFixture(t, tc.body)
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", tc.project, "--effective-config", path, "--from", tc.from, "--to", tc.to, "--effective-config-complete", "--precedence-resolved", "--now", now, "--format", "json"}, &stdout, &stderr, "test")
			if exit != tc.want {
				t.Fatalf("exit=%d want=%d stderr=%q stdout=%q", exit, tc.want, stderr.String(), stdout.String())
			}
			for _, secret := range []string{path, "secret.invalid", "private-role", "private-host"} {
				if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
					t.Fatalf("private value leaked: %q", secret)
				}
			}
		})
	}
}

func TestProjectCLIRejectsExternalSelectorsAndUnsafeFiles(t *testing.T) {
	path := writePrivateProjectFixture(t, "[alerting]\nenabled=false\n")
	for _, extra := range [][]string{{"--knowledge-db", "store"}, {"--profile", "cncf"}, {"--replay-report", "receipt"}, {"--effective-config", path}} {
		args := []string{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}
		args = append(args, extra...)
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage {
			t.Fatalf("extra=%v exit=%d", extra, exit)
		}
		if strings.Contains(stderr.String(), path) {
			t.Fatal("path leaked")
		}
	}
	unsafe := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(unsafe, []byte("[alerting]\nenabled=false\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"prepare", "project", "--project", "grafana", "--effective-config", unsafe, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved"}, &stdout, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("unsafe exit=%d", exit)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", "sha256:0", "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("malformed digest exit=%d", exit)
	}
	for _, command := range [][]string{
		{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"},
		{"prepare", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved"},
	} {
		for _, value := range []string{"", " "} {
			stdout.Reset()
			stderr.Reset()
			args := append(append([]string{}, command...), "--effective-config-digest="+value)
			if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
				t.Fatalf("empty effective-config pin args=%v exit=%d output=%q", args, exit, stdout.String()+stderr.String())
			}
		}
	}
	wantDigest := digestCommunityBytes([]byte("[alerting]\nenabled=false\n"))
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", wantDigest, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitOK {
		t.Fatalf("pinned input exit=%d stderr=%q", exit, stderr.String())
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", badDigest, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitIntegrity || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("mismatched digest exit=%d output=%q", exit, stdout.String()+stderr.String())
	}
}

func TestProjectCLIHelpAndPreparation(t *testing.T) {
	path := writePrivateProjectFixture(t, "xpack.reporting.roles.allow: [reporting_user]\n")
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"prepare", "project", "--project", "kibana", "--effective-config", path, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--format", "input"}, &stdout, &stderr, "test"); exit != ExitOK {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"component":"pkg:github/elastic/kibana"`) || strings.Contains(stdout.String(), "reporting_user") {
		t.Fatalf("unexpected canonical input %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--help"}, &stdout, &stderr, "test"); exit != ExitOK || !strings.Contains(stdout.String(), "embedded-only") {
		t.Fatalf("help exit/output %d %q", exit, stdout.String())
	}
}

func TestProjectCLIHumanShowsPinnedSourcesWithoutPrivateInput(t *testing.T) {
	path := writePrivateProjectFixture(t, "xpack.reporting.roles.allow: [private-role]\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", path, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitBlocked || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	for _, source := range []string{"docs/settings/reporting-settings.asciidoc", "docs/release-notes/breaking-changes.md"} {
		if !strings.Contains(stdout.String(), source) {
			t.Fatalf("missing source %q from %q", source, stdout.String())
		}
	}
	for _, private := range []string{path, "private-role"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatalf("private input leaked: %q", private)
		}
	}
}

func TestProjectCLIUnreviewedTransitionIsExplicitUnknown(t *testing.T) {
	path := writePrivateProjectFixture(t, "server.host: private-host\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", path, "--from", "8.17.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitUnknown || stderr.Len() != 0 || !strings.Contains(stdout.String(), "no reviewed rule matches this exact project transition") || strings.Contains(stdout.String(), path) || strings.Contains(stdout.String(), "private-host") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func writePrivateProjectFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "effective-config")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
