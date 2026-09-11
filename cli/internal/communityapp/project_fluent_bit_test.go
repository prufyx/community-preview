package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFluentBitProjectRouteAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fluent-bit.conf")
	raw := "[OUTPUT]\n  Name opentelemetry\n  Host collector.private.invalid\n  http2 on\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"check", "project", "--project", "fluent-bit", "--effective-config", path, "--from", "3.2.0", "--to", "4.0.0", "--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled", "--now", "2026-09-12T00:00:00Z", "--format", "json"}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), base, &stdout, &stderr, "test"); exit != ExitOK || stderr.Len() != 0 {
		t.Fatalf("on exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "collector.private.invalid") || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatal("private config value leaked")
	}
	if !strings.Contains(stdout.String(), "fluent-bit.http2-setting.3-2-to-4-0") {
		t.Fatalf("missing reviewed rule: %q", stdout.String())
	}

	off := "[OUTPUT]\n  Name opentelemetry\n  http2 off\n"
	if err := os.WriteFile(path, []byte(off), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), base, &stdout, &stderr, "test"); exit != ExitBlocked {
		t.Fatalf("off exit=%d want=%d stderr=%q stdout=%q", exit, ExitBlocked, stderr.String(), stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	missing := append([]string{}, base[:10]...)
	missing = append(missing, base[12:]...)
	if exit := Run(t.Context(), missing, &stdout, &stderr, "test"); exit != ExitUnknown {
		t.Fatalf("missing current declaration exit=%d want=%d stderr=%q", exit, ExitUnknown, stderr.String())
	}
}
