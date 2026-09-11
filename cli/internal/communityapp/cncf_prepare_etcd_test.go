package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEtcdPreparationCLIUsesPrivateMinimizedInput(t *testing.T) {
	raw := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node","--enable-v2=false"]}`)
	path := writeCNCFFile(t, "etcd-argv.json", raw, 0o600)
	code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", "3.5.17", "--to", "3.6.0", "--format", "input")
	if code != ExitOK || stderr != "" {
		t.Fatalf("prepare code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(input, "private-node") || strings.Contains(input, "enable-v2") || !json.Valid([]byte(input)) {
		t.Fatalf("canonical output leaked argv or was invalid: %s", input)
	}
	preparedPath := writeCNCFFile(t, "etcd-prepared.json", []byte(input), 0o600)
	code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "etcd", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-10T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(output, `"status":"BLOCKED"`) || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
		t.Fatalf("check code=%d stderr=%q output=%s", code, stderr, output)
	}
}

func TestEtcdPreparationCLIUnknownDoesNotEmitFalse(t *testing.T) {
	raw := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--initial-cluster","--enable-v2=true"]}`)
	path := writeCNCFFile(t, "etcd-unknown.json", raw, 0o600)
	code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", "3.5.17", "--to", "3.6.0", "--format", "input")
	if code != ExitUnknown || stderr != "" || strings.Contains(input, `"boolValue"`) || strings.Contains(input, "enable-v2") {
		t.Fatalf("unknown output code=%d stderr=%q input=%s", code, stderr, input)
	}
}
