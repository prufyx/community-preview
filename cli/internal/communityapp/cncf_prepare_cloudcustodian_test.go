package communityapp

import (
	"strings"
	"testing"
)

func TestCloudCustodianPreparationFeedsScopedRule(t *testing.T) {
	blocked := writeCNCFFile(t, "cloud-custodian-blocked.json", []byte(`{"policies":[{"name":"private-policy","resource":"aws.iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`), 0o600)
	code, prepared, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", blocked, "--from", "0.9.50", "--to", "0.9.51", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(prepared, `"boolValue":true`) || strings.Contains(prepared, "private-policy") || strings.Contains(prepared, blocked) {
		t.Fatalf("blocked preparation code=%d stderr=%q input=%q", code, stderr, prepared)
	}
	preparedPath := writeCNCFFile(t, "cloud-custodian-blocked-prepared.json", []byte(prepared), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cloud-custodian", "--input", preparedPath, "--now", "2026-09-11T22:38:05Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) || strings.Contains(report, "private-policy") || strings.Contains(report, preparedPath) {
		t.Fatalf("blocked check code=%d stderr=%q report=%q", code, stderr, report)
	}

	empty := writeCNCFFile(t, "cloud-custodian-empty.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`), 0o600)
	code, prepared, stderr = runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", empty, "--from", "0.9.50", "--to", "0.9.51", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(prepared, `"boolValue":false`) || strings.Contains(prepared, "private-policy") {
		t.Fatalf("empty preparation code=%d stderr=%q input=%q", code, stderr, prepared)
	}
	preparedPath = writeCNCFFile(t, "cloud-custodian-empty-prepared.json", []byte(prepared), 0o600)
	code, report, stderr = runCNCFCLI(t, "check", "cncf", "--project", "cloud-custodian", "--input", preparedPath, "--now", "2026-09-11T22:38:05Z", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(report, `"status":"PASS"`) || strings.Contains(report, "private-policy") {
		t.Fatalf("empty check code=%d stderr=%q report=%q", code, stderr, report)
	}
}

func TestCloudCustodianPreparationArgumentErrorsIdentifyProject(t *testing.T) {
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", "unused", "--to", "0.9.51", "--format", "json")
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID") || strings.Contains(stderr, "ARGO_CD") {
		t.Fatalf("missing from code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCloudCustodianPreparationUnknownAndPrivateFileAdmission(t *testing.T) {
	raw := []byte("{\"vars\":{\"private\":\"canary\"},\"policies\":[{\"name\":\"private-policy\",\"resource\":\"iam-access-key\",\"filters\":[]}]}")
	unknown := writeCNCFFile(t, "cloud-custodian-root-vars.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", unknown, "--from", "0.9.50", "--to", "0.9.51", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "\"state\":\"unsupported\"") || strings.Contains(stdout, "canary") || strings.Contains(stdout, unknown) {
		t.Fatalf("root variables code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	invalidUTF8 := writeCNCFFile(t, "cloud-custodian-invalid-utf8.json", []byte{'{', '}', 0xff}, 0o600)
	code, stdout, stderr = runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", invalidUTF8, "--from", "0.9.50", "--to", "0.9.51", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, invalidUTF8) || strings.Contains(stderr, "canary") {
		t.Fatalf("invalid UTF-8 code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	permissive := writeCNCFFile(t, "cloud-custodian-permissive.json", []byte("{\"policies\":[{\"name\":\"private-policy\",\"resource\":\"iam-access-key\",\"filters\":[]}]}"), 0o644)
	code, stdout, stderr = runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", permissive, "--from", "0.9.50", "--to", "0.9.51", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, permissive) {
		t.Fatalf("permissive mode code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCloudCustodianPreparationRejectsPrivateInputPinAndMalformedJSON(t *testing.T) {
	path := writeCNCFFile(t, "cloud-custodian-invalid.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[],}]}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", path, "--from", "0.9.50", "--to", "0.9.51", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private-policy") {
		t.Fatalf("malformed input code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	valid := writeCNCFFile(t, "cloud-custodian-pin.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`), 0o600)
	code, stdout, stderr = runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", valid, "--from", "0.9.50", "--to", "0.9.51", "--input-digest", "sha256:"+strings.Repeat("0", 64), "--format", "json")
	if code != ExitIntegrity || stdout != "" || strings.Contains(stderr, valid) || strings.Contains(stderr, "private-policy") {
		t.Fatalf("bad pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
