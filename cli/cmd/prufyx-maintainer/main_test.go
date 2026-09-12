package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMaintainerCLI_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"help"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("out=%q err=%q", out.String(), errOut.String())
	}
}

func TestMaintainerCLI_FlagErrorsAreSanitized(t *testing.T) {
	tests := [][]string{{"export-knowledge", "--PRIVATE_ARGUMENT_CANARY"}, {"package-knowledge", "--PRIVATE_ARGUMENT_CANARY"}, {"knowledge-publish", "--PRIVATE_ARGUMENT_CANARY"}, {"knowledge-sign", "--PRIVATE_ARGUMENT_CANARY"}, {"support-inventory", "--PRIVATE_ARGUMENT_CANARY"}, {"contribution", "validate", "--PRIVATE_ARGUMENT_CANARY"}, {"release-gate", "generate", "--PRIVATE_ARGUMENT_CANARY"}, {"release-metadata", "--PRIVATE_ARGUMENT_CANARY"}, {"staging-receipt", "create", "--PRIVATE_ARGUMENT_CANARY"}}
	for _, args := range tests {
		var out, errOut bytes.Buffer
		err := run(args, &out, &errOut)
		if err == nil {
			t.Fatalf("expected rejection for %v", args)
		}
		if strings.Contains(err.Error(), "PRIVATE_ARGUMENT_CANARY") || strings.Contains(errOut.String(), "PRIVATE_ARGUMENT_CANARY") || errOut.Len() != 0 {
			t.Fatalf("argument leaked: error=%q stderr=%q", err, errOut.String())
		}
	}
}

func TestMaintainerCLIRejectsDuplicateLongOption(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"release-gate", "generate", "--source-root", "one", "--source-root=two"}, &out, &errOut); err == nil {
		t.Fatal("duplicate singleton option accepted")
	}
}

func TestMaintainerCLI_OutputPairRejectsUnsafeTargets(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("PRIVATE_CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", first); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected symlink rejection")
	}
	raw, _ := os.ReadFile(victim)
	if string(raw) != "PRIVATE_CANARY" {
		t.Fatal("symlink target changed")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected FIFO rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, first); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected hard-link rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected directory rejection")
	}
}

func TestMaintainerCLI_OutputPairRollsBackSecondRenameFailure(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	if err := os.WriteFile(first, []byte("old-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("old-markdown"), 0o644); err != nil {
		t.Fatal(err)
	}
	original := renameAt
	calls := 0
	renameAt = func(oldFD int, old string, newFD int, new string) error {
		calls++
		if calls == 2 {
			return errors.New("injected second rename failure")
		}
		return original(oldFD, old, newFD, new)
	}
	defer func() { renameAt = original }()
	if err := writeOutputPair(first, []byte("new-json"), second, []byte("new-markdown")); err == nil {
		t.Fatal("expected injected failure")
	}
	firstRaw, _ := os.ReadFile(first)
	secondRaw, _ := os.ReadFile(second)
	if string(firstRaw) != "old-json" || string(secondRaw) != "old-markdown" {
		t.Fatalf("mixed output: %q %q", firstRaw, secondRaw)
	}
}

func TestMaintainerCLI_ReadOutputPairRejectsUnsafeTargets(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("markdown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected symlink rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(first, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected FIFO rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected hard-link rejection")
	}
}

func TestMaintainerCLI_SupportInventory_CheckAcceptedFiles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"support-inventory", "--selected-source-manifest", filepath.Join(root, "docs/data/selected-source-records-v1.json"), "--json-output", filepath.Join(root, "docs/generated/community-support-inventory.json"), "--markdown-output", filepath.Join(root, "docs/generated/community-support-inventory.md"), "--check"}
	var out, errOut bytes.Buffer
	if err = run(args, &out, &errOut); err != nil {
		t.Fatalf("check failed: %v stderr=%q", err, errOut.String())
	}
}

func TestMaintainerCLIExportKnowledgeWritesNewTarget(t *testing.T) {
	output := filepath.Join(t.TempDir(), "constraints.v1.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"export-knowledge", "--profile", "cncf", "--revision", "73", "--output", output}, &stdout, &stderr); err != nil {
		t.Fatalf("export failed: %v stderr=%q", err, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("output info=%v err=%v", info, err)
	}
	if err := run([]string{"export-knowledge", "--profile", "cncf", "--revision", "73", "--output", output}, &stdout, &stderr); err == nil {
		t.Fatal("existing output accepted")
	}
}

func TestMaintainerCLIKnowledgeSignRejectsNonTTYWithoutEchoingArguments(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "PRIVATE_PATH_CANARY")
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = readEnd
	defer func() {
		os.Stdin = originalStdin
		_ = readEnd.Close()
		_ = writeEnd.Close()
	}()
	var stdout, stderr bytes.Buffer
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	err = run([]string{"knowledge-sign", "init", "--key-dir", keyDir, "--root-expires", expires}, &stdout, &stderr)
	if err == nil {
		t.Fatal("non-TTY signing initialization accepted")
	}
	if strings.Contains(err.Error(), "PRIVATE_PATH_CANARY") || strings.Contains(stdout.String()+stderr.String(), "PRIVATE_PATH_CANARY") || strings.Contains(stderr.String(), "Passphrase") {
		t.Fatalf("path or prompt leaked err=%q stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if _, statErr := os.Stat(keyDir); !os.IsNotExist(statErr) {
		t.Fatalf("key directory changed stat=%v", statErr)
	}
}

func TestMaintainerCLIKnowledgeSignHelpDoesNotPromptOrWrite(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"knowledge-sign", "init", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "knowledge-sign init") || stderr.Len() != 0 {
		t.Fatalf("unexpected help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if err := run([]string{"knowledge-sign", "sign-role", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "knowledge-sign sign-role") || stderr.Len() != 0 {
		t.Fatalf("unexpected help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
