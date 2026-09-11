package releasehelpers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunUsesProvidedStreamsAndRejectsUnsafeFlags(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "metadata.json")
	if err := WriteMetadata(MetadataOptions{Output: meta, Version: "v1.0.0", Revision: strings.Repeat("a", 40), SourceTreeDigest: "sha256:" + strings.Repeat("b", 64), ManifestDigest: "sha256:" + strings.Repeat("c", 64), Target: "linux-amd64", BuildEpoch: "1", GoVersion: "go1.26.8"}); err != nil {
		t.Fatal(err)
	}
	report := `{"result":{"status":"OK"},"data":{"version":"v1.0.0","releaseState":"release","sourceRevision":"` + strings.Repeat("a", 40) + `","sourceTreeDigest":"sha256:` + strings.Repeat("b", 64) + `","allowlistDigest":"sha256:` + strings.Repeat("c", 64) + `","buildProfile":"linux-amd64","goVersion":"go1.26.8","trustRootDigest":"UNPINNED","candidateOnly":true}}`
	var out bytes.Buffer
	if err := Run([]string{"release-verify-version", "--metadata", meta, "--report-stdin"}, strings.NewReader(report), &out, &out); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"release-verify-version", "--metadata", meta}, {"release-verify-version", "--metadata", meta, "--bogus", "x"}, {"release-verify-version", "--metadata", meta, "--report-stdin", "true"}} {
		if err := Run(args, strings.NewReader(report), &out, &out); err == nil {
			t.Fatalf("accepted unsafe args %v", args)
		}
	}
}

func TestRunReleaseMetadataSupportsDarwinTmpAlias(t *testing.T) {
	path := filepath.Join("/tmp", "prufyx-releasehelpers-"+strings.Repeat("a", 16)+".json")
	os.Remove(path)
	defer os.Remove(path)
	args := []string{
		"release-metadata", "--output", path, "--version", "v1.0.0",
		"--revision", strings.Repeat("a", 40), "--source-tree-digest", "sha256:" + strings.Repeat("b", 64),
		"--manifest-digest", "sha256:" + strings.Repeat("c", 64), "--target", "linux-amd64",
		"--build-epoch", "1", "--go-version", "go1.26.8",
	}
	if err := Run(args, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
func TestVerifyDemoRejectsDuplicateJSON(t *testing.T) {
	raw := []byte(`{"aggregate":"UNKNOWN","aggregate":"PASS","status":"SYNTHETIC_DEMONSTRATION","pin":"2.55.1 3.1.0 linux/arm64/v8"}`)
	if err := VerifyDemo(raw); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
}
func TestWriteSBOMIsCanonicalAndNoFirstPartyRuntimeClaim(t *testing.T) {
	p := filepath.Join(t.TempDir(), "SBOM.json")
	if err := WriteSBOM(SBOMOptions{Output: p, Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte{'\n'}) {
		t.Fatal("missing canonical newline")
	}
	if bytes.Contains(raw, []byte(`SPDXRef-Package-Python`)) {
		t.Fatal("retired Python runtime is still represented")
	}
}

func TestWriteSBOMProjectsEveryActivePolicyModule(t *testing.T) {
	policyPath := filepath.Join("..", "..", "..", "release", "community-shipping-policy-v2.json")
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		t.Fatal(err)
	}
	modules, ok := policy["externalModules"].([]any)
	if !ok || len(modules) == 0 {
		t.Fatal("fixture has no external modules")
	}
	out := filepath.Join(t.TempDir(), "SBOM.json")
	if err := WriteSBOM(SBOMOptions{Output: out, Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8", Policy: policyPath}); err != nil {
		t.Fatal(err)
	}
	var sbom map[string]any
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &sbom); err != nil {
		t.Fatal(err)
	}
	packages, _ := sbom["packages"].([]any)
	if len(packages) != len(modules)+2 {
		t.Fatalf("SBOM package count=%d, want %d", len(packages), len(modules)+2)
	}
}

func TestWriteSBOMRejectsMalformedPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSBOM(SBOMOptions{Output: filepath.Join(t.TempDir(), "SBOM.json"), Version: "v1.0.0", Revision: strings.Repeat("a", 40), BuildEpoch: "0", GoVersion: "go1.26.8", Policy: policyPath}); err == nil {
		t.Fatal("malformed policy accepted")
	}
}

func TestVerifyArchiveBindsLicenseFilesAndRejectsExtraMembers(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "LICENSES"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSES", "module.txt"), []byte("module license\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "release.tar.gz")
	writeArchiveFixture(t, archivePath, 17, "", root)
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	writeArchiveFixture(t, archivePath, 17, "pkg/extra", root)
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive with an extra member accepted")
	}
	writeArchiveFixture(t, archivePath, 17, "pkg/../escape", root)
	if err := VerifyArchive(ArchiveOptions{Archive: archivePath, PackageName: "pkg", RepositoryRoot: root, BuildEpoch: "17"}); err == nil {
		t.Fatal("archive with a traversal member accepted")
	}
}

func writeArchiveFixture(t *testing.T, path string, epoch int64, extraName, root string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tarWriter := tar.NewWriter(gz)
	write := func(name string, mode int64, data []byte) {
		header := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	directory := func(name string) {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0755, ModTime: time.Unix(epoch, 0), Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	directory("pkg/")
	write("pkg/LICENSE", 0644, []byte("LICENSE\n"))
	write("pkg/NOTICE", 0644, []byte("NOTICE\n"))
	write("pkg/THIRD-PARTY.md", 0644, []byte("THIRD-PARTY.md\n"))
	write("pkg/RELEASE-METADATA.json", 0644, nil)
	write("pkg/SOURCE-REVISION", 0644, nil)
	write("pkg/prufyx", 0755, nil)
	directory("pkg/LICENSES/")
	write("pkg/LICENSES/module.txt", 0644, []byte("module license\n"))
	if extraName != "" {
		write(extraName, 0644, nil)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_ = root
}
