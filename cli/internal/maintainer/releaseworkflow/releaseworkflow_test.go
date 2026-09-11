package releaseworkflow

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVersionAndTargetAdmission(t *testing.T) {
	if !versionOK("v1.2.3-alpha.1") || versionOK("1.2.3") || versionOK("v1.02.3") {
		t.Fatal("version admission mismatch")
	}
	for _, bad := range []string{"v1.2.3-", "v1.2.3-alpha..1", "v1.2.3-01", "v1.2.3+", "v1.2.3+meta+again", "v1.2.3-!"} {
		if versionOK(bad) {
			t.Fatalf("accepted invalid SemVer %q", bad)
		}
	}
	if !versionOK("v1.2.3-alpha.1+build.01") {
		t.Fatal("rejected valid SemVer")
	}
	if _, _, err := target("linux-arm64"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := target("darwin-arm64"); err == nil {
		t.Fatal("accepted unsupported target")
	}
}

func TestGoTestCommandKeepsOutputStreamsSeparate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := goTestCommand("go", t.TempDir(), &stdout, &stderr)
	if c.Stdout != &stdout || c.Stderr != &stderr {
		t.Fatal("go test output streams were not preserved")
	}
}

func TestSourceTreeChecksumUsesCanonicalTarLabel(t *testing.T) {
	want := strings.Repeat("a", 64) + "  source-tree.tar\n"
	if got := string(sourceTreeChecksum("sha256:" + strings.Repeat("a", 64))); got != want {
		t.Fatalf("source tree checksum = %q", got)
	}
}

func TestSmokeLayoutRejectsExtraAndSourceMembers(t *testing.T) {
	makeLayout := func(t *testing.T) (string, string) {
		t.Helper()
		work := t.TempDir()
		pkg := filepath.Join(work, "prufyx-cli_1.2.3_linux_arm64")
		if err := os.Mkdir(pkg, 0755); err != nil {
			t.Fatal(err)
		}
		return work, pkg
	}
	t.Run("closed layout", func(t *testing.T) {
		work, pkg := makeLayout(t)
		if err := validateSmokeLayout(work, pkg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("extra top level", func(t *testing.T) {
		work, pkg := makeLayout(t)
		if err := os.WriteFile(filepath.Join(work, "extra"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		if err := validateSmokeLayout(work, pkg); err == nil {
			t.Fatal("accepted an extra top-level archive member")
		}
	})
	for _, name := range []string{"go.mod", ".git"} {
		t.Run(name, func(t *testing.T) {
			work, pkg := makeLayout(t)
			if err := os.WriteFile(filepath.Join(pkg, name), nil, 0644); err != nil {
				t.Fatal(err)
			}
			if err := validateSmokeLayout(work, pkg); err == nil {
				t.Fatalf("accepted forbidden %s", name)
			}
		})
	}
}

func TestGoLaunchersPinLocalOfflineToolchain(t *testing.T) {
	// Source exports intentionally omit .git. Locate these shipped launchers
	// from the compiled test file rather than asking the release-only root()
	// helper to discover a checkout.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source location is unavailable")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	for _, rel := range []string{"scripts/community-release.sh", "cli/examples/community/local-kind/run.sh"} {
		b, err := os.ReadFile(filepath.Join(repo, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, binding := range []string{"GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS='-mod=vendor -buildvcs=false'"} {
			if !strings.Contains(text, binding) {
				t.Fatalf("%s lacks %s", rel, binding)
			}
		}
	}
}

func TestOutputDirRejectsCheckoutBeforeCreation(t *testing.T) {
	repo := t.TempDir()
	inside := filepath.Join(repo, "candidate")
	if _, err := outputDir(repo, inside); err == nil {
		t.Fatal("accepted checkout-contained output")
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatal("created rejected checkout-contained output")
	}
	outside := filepath.Join(t.TempDir(), "candidate")
	if _, err := outputDir(repo, outside); err != nil {
		t.Fatalf("rejected outside output: %v", err)
	}
	link := filepath.Join(t.TempDir(), "outside-looking-link")
	if err := os.Symlink(repo, link); err != nil {
		t.Fatal(err)
	}
	if _, err := outputDir(repo, filepath.Join(link, "through-link")); err == nil {
		t.Fatal("accepted checkout-contained symlink target")
	}
	if _, err := os.Stat(filepath.Join(repo, "through-link")); !os.IsNotExist(err) {
		t.Fatal("created rejected symlink-target output")
	}
}
func TestCanonicalArchiveIsStable(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(t.TempDir(), "a.tar.gz")
	b := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := tarGz(root, "prefix", a, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := tarGz(root, "prefix", b, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	ad, _ := os.ReadFile(a)
	bd, _ := os.ReadFile(b)
	if string(ad) != string(bd) {
		t.Fatal("archive bytes differ")
	}
}
