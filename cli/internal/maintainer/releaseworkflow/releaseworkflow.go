// Package releaseworkflow implements the local Community release workflow.
//
// It deliberately grants no publication authority. It operates only on a clean,
// caller-selected checkout and writes release candidates outside that checkout.
package releaseworkflow

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx-cli/internal/maintainer/releasegate"
	"github.com/prufyx/prufyx-cli/internal/maintainer/releasehelpers"
)

const (
	requiredGo     = "go1.26.8"
	modulePath     = "github.com/prufyx/prufyx-cli"
	entrypoint     = "./cmd/prufyx-community"
	policyRel      = "cli/release/community-shipping-policy-v2.json"
	commandTimeout = 10 * time.Minute
)

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "test":
		if len(args) != 1 {
			return usage()
		}
		return test(stdout, stderr)
	case "binary":
		if len(args) != 4 {
			return usage()
		}
		p, err := binary(args[1], args[2], args[3])
		if err == nil {
			_, err = fmt.Fprintln(stdout, p)
		}
		return err
	case "smoke":
		if len(args) != 4 {
			return usage()
		}
		return smoke(args[1], args[2], args[3], stdout)
	case "source":
		if len(args) != 3 {
			return usage()
		}
		p, err := source(args[1], args[2])
		if err == nil {
			_, err = fmt.Fprintln(stdout, p)
		}
		return err
	case "finalize":
		if len(args) != 3 {
			return usage()
		}
		return finalize(args[1], args[2])
	case "verify":
		if len(args) != 3 {
			return usage()
		}
		return verify(args[1], args[2])
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: prufyx-maintainer release <test|binary|smoke|source|finalize|verify> ...")
}

func root() (string, error) {
	out, err := command("", "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("run this command in a Git checkout")
	}
	return filepath.EvalSymlinks(strings.TrimSpace(string(out)))
}
func command(dir, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	out, err := c.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s exceeded the maintainer command deadline", name)
		}
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	return out, nil
}
func goPath() (string, error) {
	p, err := exec.LookPath("go")
	if err != nil {
		return "", errors.New("Go executable is unavailable")
	}
	return filepath.EvalSymlinks(p)
}
func checkout(repo string) (string, error) {
	head, err := command(repo, "git", "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", errors.New("HEAD is unavailable")
	}
	revision := strings.TrimSpace(string(head))
	if len(revision) != 40 || strings.Trim(revision, "0123456789abcdef") != "" {
		return "", errors.New("HEAD is not an exact lowercase Git revision")
	}
	porcelain, err := command(repo, "git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored")
	if err != nil || len(porcelain) != 0 {
		return "", errors.New("checkout is not clean")
	}
	if expected := os.Getenv("EXPECTED_REVISION"); expected != "" && expected != revision {
		return "", errors.New("checked-out revision differs from EXPECTED_REVISION")
	}
	return revision, nil
}
func toolchain(repo string) (string, error) {
	g, err := goPath()
	if err != nil {
		return "", err
	}
	v, err := command("", g, "env", "GOVERSION")
	if err != nil || strings.TrimSpace(string(v)) != requiredGo {
		return "", fmt.Errorf("Go toolchain must be %s", requiredGo)
	}
	exp, err := command("", g, "env", "GOEXPERIMENT")
	if err != nil || strings.TrimSpace(string(exp)) != "" {
		return "", errors.New("release builds require empty GOEXPERIMENT")
	}
	m, err := command(filepath.Join(repo, "cli"), g, "list", "-mod=vendor", "-m")
	if err != nil || strings.TrimSpace(string(m)) != modulePath {
		return "", errors.New("release module identity differs")
	}
	if _, err = command(filepath.Join(repo, "cli"), g, "list", "-mod=vendor", "-deps", entrypoint); err != nil {
		return "", errors.New("vendored release module closure is inconsistent")
	}
	return g, nil
}
func sourceInputs(repo, goBin string) error {
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "LICENSES/Go-BSD-3-Clause.txt"} {
		i, err := os.Lstat(filepath.Join(repo, name))
		if err != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("required legal input is unavailable")
		}
	}
	license, err := os.ReadFile(filepath.Join(repo, "LICENSES/Go-BSD-3-Clause.txt"))
	if err != nil {
		return errors.New("cannot read Go license")
	}
	goroot, err := command("", goBin, "env", "GOROOT")
	if err != nil {
		return errors.New("cannot locate Go root")
	}
	actual, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goroot)), "LICENSE"))
	if err != nil || string(license) != string(actual) {
		return errors.New("repository Go license differs from selected toolchain")
	}
	found := false
	err = filepath.WalkDir(filepath.Join(repo, "LICENSES"), func(_ string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errors.New("LICENSES contains unsupported entry")
		}
		if d.Type().IsRegular() {
			found = true
		}
		return nil
	})
	if err != nil || !found {
		return errors.New("LICENSES inventory is invalid")
	}
	return nil
}
func versionOK(v string) bool {
	if !strings.HasPrefix(v, "v") {
		return false
	}
	x := strings.TrimPrefix(v, "v")
	main, pre, build := x, "", ""
	if plus := strings.IndexByte(x, '+'); plus >= 0 {
		main, build = x[:plus], x[plus+1:]
		if build == "" || strings.Contains(build, "+") || !semverIdentifiers(build, false) {
			return false
		}
	}
	if dash := strings.IndexByte(main, '-'); dash >= 0 {
		main, pre = main[:dash], main[dash+1:]
		if pre == "" || !semverIdentifiers(pre, true) {
			return false
		}
	}
	p := strings.Split(main, ".")
	if len(p) != 3 {
		return false
	}
	for _, n := range p {
		if n == "" || (len(n) > 1 && n[0] == '0') {
			return false
		}
		for _, r := range n {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func semverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, r := range identifier {
			if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && r != '-' {
				return false
			}
			if r < '0' || r > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}
func target(t string) (string, string, error) {
	switch t {
	case "linux-amd64":
		return "linux", "amd64", nil
	case "linux-arm64":
		return "linux", "arm64", nil
	default:
		return "", "", errors.New("release target must be linux-amd64 or linux-arm64")
	}
}
func outputDir(repo, raw string) (string, error) {
	if raw == "" {
		return "", errors.New("output directory is required")
	}
	candidate, err := filepath.Abs(raw)
	if err != nil {
		return "", errors.New("cannot resolve output directory")
	}
	r, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", err
	}
	if within(r, candidate) {
		return "", errors.New("OUTPUT_DIR must be outside the Git checkout")
	}
	prospective, err := prospectivePath(candidate)
	if err != nil || within(r, prospective) {
		return "", errors.New("OUTPUT_DIR must be outside the Git checkout")
	}
	if err := os.MkdirAll(candidate, 0700); err != nil {
		return "", errors.New("cannot create output directory")
	}
	i, err := os.Lstat(candidate)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("output directory is unavailable")
	}
	p, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", errors.New("cannot resolve output directory")
	}
	if within(r, p) {
		return "", errors.New("OUTPUT_DIR must be outside the Git checkout")
	}
	return p, nil
}

func within(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}

// prospectivePath resolves the nearest existing ancestor before creating any
// output. This prevents an outside-looking path through an existing symlink
// from creating a directory inside the checkout.
func prospectivePath(candidate string) (string, error) {
	var suffix []string
	probe := candidate
	for {
		info, err := os.Lstat(probe)
		if err == nil {
			if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return "", errors.New("output ancestor is not a directory")
			}
			root, err := filepath.EvalSymlinks(probe)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				root = filepath.Join(root, suffix[i])
			}
			return root, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("output ancestor is unavailable")
		}
		suffix = append(suffix, filepath.Base(probe))
		probe = parent
	}
}
func stage(repo, goBin string, native bool) (string, string, string, error) {
	work, err := os.MkdirTemp("", "prufyx-community-release-*")
	if err != nil {
		return "", "", "", err
	}
	manifest := filepath.Join(work, "SOURCE-MANIFEST.json")
	staged := filepath.Join(work, "source")
	o := releasegate.Options{SourceRoot: repo, PolicyPath: filepath.Join(repo, policyRel), Go: goBin, OutputPath: manifest}
	if _, err = releasegate.Generate(o); err != nil {
		os.RemoveAll(work)
		return "", "", "", fmt.Errorf("release manifest: %w", err)
	}
	o.ManifestPath = manifest
	o.OutputPath = staged
	o.RunNativeChecks = native
	if _, err = releasegate.Stage(o); err != nil {
		os.RemoveAll(work)
		return "", "", "", fmt.Errorf("release source stage: %w", err)
	}
	return work, manifest, staged, nil
}
func digest(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

type tarEntry struct {
	disk, name string
	dir        bool
	mode       fs.FileMode
	size       int64
}

func entries(root, prefix string) ([]tarEntry, error) {
	var out []tarEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if name == "." {
			name = "."
		}
		if prefix != "" {
			if name == "." {
				name = strings.TrimSuffix(prefix, "/")
			} else {
				name = prefix + "/" + name
			}
		}
		i, e := d.Info()
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 || (!i.IsDir() && !i.Mode().IsRegular()) {
			return errors.New("archive source contains unsupported entry")
		}
		out = append(out, tarEntry{path, name, i.IsDir(), i.Mode(), i.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, err
}
func writeTar(root, prefix string, dst io.Writer, epoch time.Time) error {
	es, err := entries(root, prefix)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(dst)
	for _, e := range es {
		n := e.name
		if e.dir && !strings.HasSuffix(n, "/") {
			n += "/"
		}
		mode := int64(0644)
		typ := byte(tar.TypeReg)
		if e.dir {
			mode = 0755
			typ = tar.TypeDir
		} else if e.mode.Perm()&0111 != 0 {
			mode = 0755
		}
		h := &tar.Header{Name: n, Mode: mode, Size: e.size, Uid: 0, Gid: 0, ModTime: epoch, Typeflag: typ, Format: tar.FormatGNU}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !e.dir {
			src, err := os.Open(e.disk)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, src)
			closeErr := src.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return tw.Close()
}
func tarFile(root, prefix, out string, epoch time.Time) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = writeTar(root, prefix, f, epoch); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func tarGz(root, prefix, out string, epoch time.Time) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	g := gzip.NewWriter(f)
	g.Name = ""
	g.Comment = ""
	g.ModTime = time.Unix(0, 0)
	g.OS = 255
	if err = writeTar(root, prefix, g, epoch); err != nil {
		g.Close()
		f.Close()
		return err
	}
	if err = g.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func sourceDigest(stage, work string) (string, error) {
	p := filepath.Join(work, "source-tree.tar")
	if err := tarFile(stage, "", p, time.Unix(0, 0)); err != nil {
		return "", err
	}
	return digest(p)
}
func copyFile(source, dest string, perm fs.FileMode) error {
	b, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	return os.WriteFile(dest, b, perm)
}
func epoch(repo, revision string) (time.Time, error) {
	out, e := command(repo, "git", "show", "-s", "--format=%ct", revision)
	if e != nil {
		return time.Time{}, e
	}
	var n int64
	if _, e = fmt.Sscan(strings.TrimSpace(string(out)), &n); e != nil {
		return time.Time{}, e
	}
	return time.Unix(n, 0).UTC(), nil
}

func test(stdout, stderr io.Writer) error {
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	work, _, staged, e := stage(repo, g, true)
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	fmt.Fprintf(stderr, "testing revision %s on %s/%s\n", rev, runtime.GOOS, runtime.GOARCH)
	c := goTestCommand(g, staged, stdout, stderr)
	return c.Run()
}

func goTestCommand(goBin, staged string, stdout, stderr io.Writer) *exec.Cmd {
	c := exec.Command(goBin, "test", "-race", "./...", "-count=1")
	c.Dir = filepath.Join(staged, "cli")
	c.Env = append(os.Environ(), "CGO_ENABLED=1", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	c.Stdout = stdout
	c.Stderr = stderr
	return c
}

func binary(v, t, out string) (string, error) {
	if !versionOK(v) {
		return "", errors.New("version must be v-prefixed semantic version")
	}
	osName, arch, e := target(t)
	if e != nil {
		return "", e
	}
	repo, e := root()
	if e != nil {
		return "", e
	}
	rev, e := checkout(repo)
	if e != nil {
		return "", e
	}
	g, e := toolchain(repo)
	if e != nil {
		return "", e
	}
	if e = sourceInputs(repo, g); e != nil {
		return "", e
	}
	hostOS, e := command("", g, "env", "GOHOSTOS")
	if e != nil {
		return "", e
	}
	hostArch, e := command("", g, "env", "GOHOSTARCH")
	if e != nil {
		return "", e
	}
	if strings.TrimSpace(string(hostOS)) != osName || strings.TrimSpace(string(hostArch)) != arch {
		return "", errors.New("binary build and smoke require a native target runner")
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return "", e
	}
	num := strings.TrimPrefix(v, "v")
	archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch))
	if _, e = os.Lstat(archive); e == nil {
		return "", errors.New("refusing to overwrite archive")
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(work)
	srcDigest, e := sourceDigest(staged, work)
	if e != nil {
		return "", e
	}
	manifestDigest, e := digest(manifest)
	if e != nil {
		return "", e
	}
	buildTime, e := epoch(repo, rev)
	if e != nil {
		return "", e
	}
	goVersion, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return "", e
	}
	gv := strings.TrimSpace(string(goVersion))
	pkg := filepath.Join(work, fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch))
	if e = os.Mkdir(pkg, 0755); e != nil {
		return "", e
	}
	bin := filepath.Join(pkg, "prufyx")
	marker := fmt.Sprintf("PRUFYX_BUILD_IDENTITY_V1_BEGIN|%s|release|%s|%s|%s|%s|%s|%s|UNPINNED|true|PRUFYX_BUILD_IDENTITY_V1_END", v, rev, srcDigest, manifestDigest, t, buildTime.Format(time.RFC3339), gv)
	ld := fmt.Sprintf("-buildid= -s -w -X %s/internal/buildidentity.Version=%s -X %s/internal/buildidentity.SourceRevision=%s -X %s/internal/buildidentity.SourceTreeDigest=%s -X %s/internal/buildidentity.AllowlistDigest=%s -X %s/internal/buildidentity.BuildProfile=%s -X %s/internal/buildidentity.BuildEpoch=%d -X %s/internal/buildidentity.TrustRootDigest=UNPINNED -X %s/internal/buildidentity.EmbeddedIdentity=%s", modulePath, v, modulePath, rev, modulePath, srcDigest, modulePath, manifestDigest, modulePath, t, modulePath, buildTime.Unix(), modulePath, modulePath, marker)
	c := exec.Command(g, "build", "-trimpath", "-buildvcs=false", "-ldflags", ld, "-o", bin, entrypoint)
	c.Dir = filepath.Join(staged, "cli")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false", "SOURCE_DATE_EPOCH="+fmt.Sprint(buildTime.Unix()), "GOOS="+osName, "GOARCH="+arch)
	if output, e := c.CombinedOutput(); e != nil {
		return "", fmt.Errorf("release build failed: %s", strings.TrimSpace(string(output)))
	}
	if e = os.Chmod(bin, 0755); e != nil {
		return "", e
	}
	meta := filepath.Join(pkg, "RELEASE-METADATA.json")
	if e = releasehelpers.WriteMetadata(releasehelpers.MetadataOptions{Output: meta, Version: v, Revision: rev, SourceTreeDigest: srcDigest, ManifestDigest: manifestDigest, Target: t, BuildEpoch: fmt.Sprint(buildTime.Unix()), GoVersion: gv}); e != nil {
		return "", e
	}
	for _, n := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		if e = copyFile(filepath.Join(staged, n), filepath.Join(pkg, n), 0644); e != nil {
			return "", e
		}
	}
	if e = copyTree(filepath.Join(staged, "LICENSES"), filepath.Join(pkg, "LICENSES")); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(pkg, "SOURCE-REVISION"), []byte(rev+"\n"), 0644); e != nil {
		return "", e
	}
	versionOut, e := exec.Command(bin, "version").Output()
	if e != nil {
		return "", e
	}
	if e = releasehelpers.VerifyVersion(releasehelpers.VersionOptions{Metadata: meta, Report: versionOut}); e != nil {
		return "", e
	}
	demo := exec.Command(bin, "check", "prometheus-mode", "--demo", "--format", "json")
	raw, e := demo.Output()
	if exit, e2 := exitCode(e); e2 != nil || exit != 11 {
		return "", errors.New("Prometheus demo did not return UNKNOWN/11")
	}
	if e = releasehelpers.VerifyDemo(raw); e != nil {
		return "", e
	}
	return archive, tarGz(pkg, filepath.Base(pkg), archive, buildTime)
}
func exitCode(e error) (int, error) {
	if e == nil {
		return 0, nil
	}
	var x *exec.ExitError
	if errors.As(e, &x) {
		return x.ExitCode(), nil
	}
	return 0, e
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(src, path)
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0755)
		}
		if !d.Type().IsRegular() || d.Type()&os.ModeSymlink != 0 {
			return errors.New("source tree contains unsupported entry")
		}
		return copyFile(path, to, 0644)
	})
}

func source(v, out string) (string, error) {
	if !versionOK(v) {
		return "", errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return "", e
	}
	rev, e := checkout(repo)
	if e != nil {
		return "", e
	}
	g, e := goPath()
	if e != nil {
		return "", e
	}
	if e = sourceInputs(repo, g); e != nil {
		return "", e
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return "", e
	}
	num := strings.TrimPrefix(v, "v")
	archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num))
	if _, e = os.Lstat(archive); e == nil {
		return "", errors.New("refusing to overwrite archive")
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(work)
	d, e := sourceDigest(staged, work)
	if e != nil {
		return "", e
	}
	if e = tarGz(staged, fmt.Sprintf("prufyx-cli_%s_source", num), archive, time.Unix(0, 0)); e != nil {
		return "", e
	}
	if e = copyFile(manifest, filepath.Join(dst, "SOURCE-MANIFEST.json"), 0644); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dst, "SOURCE-REVISION"), []byte(rev+"\n"), 0644); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(dst, "SOURCE-TREE.sha256"), sourceTreeChecksum(d), 0644); e != nil {
		return "", e
	}
	return archive, nil
}

func sourceTreeChecksum(digest string) []byte {
	return []byte(strings.TrimPrefix(digest, "sha256:") + "  source-tree.tar\n")
}

func finalize(v, out string) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return e
	}
	for _, n := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		if e = copyFile(filepath.Join(repo, n), filepath.Join(dst, n), 0644); e != nil {
			return e
		}
	}
	if e = copyFile(filepath.Join(repo, "LICENSES", "Go-BSD-3-Clause.txt"), filepath.Join(dst, "Go-BSD-3-Clause.txt"), 0644); e != nil {
		return e
	}
	bt, e := epoch(repo, rev)
	if e != nil {
		return e
	}
	gv, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return e
	}
	if e = releasehelpers.WriteSBOM(releasehelpers.SBOMOptions{Output: filepath.Join(dst, "SBOM.spdx.json"), Version: v, Revision: rev, BuildEpoch: fmt.Sprint(bt.Unix()), GoVersion: strings.TrimSpace(string(gv)), Policy: filepath.Join(repo, policyRel)}); e != nil {
		return e
	}
	num := strings.TrimPrefix(v, "v")
	names := []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SBOM.spdx.json", "SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256", fmt.Sprintf("prufyx-cli_%s_linux_amd64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_linux_arm64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num)}
	sort.Strings(names)
	for _, n := range names {
		if i, e := os.Lstat(filepath.Join(dst, n)); e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("release output contains missing or unsafe file")
		}
	}
	f, e := os.OpenFile(filepath.Join(dst, "SHA256SUMS"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	for _, n := range names {
		d, e := digest(filepath.Join(dst, n))
		if e != nil {
			return e
		}
		if _, e = fmt.Fprintf(f, "%s  %s\n", strings.TrimPrefix(d, "sha256:"), n); e != nil {
			return e
		}
	}
	return nil
}

func smoke(v, t, out string, stdout io.Writer) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	osName, arch, e := target(t)
	if e != nil {
		return e
	}
	dst, e := filepath.EvalSymlinks(out)
	if e != nil {
		return errors.New("archive output directory is unavailable")
	}
	num := strings.TrimPrefix(v, "v")
	archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch))
	a, e := os.Lstat(archive)
	if e != nil || !a.Mode().IsRegular() || a.Mode()&os.ModeSymlink != 0 {
		return errors.New("native archive is unavailable")
	}
	work, e := os.MkdirTemp("", "prufyx-community-smoke-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if e = extract(archive, work); e != nil {
		return e
	}
	pkg := filepath.Join(work, fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch))
	if e = validateSmokeLayout(work, pkg); e != nil {
		return e
	}
	bin := filepath.Join(pkg, "prufyx")
	i, e := os.Lstat(bin)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive package layout is invalid")
	}
	if e = os.Chmod(bin, 0755); e != nil {
		return e
	}
	home := filepath.Join(work, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		return e
	}
	version := exec.Command(bin, "version")
	version.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TZ=UTC"}
	raw, e := version.Output()
	if e != nil {
		return e
	}
	if e = releasehelpers.VerifyVersion(releasehelpers.VersionOptions{Metadata: filepath.Join(pkg, "RELEASE-METADATA.json"), Report: raw}); e != nil {
		return e
	}
	values := filepath.Join(work, "cert-manager-values.json")
	if e = os.WriteFile(values, []byte("{\"prometheus\":{\"servicemonitor\":{\"path\":\"/release-smoke\"}}}\n"), 0600); e != nil {
		return e
	}
	cert := exec.Command(bin, "check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--format", "json")
	cert.Env = version.Env
	cr, e := cert.Output()
	xc, ec := exitCode(e)
	if ec != nil || xc != 10 {
		return errors.New("cert-manager smoke did not return BLOCKED/10")
	}
	certPath := filepath.Join(work, "cert.json")
	if e = os.WriteFile(certPath, cr, 0600); e != nil {
		return e
	}
	if e = releasehelpers.VerifyScoped("cert-manager", certPath); e != nil {
		return e
	}
	k := filepath.Join(work, "karmada.json")
	if e = os.WriteFile(k, []byte("{\"apiVersion\":\"policy.karmada.io/v1alpha1\",\"kind\":\"PropagationPolicy\",\"metadata\":{\"name\":\"release-smoke\"},\"spec\":{\"failover\":{\"application\":{\"purgeMode\":\"Immediately\"}}}}\n"), 0600); e != nil {
		return e
	}
	prepared := filepath.Join(work, "karmada-input.json")
	p := exec.Command(bin, "prepare", "cncf", "--project", "karmada", "--input", k, "--from", "1.18.3", "--to", "1.19.0", "--distribution", "official_upstream", "--target-policy-crd-admission", "required", "--format", "input")
	p.Env = version.Env
	pr, e := p.Output()
	if e != nil {
		return e
	}
	if e = os.WriteFile(prepared, pr, 0600); e != nil {
		return e
	}
	check := exec.Command(bin, "check", "cncf", "--project", "karmada", "--input", prepared, "--now", "2026-09-09T05:00:00Z", "--format", "json")
	check.Env = version.Env
	kr, e := check.Output()
	xc, ec = exitCode(e)
	if ec != nil || xc != 10 {
		return errors.New("Karmada smoke did not return BLOCKED/10")
	}
	kp := filepath.Join(work, "karmada-report.json")
	if e = os.WriteFile(kp, kr, 0600); e != nil {
		return e
	}
	if e = releasehelpers.VerifyScoped("karmada", kp); e != nil {
		return e
	}
	d, e := digest(archive)
	if e != nil {
		return e
	}
	return releasehelpers.WriteSmokeReceiptTo(stdout, releasehelpers.SmokeReceiptOptions{Version: v, Target: t, ArchiveDigest: d, Metadata: filepath.Join(pkg, "RELEASE-METADATA.json")})
}

func validateSmokeLayout(work, pkg string) error {
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(pkg) || !entries[0].IsDir() {
		return errors.New("archive extraction contains unexpected top-level paths")
	}
	for _, name := range []string{"go.mod", ".git"} {
		if _, err := os.Lstat(filepath.Join(pkg, name)); err == nil || !os.IsNotExist(err) {
			return errors.New("archive package contains source or repository metadata")
		}
	}
	return nil
}

func extract(archive, dst string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	g, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer g.Close()
	tr := tar.NewReader(g)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if filepath.IsAbs(h.Name) || strings.Contains(h.Name, "..") || strings.Contains(h.Name, "//") {
			return errors.New("archive contains unsafe member")
		}
		to := filepath.Join(dst, filepath.FromSlash(h.Name))
		if !strings.HasPrefix(to, dst+string(filepath.Separator)) {
			return errors.New("archive member escapes output")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(to, 0755); e != nil {
				return e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(to), 0755); e != nil {
				return e
			}
			o, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(h.Mode))
			if e != nil {
				return e
			}
			_, e = io.Copy(o, tr)
			ce := o.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return errors.New("archive contains unsupported member")
		}
	}
}

func verify(v, out string) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	dst, e := filepath.EvalSymlinks(out)
	if e != nil {
		return errors.New("release output directory unavailable")
	}
	num := strings.TrimPrefix(v, "v")
	names := []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SHA256SUMS", "SBOM.spdx.json", "SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256", fmt.Sprintf("prufyx-cli_%s_linux_amd64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_linux_arm64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num)}
	actual, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	if len(actual) != len(names) {
		return errors.New("release output contains unexpected files")
	}
	for _, n := range names {
		if _, e := os.Lstat(filepath.Join(dst, n)); e != nil {
			return errors.New("release output contains missing file")
		}
	}
	if b, e := os.ReadFile(filepath.Join(dst, "SOURCE-REVISION")); e != nil || string(b) != rev+"\n" {
		return errors.New("source revision asset mismatch")
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	expected, e := sourceDigest(staged, work)
	if e != nil {
		return e
	}
	tree, e := os.ReadFile(filepath.Join(dst, "SOURCE-TREE.sha256"))
	if e != nil || string(tree) != string(sourceTreeChecksum(expected)) {
		return errors.New("source tree digest asset mismatch")
	}
	if b, e := os.ReadFile(manifest); e != nil {
		return e
	} else if c, e := os.ReadFile(filepath.Join(dst, "SOURCE-MANIFEST.json")); e != nil || string(b) != string(c) {
		return errors.New("source manifest differs from exact policy and source bytes")
	}
	tmpSource := filepath.Join(work, "expected-source.tar.gz")
	if e = tarGz(staged, fmt.Sprintf("prufyx-cli_%s_source", num), tmpSource, time.Unix(0, 0)); e != nil {
		return e
	}
	if a, e := os.ReadFile(tmpSource); e != nil {
		return e
	} else if b, e := os.ReadFile(filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num))); e != nil || string(a) != string(b) {
		return errors.New("source archive differs from exact source stage")
	}
	bt, e := epoch(repo, rev)
	if e != nil {
		return e
	}
	gvb, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return e
	}
	sbom := filepath.Join(work, "SBOM.spdx.json")
	if e = releasehelpers.WriteSBOM(releasehelpers.SBOMOptions{Output: sbom, Version: v, Revision: rev, BuildEpoch: fmt.Sprint(bt.Unix()), GoVersion: strings.TrimSpace(string(gvb)), Policy: filepath.Join(repo, policyRel)}); e != nil {
		return e
	}
	if a, e := os.ReadFile(sbom); e != nil {
		return e
	} else if b, e := os.ReadFile(filepath.Join(dst, "SBOM.spdx.json")); e != nil || string(a) != string(b) {
		return errors.New("SBOM differs from exact release inputs")
	}
	for _, tt := range []string{"linux-amd64", "linux-arm64"} {
		osName, arch, _ := target(tt)
		archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch))
		if e = releasehelpers.VerifyArchive(releasehelpers.ArchiveOptions{Archive: archive, PackageName: fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch), RepositoryRoot: repo, BuildEpoch: fmt.Sprint(bt.Unix())}); e != nil {
			return e
		}
	}
	return verifySums(dst)
}
func verifySums(dir string) error {
	raw, e := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if e != nil {
		return e
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		p := strings.SplitN(line, "  ", 2)
		if len(p) != 2 || len(p[0]) != 64 {
			return errors.New("SHA256SUMS is invalid")
		}
		d, e := digest(filepath.Join(dir, p[1]))
		if e != nil || strings.TrimPrefix(d, "sha256:") != p[0] {
			return errors.New("SHA256SUMS mismatch")
		}
	}
	return nil
}
