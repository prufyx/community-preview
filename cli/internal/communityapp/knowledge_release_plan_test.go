package communityapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
	"github.com/prufyx/prufyx-cli/internal/knowledge"
	"github.com/prufyx/prufyx-cli/internal/knowledgereleaseplan"
	"github.com/prufyx/prufyx-cli/internal/maintainer/knowledgepublish"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type publishedRelease struct {
	url, revision string
	packageRaw    []byte
	planRaw       []byte
}

type publisherTestKey struct {
	private ed25519.PrivateKey
	signer  signature.Signer
	id      string
}

func TestKnowledgeReleasePlanPublisherToClientFirstAndSecondUpdate(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	store := filepath.Join(dir, "store")
	packages := map[string][]byte{}
	for i, release := range releases {
		planPath := writeKnowledgeReleaseFile(t, dir, "plan-"+release.revision+".json", release.planRaw)
		plan, err := knowledgereleaseplan.Parse(release.planRaw)
		if err != nil {
			t.Fatal(err)
		}
		assertionDigest, err := plan.VerificationAssertionsDigest()
		if err != nil {
			t.Fatal(err)
		}
		packages[release.url] = release.packageRaw
		outputPath := filepath.Join(dir, "package-"+release.revision+".tar")
		args := []string{"--release-plan", planPath, "--package-out", outputPath, "--db-root", store, "--format", "json"}
		if i == 0 {
			args = append(args, "--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest)
		}
		calls := 0
		code, output, stderr := runReleasePlanUpdate(t, args, func(_ context.Context, source string) ([]byte, error) {
			calls++
			return bytes.Clone(packages[source]), nil
		})
		if code != ExitOK || stderr != "" || calls != 1 || output.Status != "IMPORTED" || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.ImportReceipt == nil || output.ImportReceipt.TrustReceipt.KnowledgeRevision != release.revision || output.ImportReceipt.TrustReceipt.APIVersion != "prufyx.io/knowledge-trust-receipt/v2" || output.ImportReceipt.TrustReceipt.ExpectedVerificationAssertionsDigest != assertionDigest {
			t.Fatalf("release %d: code=%d calls=%d output=%+v stderr=%q", i, code, calls, output, stderr)
		}
		retained, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(retained, release.packageRaw) {
			t.Fatalf("release %d retained package mismatch: %v", i, err)
		}
	}
	status, err := knowledge.InspectConstraints(store)
	if err != nil || status.SelectedRevision != releases[1].revision {
		t.Fatalf("second plan did not select revision %s: %+v err=%v", releases[1].revision, status, err)
	}
}

func TestKnowledgeReleasePlanWrongPackageDigestPrecedesStoreMutation(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	plan, err := knowledgereleaseplan.Parse(releases[0].planRaw)
	if err != nil {
		t.Fatal(err)
	}
	plan.Package.Digest = "sha256:" + strings.Repeat("0", 64)
	planRaw, err := knowledgereleaseplan.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := writeKnowledgeReleaseFile(t, dir, "wrong-package-plan.json", planRaw)
	store := filepath.Join(dir, "store")
	outputPath := filepath.Join(dir, "retained.tar")
	calls := 0
	code, output, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", planPath, "--package-out", outputPath, "--db-root", store,
		"--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest, "--format", "json",
	}, func(context.Context, string) ([]byte, error) {
		calls++
		return bytes.Clone(releases[0].packageRaw), nil
	})
	if code != ExitIntegrity || stderr != "" || calls != 1 || !output.NetworkAttempted || !output.TransferCompleted || !output.PackageRetained || output.PackageDigest != testDigest(releases[0].packageRaw) || output.ImportReceipt != nil || output.Rejection != nil || output.ReasonCode != "KNOWLEDGE_PACKAGE_IMPORT_REJECTED" {
		t.Fatalf("code=%d calls=%d output=%+v stderr=%q", code, calls, output, stderr)
	}
	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Fatalf("wrong package digest reached store: %v", err)
	}
}

func TestKnowledgeReleasePlanVerifiedBindingMismatchesCannotSelect(t *testing.T) {
	rootRaw, rootDigest, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeKnowledgeReleaseFile(t, dir, "test-root.json", rootRaw)
	store := filepath.Join(dir, "store")
	firstPlan := writeKnowledgeReleaseFile(t, dir, "first-plan.json", releases[0].planRaw)
	code, _, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", firstPlan, "--package-out", filepath.Join(dir, "first.tar"), "--db-root", store,
		"--bootstrap-root", rootPath, "--bootstrap-root-digest", rootDigest, "--format", "json",
	}, func(context.Context, string) ([]byte, error) { return bytes.Clone(releases[0].packageRaw), nil })
	if code != ExitOK || stderr != "" {
		t.Fatalf("bootstrap failed: code=%d stderr=%q", code, stderr)
	}
	base, err := knowledgereleaseplan.Parse(releases[1].planRaw)
	if err != nil {
		t.Fatal(err)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name   string
		mutate func(*knowledgereleaseplan.Plan)
	}{
		{name: "role", mutate: func(p *knowledgereleaseplan.Plan) { p.PublisherVerification.Timestamp.Digest = badDigest }},
		{name: "target digest", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.Digest = badDigest }},
		{name: "revision", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.Revision = "999" }},
		{name: "capability", mutate: func(p *knowledgereleaseplan.Plan) { p.Target.EngineCapabilityDigest = badDigest }},
		{name: "root", mutate: func(p *knowledgereleaseplan.Plan) {
			p.PublisherVerification.PublisherInitialRootDigest = badDigest
			p.PublisherVerification.RootHistory[0].Digest = badDigest
			p.PublisherVerification.Root.Digest = badDigest
		}},
	}
	for caseIndex, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			plan.PublisherVerification.RootHistory = append([]knowledge.RootHistoryEntry(nil), base.PublisherVerification.RootHistory...)
			test.mutate(&plan)
			raw, err := knowledgereleaseplan.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			planPath := writeKnowledgeReleaseFile(t, dir, "bad-plan-"+strings.ReplaceAll(test.name, " ", "-")+".json", raw)
			calls := 0
			code, output, stderr := runReleasePlanUpdate(t, []string{
				"--release-plan", planPath, "--package-out", filepath.Join(dir, "bad-package-"+string(rune('a'+caseIndex))+".tar"), "--db-root", store, "--format", "json",
			}, func(context.Context, string) ([]byte, error) {
				calls++
				return bytes.Clone(releases[1].packageRaw), nil
			})
			if code != ExitIntegrity || stderr != "" || calls != 1 || !output.PackageRetained || output.Rejection == nil || output.Rejection.SelectionChanged {
				t.Fatalf("code=%d calls=%d output=%+v stderr=%q", code, calls, output, stderr)
			}
			if output.Rejection.TrustStateAdvanced != (caseIndex == 0) {
				t.Fatalf("trust progress is not truthful for case %d: %+v", caseIndex, output.Rejection)
			}
			status, err := knowledge.InspectConstraints(store)
			if err != nil && !errors.Is(err, knowledge.ErrTrustAdvanced) {
				t.Fatalf("status failed: %+v err=%v", status, err)
			}
			if status.SelectedRevision != releases[0].revision {
				t.Fatalf("binding mismatch selected revision: %+v", status)
			}
		})
	}
}

func TestKnowledgeReleasePlanRejectsConflictAndMalformedPlanBeforeFetch(t *testing.T) {
	_, _, releases := publishedReleaseFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	validPath := writeKnowledgeReleaseFile(t, dir, "valid-plan.json", releases[0].planRaw)
	duplicatePath := writeKnowledgeReleaseFile(t, dir, "duplicate-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"schema":`), []byte(`"schema":"prufyx.io/knowledge-release-plan/v1","schema":`), 1))
	unknownPath := writeKnowledgeReleaseFile(t, dir, "unknown-plan.json", append(releases[0].planRaw[:len(releases[0].planRaw)-1], []byte(`,"unknown":true}`)...))
	oversizedPath := writeKnowledgeReleaseFile(t, dir, "oversized-plan.json", bytes.Repeat([]byte{'x'}, knowledgereleaseplan.MaxBytes+1))
	unsupportedProfilePath := writeKnowledgeReleaseFile(t, dir, "unsupported-profile-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"profile":"cncf"`), []byte(`"profile":"cert-manager"`), 1))
	wrongTargetPath := writeKnowledgeReleaseFile(t, dir, "wrong-target-plan.json", bytes.Replace(releases[0].planRaw, []byte(`"path":"knowledge/constraints.v1.json"`), []byte(`"path":"knowledge/other.json"`), 1))
	cases := [][]string{
		{"--release-plan", validPath, "--source", releases[0].url},
		{"--release-plan", validPath, "--profile", "cncf"},
		{"--release-plan", validPath, "--expected-revision", "1"},
		{"--release-plan", validPath, "--expected-bundle-digest", testDigest(releases[0].packageRaw)},
		{"--release-plan", duplicatePath},
		{"--release-plan", unknownPath},
		{"--release-plan", oversizedPath},
		{"--release-plan", unsupportedProfilePath},
		{"--release-plan", wrongTargetPath},
	}
	for i, prefix := range cases {
		args := append(append([]string{}, prefix...), "--package-out", filepath.Join(dir, "rejected-"+string(rune('a'+i))+".tar"), "--db-root", filepath.Join(dir, "store"), "--format", "json")
		calls := 0
		code, output, stderr := runReleasePlanUpdate(t, args, func(context.Context, string) ([]byte, error) {
			calls++
			return nil, nil
		})
		if code != ExitUsage || calls != 0 || output.APIVersion != "" || strings.Contains(stderr, dir) {
			t.Fatalf("case %d: code=%d calls=%d output=%+v stderr=%q", i, code, calls, output, stderr)
		}
	}
}

func runReleasePlanUpdate(t *testing.T, args []string, fetch func(context.Context, string) ([]byte, error)) (int, knowledgeUpdateOutput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	code := r.databaseUpdateWithFetch(context.Background(), args, fetch)
	var output knowledgeUpdateOutput
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatalf("invalid update output: %s", stdout.String())
		}
	}
	return code, output, stderr.String()
}

func publishedReleaseFixture(t *testing.T) ([]byte, string, []publishedRelease) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	keys := map[string]publisherTestKey{}
	root := metadata.Root(now.Add(7 * 24 * time.Hour))
	root.Signed.Version = 1
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := signature.LoadSigner(private, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		id, err := key.ID()
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
		keys[role] = publisherTestKey{private: private, signer: signer, id: id}
	}
	if _, err := root.Sign(keys[metadata.ROOT].signer); err != nil {
		t.Fatal(err)
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	rootDigest := releaseDigest(rootRaw)
	t.Cleanup(func() {
		for _, key := range keys {
			for i := range key.private {
				key.private[i] = 0
			}
		}
	})
	releases := make([]publishedRelease, 0, 2)
	for index, revision := range []string{"61", "62"} {
		version := int64(index + 1)
		target := emptyPublishedTarget(t, revision)
		targetsPrep, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: version, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		targets := finalizePublisherTestRole(t, rootRaw, rootDigest, targetsPrep, keys[metadata.TARGETS])
		snapshotPrep, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: rootRaw, Target: target, Targets: targets, RootDigest: rootDigest, Version: version, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := finalizePublisherTestRole(t, rootRaw, rootDigest, snapshotPrep, keys[metadata.SNAPSHOT])
		timestampPrep, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, RootDigest: rootDigest, Version: version, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		timestamp := finalizePublisherTestRole(t, rootRaw, rootDigest, timestampPrep, keys[metadata.TIMESTAMP])
		url := "https://metadata.example.test/cncf-" + revision + ".tar"
		packageRaw, planRaw, receipt, err := knowledgepublish.FinalizePackageWithReleasePlan(knowledgepublish.FinalizePackageOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}, url)
		if err != nil || receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.KnowledgeRevision != revision {
			t.Fatalf("publisher finalization revision=%s receipt=%+v err=%v", revision, receipt, err)
		}
		releases = append(releases, publishedRelease{url: url, revision: revision, packageRaw: packageRaw, planRaw: planRaw})
	}
	return rootRaw, rootDigest, releases
}

func finalizePublisherTestRole(t *testing.T, root []byte, rootDigest string, preparation knowledgepublish.Preparation, key publisherTestKey) []byte {
	t.Helper()
	signatureRaw := ed25519.Sign(key.private, preparation.Payload)
	envelope, err := json.Marshal(knowledgepublish.SignatureEnvelope{
		Schema: knowledgepublish.SignatureEnvelopeSchema, Role: preparation.Role,
		PayloadDigest: releaseDigest(preparation.Payload),
		Signatures:    []knowledgepublish.SignatureInput{{KeyID: key.id, Sig: hex.EncodeToString(signatureRaw)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := knowledgepublish.FinalizeRole(root, rootDigest, preparation.Role, preparation.UnsignedMetadata, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func emptyPublishedTarget(t *testing.T, revision string) []byte {
	t.Helper()
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	pack := struct {
		Schema, Revision, PolicyID, PolicyDigest, LandscapeFileDigest, RegistryDigest string
		Entries                                                                       []any `json:"entries"`
	}{
		Schema: requirements.PackSchema, Revision: revision, PolicyID: requirements.PolicyID,
		PolicyDigest: requirements.PolicyDigest, LandscapeFileDigest: requirements.LandscapeFileDigest,
		RegistryDigest: requirements.RegistryDigest, Entries: []any{},
	}
	// Use explicit tags through a map-free wrapper so production closed-shape
	// admission sees the exact field names used by the publisher contract.
	packRaw, err := json.Marshal(struct {
		Schema              string `json:"schema"`
		Revision            string `json:"revision"`
		PolicyID            string `json:"policyId"`
		PolicyDigest        string `json:"policyDigest"`
		LandscapeFileDigest string `json:"landscapeFileDigest"`
		RegistryDigest      string `json:"registryDigest"`
		Entries             []any  `json:"entries"`
	}{pack.Schema, pack.Revision, pack.PolicyID, pack.PolicyDigest, pack.LandscapeFileDigest, pack.RegistryDigest, pack.Entries})
	if err != nil {
		t.Fatal(err)
	}
	target, err := json.Marshal(struct {
		Schema                 string          `json:"schema"`
		Revision               string          `json:"revision"`
		Purpose                string          `json:"purpose"`
		EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
		Pack                   json.RawMessage `json:"pack"`
	}{requirements.Schema, revision, "operator_provided", requirements.EngineCapabilityDigest, packRaw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(target); err != nil {
		t.Fatal(err)
	}
	return target
}

func writeKnowledgeReleaseFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func releaseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
