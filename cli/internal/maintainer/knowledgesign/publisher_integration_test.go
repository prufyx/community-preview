package knowledgesign_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
	"github.com/prufyx/prufyx-cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx-cli/internal/maintainer/knowledgesign"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestEncryptedRoleKeysFinalizeExportedFullCNCFPack(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "keys")
	now := time.Now().UTC().Truncate(time.Second)
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{
		KeyDir: keyDir, RootExpires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Passphrase: []byte("integration passphrase 123"),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := cncfcheck.ExportEmbeddedExternalBundle("61")
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Pack struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(target, &exported); err != nil || len(exported.Pack.Entries) == 0 {
		t.Fatalf("exported entries=%d err=%v", len(exported.Pack.Entries), err)
	}

	targetsPreparation, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Target: target,
		Version: 11, Expires: now.Add(72 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	targets := signAndFinalize(t, initialized, keyDir, metadata.TARGETS, targetsPreparation)

	snapshotPreparation, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Target: target, Targets: targets,
		Version: 12, Expires: now.Add(48 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := signAndFinalize(t, initialized, keyDir, metadata.SNAPSHOT, snapshotPreparation)

	timestampPreparation, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Target: target, Targets: targets, Snapshot: snapshot,
		Version: 13, Expires: now.Add(24 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := signAndFinalize(t, initialized, keyDir, metadata.TIMESTAMP, timestampPreparation)

	packageRaw, receipt, err := knowledgepublish.FinalizePackage(knowledgepublish.FinalizePackageOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Target: target,
		Targets: targets, Snapshot: snapshot, Timestamp: timestamp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packageRaw) == 0 || receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.KnowledgeRevision != "61" || !receipt.Verification.HasRule || receipt.Verification.Status != "VERIFIED" || receipt.NetworkUsed || receipt.KeysHandled || receipt.Verification.NetworkUsed || receipt.Verification.StoreUsed {
		t.Fatalf("package bytes=%d receipt=%+v", len(packageRaw), receipt)
	}
}

func signAndFinalize(t *testing.T, initialized knowledgesign.InitResult, keyDir, role string, prepared knowledgepublish.Preparation) []byte {
	t.Helper()
	keyRaw, err := os.ReadFile(filepath.Join(keyDir, role+".key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := knowledgesign.SignRole(knowledgesign.SignOptions{
		Root: initialized.Root, RootDigest: initialized.RootDigest, Role: role,
		Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: sha256Digest(prepared.Payload),
		EncryptedKey: keyRaw, Passphrase: []byte("integration passphrase 123"),
	})
	if err != nil {
		t.Fatal(err)
	}
	finalized, err := knowledgepublish.FinalizeRole(initialized.Root, initialized.RootDigest, role, prepared.UnsignedMetadata, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
