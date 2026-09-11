package buildidentity

import (
	"runtime"
	"strings"
	"testing"
)

func TestReportDevelopmentIsExplicitAndPathFree(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	resetLinkerValues()

	identity, err := Report()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ReleaseState != ReleaseStateDevelopment || !identity.CandidateOnly {
		t.Fatalf("development identity = %#v", identity)
	}
	if identity.Version != "dev" || identity.SourceRevision != DevelopmentValue || identity.BuildProfile != DevelopmentProfile || identity.BuildEpoch != DevelopmentValue {
		t.Fatalf("development identity did not remain explicitly unbound: %#v", identity)
	}
}

func TestReportPinnedIdentityUsesExactInputsAndUTCBackendEpoch(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	Version = "1.2.3"
	SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "linux-amd64"
	BuildEpoch = "1700000000"
	TrustRootDigest = "unpinned"
	EmbeddedIdentity = Marker(Identity{Version: Version, ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "2023-11-14T22:13:20Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})

	identity, err := Report()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ReleaseState != ReleaseStateRelease || !identity.CandidateOnly {
		t.Fatalf("pinned identity = %#v", identity)
	}
	if identity.Version != Version || identity.SourceRevision != SourceRevision || identity.SourceTreeDigest != SourceTreeDigest || identity.AllowlistDigest != AllowlistDigest || identity.BuildProfile != BuildProfile || identity.TrustRootDigest != TrustRootDigest {
		t.Fatalf("pinned values changed: %#v", identity)
	}
	if identity.BuildEpoch != "2023-11-14T22:13:20Z" {
		t.Fatalf("build epoch = %q, want UTC instant", identity.BuildEpoch)
	}
}

func TestReportRejectsMalformedReleaseIdentity(t *testing.T) {
	cases := []struct {
		name string
		set  func()
	}{
		{"version", func() { Version = "release" }},
		{"revision", func() { Version = "1.2.3"; SourceRevision = "../private" }},
		{"tree digest", func() { Version = "1.2.3"; SourceTreeDigest = "sha256:" + strings.Repeat("0", 63) }},
		{"epoch", func() { Version = "1.2.3"; BuildEpoch = "-1" }},
		{"profile", func() { Version = "1.2.3"; BuildProfile = "/tmp" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := linkerSnapshot()
			defer old.restore()
			resetLinkerValues()
			tc.set()
			if _, err := Report(); err == nil || !strings.Contains(err.Error(), ErrIntegrity.Error()) {
				t.Fatalf("Report() error = %v, want integrity failure", err)
			}
		})
	}
}

func TestReportForVersionPreservesDeterministicPinnedFields(t *testing.T) {
	old := linkerSnapshot()
	defer old.restore()
	resetLinkerValues()
	SourceRevision = "0123456789abcdef"
	SourceTreeDigest = "sha256:" + strings.Repeat("a", 64)
	AllowlistDigest = "sha256:" + strings.Repeat("b", 64)
	BuildProfile = "linux-arm64"
	BuildEpoch = "0"
	TrustRootDigest = "sha256:" + strings.Repeat("c", 64)
	EmbeddedIdentity = Marker(Identity{Version: "1.2.3", ReleaseState: ReleaseStateRelease, SourceRevision: SourceRevision, SourceTreeDigest: SourceTreeDigest, AllowlistDigest: AllowlistDigest, BuildProfile: BuildProfile, BuildEpoch: "1970-01-01T00:00:00Z", GoVersion: runtime.Version(), TrustRootDigest: TrustRootDigest, CandidateOnly: true})
	first, err := ReportForVersion("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReportForVersion("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same inputs yielded different identities: %#v != %#v", first, second)
	}
}

type snapshot struct {
	version, sourceRevision, sourceTreeDigest, allowlistDigest string
	buildProfile, buildEpoch, trustRootDigest                  string
	embeddedIdentity                                           string
}

func linkerSnapshot() snapshot {
	return snapshot{Version, SourceRevision, SourceTreeDigest, AllowlistDigest, BuildProfile, BuildEpoch, TrustRootDigest, EmbeddedIdentity}
}

func (s snapshot) restore() {
	Version, SourceRevision, SourceTreeDigest, AllowlistDigest = s.version, s.sourceRevision, s.sourceTreeDigest, s.allowlistDigest
	BuildProfile, BuildEpoch, TrustRootDigest, EmbeddedIdentity = s.buildProfile, s.buildEpoch, s.trustRootDigest, s.embeddedIdentity
}

func resetLinkerValues() {
	Version = DevelopmentVersion
	SourceRevision = DevelopmentValue
	SourceTreeDigest = DevelopmentValue
	AllowlistDigest = DevelopmentValue
	BuildProfile = DevelopmentProfile
	BuildEpoch = DevelopmentValue
	TrustRootDigest = DevelopmentValue
	EmbeddedIdentity = DevelopmentValue
}
