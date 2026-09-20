package evidencerepin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx-cli/internal/maintainer/sourcecorpus"
)

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }
}

func rulePackJSON(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema":   "prufyx.io/rule-pack/v1",
		"revision": "test",
		"entries":  entries,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func ruleEntry(project, ruleID string, sources ...map[string]any) map[string]any {
	return map[string]any{
		"project": project,
		"rule": map[string]any{
			"id": ruleID,
			"evidence": map[string]any{
				"reviewedAt": "2026-09-12T10:00:00Z",
				"validUntil": "2026-12-11T10:00:00Z",
				"state":      "active",
				"sources":    sources,
			},
		},
	}
}

func source(id, owner, repo, commit, path, digest string, start, end int) map[string]any {
	return map[string]any{
		"id":            id,
		"url":           "https://github.com/" + owner + "/" + repo + "/blob/" + commit + "/" + path,
		"revision":      commit,
		"contentDigest": digest,
		"startLine":     start,
		"endLine":       end,
	}
}

const commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
const commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"

func TestLoadCitations(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1\nline2"))
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 2)))

	citations, err := LoadCitations("rules.json", raw)
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	if len(citations) != 1 {
		t.Fatalf("expected 1 citation, got %d", len(citations))
	}
	got := citations[0]
	if got.Owner != "argoproj" || got.Repo != "argo-cd" || got.Path != "VERSION" || got.OldCommit != commitA {
		t.Fatalf("unexpected citation: %+v", got)
	}
	if got.StartLine != 1 || got.EndLine != 2 {
		t.Fatalf("unexpected span: %+v", got)
	}
}

func TestLoadCitationsAcceptsRawGithubusercontentShape(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1"))
	raw := rulePackJSON(t, ruleEntry("dragonfly", "dragonfly.rule-1", map[string]any{
		"id":            "old-base-options",
		"url":           "https://raw.githubusercontent.com/dragonflyoss/dragonfly/" + commitA + "/cmd/dependency/base/option.go",
		"revision":      commitA,
		"contentDigest": digest,
		"startLine":     19,
		"endLine":       19,
	}))
	citations, err := LoadCitations("rules.json", raw)
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	if len(citations) != 1 || citations[0].Owner != "dragonflyoss" || citations[0].Repo != "dragonfly" || citations[0].Path != "cmd/dependency/base/option.go" {
		t.Fatalf("unexpected citation: %+v", citations)
	}
}

func TestLoadCitationsRejectsMismatchedRevision(t *testing.T) {
	entry := ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", "sha256:abc", 1, 1))
	// Corrupt the revision so it no longer matches the URL's embedded commit.
	entry["rule"].(map[string]any)["evidence"].(map[string]any)["sources"].([]map[string]any)[0]["revision"] = commitB
	raw := rulePackJSON(t, entry)
	if _, err := LoadCitations("rules.json", raw); err == nil {
		t.Fatal("expected rejection of mismatched revision/url commit")
	}
}

func TestClassifySpanIdentical(t *testing.T) {
	data := []byte("a\nb\nc\nd\ne")
	digest, ok := spanDigestAt([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}, 2, 3)
	if !ok {
		t.Fatal("expected ok")
	}
	class, start, end := classifySpan(digest, 2, 3, data)
	if class != ClassSpanIdentical || start != 2 || end != 3 {
		t.Fatalf("got class=%s start=%d end=%d", class, start, end)
	}
}

func TestClassifySpanMoved(t *testing.T) {
	lines := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	digest, _ := spanDigestAt(lines, 1, 2) // digest of "a\nb"
	// New file: same "a\nb" pair now appears at lines 3-4 instead of 1-2.
	newData := []byte("x\ny\na\nb\nz")
	class, start, end := classifySpan(digest, 1, 2, newData)
	if class != ClassSpanMoved {
		t.Fatalf("expected SPAN_MOVED, got %s", class)
	}
	if start != 3 || end != 4 {
		t.Fatalf("expected new range 3-4, got %d-%d", start, end)
	}
}

func TestClassifySpanContentChanged(t *testing.T) {
	class, _, _ := classifySpan("sha256:0000000000000000000000000000000000000000000000000000000000000000", 1, 2, []byte("totally\ndifferent\ncontent"))
	if class != ClassContentChanged {
		t.Fatalf("expected CONTENT_CHANGED, got %s", class)
	}
}

// fakeBlobFetcher implements sourcecapture.Fetcher over an in-memory map
// keyed by the exact raw path, so classification tests never touch the
// network.
type fakeBlobFetcher map[string]sourcecapture.FetchResult

func (f fakeBlobFetcher) Fetch(_ context.Context, path string) sourcecapture.FetchResult {
	if result, ok := f[path]; ok {
		return result
	}
	return sourcecapture.FetchResult{Kind: "HTTP_STATUS", StatusCode: 404}
}

func TestClassifyNoNewRelease(t *testing.T) {
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "VERSION", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	result := Classify(context.Background(), citation, commitA, fakeBlobFetcher{})
	if result.Class != ClassNoNewRelease {
		t.Fatalf("expected NO_NEW_RELEASE, got %s (%s)", result.Class, result.Detail)
	}
}

func TestClassifyPathGone(t *testing.T) {
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "removed.go", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	result := Classify(context.Background(), citation, commitB, fakeBlobFetcher{})
	if result.Class != ClassPathGone {
		t.Fatalf("expected PATH_GONE, got %s", result.Class)
	}
}

func TestClassifyEndToEndIdentical(t *testing.T) {
	body := []byte("first\nsecond\nthird")
	digest, _ := spanDigestAt([][]byte{[]byte("first"), []byte("second"), []byte("third")}, 2, 2)
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "util/helm/client.go", OldCommit: commitA, OldDigest: digest, StartLine: 2, EndLine: 2}
	fetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/util/helm/client.go": {Kind: "HTTP_200", StatusCode: 200, Body: body},
	}
	result := Classify(context.Background(), citation, commitB, fetcher)
	if result.Class != ClassSpanIdentical {
		t.Fatalf("expected SPAN_IDENTICAL, got %s (%s)", result.Class, result.Detail)
	}
	if result.NewCommit != commitB {
		t.Fatalf("expected NewCommit set, got %+v", result)
	}
}

// fakeAPIFetcher serves canned api.github.com responses keyed by path.
type fakeAPIFetcher struct {
	responses map[string]struct {
		body   []byte
		status int
	}
	calls []string
}

func (f *fakeAPIFetcher) Fetch(_ context.Context, path string) ([]byte, int, error) {
	f.calls = append(f.calls, path)
	if response, ok := f.responses[path]; ok {
		return response.body, response.status, nil
	}
	return nil, 404, nil
}

func TestResolveCurrentCommitLightweightTag(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v3.5.2","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":  {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	tag, commit, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v3.5.2" || commit != commitB {
		t.Fatalf("got tag=%s commit=%s", tag, commit)
	}
}

func TestResolveCurrentCommitSkipsPrereleases(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v3.6.0-rc1","draft":false,"prerelease":true},{"tag_name":"v3.5.2","draft":false,"prerelease":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":  {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	tag, commit, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v3.5.2" || commit != commitB {
		t.Fatalf("expected the newest non-prerelease v3.5.2/%s, got tag=%s commit=%s", commitB, tag, commit)
	}
}

func TestResolveCurrentCommitAnnotatedTagPeels(t *testing.T) {
	annotatedSHA := "ccccccccccccccccccccccccccccccccccccccc3"
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10":     {[]byte(`[{"tag_name":"v3.5.2","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v3.5.2":      {[]byte(`{"object":{"sha":"` + annotatedSHA + `","type":"tag"}}`), 200},
		"/repos/argoproj/argo-cd/git/tags/" + annotatedSHA: {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	_, commit, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if commit != commitB {
		t.Fatalf("expected peeled commit %s, got %s", commitB, commit)
	}
}

func TestResolveCurrentCommitFallsBackToTags(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/no-releases/releases?per_page=10": {[]byte(`[]`), 200},
		"/repos/example/no-releases/tags?per_page=1":      {[]byte(`[{"name":"v1.0.0"}]`), 200},
		"/repos/example/no-releases/git/ref/tags/v1.0.0":  {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	tag, commit, err := ResolveCurrentCommit(context.Background(), fetcher, "example", "no-releases")
	if err != nil {
		t.Fatalf("ResolveCurrentCommit: %v", err)
	}
	if tag != "v1.0.0" || commit != commitA {
		t.Fatalf("got tag=%s commit=%s", tag, commit)
	}
}

func TestResolveCurrentCommitRateLimited(t *testing.T) {
	fetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`{"message":"API rate limit exceeded"}`), 403},
	}}
	_, _, err := ResolveCurrentCommit(context.Background(), fetcher, "argoproj", "argo-cd")
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("expected rate-limited error, got %v", err)
	}
}

func TestBuildWorklistFalsificationArithmetic(t *testing.T) {
	// Three citations: two SPAN_IDENTICAL/NO_NEW_RELEASE, one CONTENT_CHANGED.
	// Batch-attestable-by-SPAN_IDENTICAL-alone fraction should be 1/3 < 0.5.
	body := []byte("alpha\nbeta\ngamma")
	identicalDigest, _ := spanDigestAt([][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}, 1, 1)
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "argo-cd", SourceID: "s1", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: identicalDigest, StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "argo-cd", SourceID: "s2", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitB, OldDigest: "sha256:irrelevant", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r3", Project: "argo-cd", SourceID: "s3", Owner: "argoproj", Repo: "argo-cd", Path: "a.go", OldCommit: commitA, OldDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", StartLine: 1, EndLine: 1},
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitB + `","type":"commit"}}`), 200},
	}}
	blobFetcher := fakeBlobFetcher{
		"/argoproj/argo-cd/" + commitB + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: body},
	}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, apiFetcher, blobFetcher, fixedNow(), nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if worklist.Summary.Classified != 3 {
		t.Fatalf("expected 3 classified, got %+v", worklist.Summary)
	}
	if worklist.Summary.Distribution[ClassSpanIdentical] != 1 {
		t.Fatalf("expected 1 SPAN_IDENTICAL, got %+v", worklist.Summary.Distribution)
	}
	if worklist.Summary.Distribution[ClassNoNewRelease] != 1 {
		t.Fatalf("expected 1 NO_NEW_RELEASE, got %+v", worklist.Summary.Distribution)
	}
	if worklist.Summary.Distribution[ClassContentChanged] != 1 {
		t.Fatalf("expected 1 CONTENT_CHANGED, got %+v", worklist.Summary.Distribution)
	}
	// SPAN_IDENTICAL alone is 1/3 < 0.5: the falsification condition fires.
	if !worklist.Summary.FalsificationMet {
		t.Fatalf("expected falsification condition met, got %+v", worklist.Summary)
	}
	// Worklist must be cost-ordered: NO_NEW_RELEASE/SPAN_IDENTICAL first.
	if worklist.Citations[0].Class == ClassContentChanged {
		t.Fatalf("expected cheapest class first, got %s", worklist.Citations[0].Class)
	}
	if len(worklist.Rules) != 3 {
		t.Fatalf("expected 3 rule verdicts, got %d", len(worklist.Rules))
	}
}

func TestBuildWorklistRateLimitDegradesGracefully(t *testing.T) {
	citations := []Citation{
		{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
		{RulePack: "p", RuleID: "r2", Project: "a", SourceID: "s2", Owner: "owner2", Repo: "repo2", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/owner1/repo1/releases?per_page=10": {[]byte(`{"message":"rate limited"}`), 403},
	}}
	state := newState()
	worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), nil)
	if err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if worklist.Summary.Pending != 2 {
		t.Fatalf("expected both citations pending after rate limit, got %+v", worklist.Summary)
	}
	// Second repo must never have been attempted once the first hit the limit.
	for _, call := range apiFetcher.calls {
		if strings.Contains(call, "owner2") {
			t.Fatalf("expected no calls for owner2 after rate limit, got call %q", call)
		}
	}
	if state.Repos["owner1/repo1"].Status != repoPendingRateLimited {
		t.Fatalf("expected owner1/repo1 marked rate-limited, got %+v", state.Repos["owner1/repo1"])
	}
}

func TestStateRoundTripResumesWithoutReclassifying(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	citation := Citation{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/owner1/repo1/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/owner1/repo1/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if _, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, state, apiFetcher, fakeBlobFetcher{}, fixedNow(), nil); err != nil {
		t.Fatalf("BuildWorklist: %v", err)
	}
	if err := SaveState(statePath, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Second run: reload state, wipe the api fetcher's responses so any new
	// call would 404. Resumed run must reuse the cached result rather than
	// reclassifying, and must issue zero further API calls for this repo.
	resumed, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState resume: %v", err)
	}
	blankFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{}}
	worklist, err := BuildWorklist(context.Background(), []Citation{citation}, nil, 0, resumed, blankFetcher, fakeBlobFetcher{}, fixedNow(), nil)
	if err != nil {
		t.Fatalf("BuildWorklist resume: %v", err)
	}
	if len(blankFetcher.calls) != 0 {
		t.Fatalf("expected resumed run to make no API calls, got %v", blankFetcher.calls)
	}
	if worklist.Summary.Classified != 1 {
		t.Fatalf("expected resumed classification preserved, got %+v", worklist.Summary)
	}
}

func TestFilterCitationsByProjectAndLimit(t *testing.T) {
	citations := []Citation{
		{RuleID: "b", SourceID: "1", Project: "argo-cd"},
		{RuleID: "a", SourceID: "1", Project: "argo-cd"},
		{RuleID: "a", SourceID: "1", Project: "cilium"},
	}
	filtered := filterCitations(citations, []string{"argo-cd"}, 0)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 argo-cd citations, got %d", len(filtered))
	}
	// Deterministic ordering: sorted by rule id, then source id.
	if filtered[0].RuleID != "a" || filtered[1].RuleID != "b" {
		t.Fatalf("expected sorted order, got %+v", filtered)
	}
	limited := filterCitations(citations, nil, 1)
	if len(limited) != 1 {
		t.Fatalf("expected limit=1 to cap to 1 citation, got %d", len(limited))
	}
}

func TestRunWritesWorklistAndRejectsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	digest := sourcecorpus.SHA([]byte("v1"))
	rulesPath := filepath.Join(dir, "rules.json")
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 1)))
	if err := os.WriteFile(rulesPath, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}

	var stdout, stderr strings.Builder
	code := Run(context.Background(), []string{"repin"}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 2 {
		t.Fatalf("expected rejection without --output, got code=%d stderr=%s", code, stderr.String())
	}

	outputPath := filepath.Join(dir, "worklist.json")
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"repin", "--output", outputPath}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%s", code, stderr.String())
	}
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var worklist Worklist
	if err := json.Unmarshal(written, &worklist); err != nil {
		t.Fatalf("decode worklist: %v", err)
	}
	if worklist.Schema != Schema {
		t.Fatalf("unexpected schema: %s", worklist.Schema)
	}
	if worklist.Summary.Distribution[ClassNoNewRelease] != 1 {
		t.Fatalf("expected NO_NEW_RELEASE for a citation already at the current commit, got %+v", worklist.Summary)
	}
}

func TestRunNeverWritesRulePack(t *testing.T) {
	dir := t.TempDir()
	digest := sourcecorpus.SHA([]byte("v1"))
	rulesPath := filepath.Join(dir, "rules.json")
	raw := rulePackJSON(t, ruleEntry("argo-cd", "argo-cd.rule-1",
		source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 1)))
	if err := os.WriteFile(rulesPath, raw, 0o444); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	apiFetcher := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/argoproj/argo-cd/releases?per_page=10": {[]byte(`[{"tag_name":"v1","draft":false}]`), 200},
		"/repos/argoproj/argo-cd/git/ref/tags/v1":      {[]byte(`{"object":{"sha":"` + commitA + `","type":"commit"}}`), 200},
	}}
	var stdout, stderr strings.Builder
	outputPath := filepath.Join(dir, "worklist.json")
	code := Run(context.Background(), []string{"repin", "--output", outputPath}, &stdout, &stderr, apiFetcher, fakeBlobFetcher{}, fixedNow(), []string{rulesPath})
	if code != 0 {
		t.Fatalf("expected success, got code=%d stderr=%s", code, stderr.String())
	}
	after, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read fixture after run: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("rule pack was modified by evidence repin")
	}
}
