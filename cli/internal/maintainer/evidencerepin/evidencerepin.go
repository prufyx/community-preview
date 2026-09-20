// Package evidencerepin implements the "evidence repin" maintainer
// subcommand: the first increment of Workstream 5's staleness pipeline
// (product-discovery/prufyx/DESIGN-rule-ingestion.md, section 8).
//
// It re-resolves the existing rule packs' citations at each project's
// current upstream release commit and classifies what happened to each one
// (see section 6.2 of the design doc):
//
//   - SPAN_IDENTICAL  - same path, same lines, byte-identical content
//   - SPAN_MOVED      - same content found at a different line range
//   - CONTENT_CHANGED - path exists, cited span content differs
//   - PATH_GONE       - path or repository no longer resolvable
//   - NO_NEW_RELEASE  - no release since the citation's pinned commit
//
// It is deterministic and involves no model anywhere. It reads rule packs
// and network bytes and writes a worklist; it never writes to a rule pack
// or a review record, and it never fabricates or alters a compatibility
// claim. Digesting reuses maintainer/sourcecorpus's span-digest convention
// (LF-split, joined with LF, no trailing separator, no normalization) and
// blob retrieval reuses maintainer/sourcecapture's fixed-URL immutable-blob
// fetch discipline (no discovery, no redirects, fixed host, bounded size).
package evidencerepin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx-cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx-cli/internal/maintainer/sourcecorpus"
)

const (
	// Schema identifies the worklist artifact this command produces.
	Schema = "prufyx.io/evidence-repin-worklist/v1"
	// Authority states plainly what this output is and is not.
	Authority = "LOCAL_MECHANICAL_CITATION_DRIFT_CLASSIFICATION_NOT_A_CLAIM"
	// StateSchema identifies the resumable progress file.
	StateSchema = "prufyx.io/evidence-repin-state/v1"

	maxRulesBytes int64 = 16 << 20
	maxAPIBytes   int64 = 4 << 20
	maxStateBytes int64 = 64 << 20

	// Drift classes, per DESIGN-rule-ingestion.md section 6.2.
	ClassSpanIdentical  = "SPAN_IDENTICAL"
	ClassSpanMoved      = "SPAN_MOVED"
	ClassContentChanged = "CONTENT_CHANGED"
	ClassPathGone       = "PATH_GONE"
	ClassNoNewRelease   = "NO_NEW_RELEASE"
	// ClassPending is not one of the five reported drift classes. It marks
	// a citation this run could not resolve (rate limit, transport error,
	// or a repo not yet attempted) so a later run can retry it.
	ClassPending = "PENDING"

	repoResolved           = "RESOLVED"
	repoPendingRateLimited = "PENDING_RATE_LIMITED"
	repoPendingError       = "PENDING_ERROR"
	repoNoReleasesOrTags   = "NO_RELEASES_OR_TAGS"
)

var (
	errRejected    = errors.New("evidence repin rejected")
	blobURLPattern = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/blob/([0-9a-f]{40})/(.+)$`)
	rawURLPattern  = regexp.MustCompile(`^https://raw\.githubusercontent\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/([0-9a-f]{40})/(.+)$`)
)

// parseCitationURL accepts the two immutable-blob URL shapes present in the
// shipped rule packs: the github.com/.../blob/... web form, and the
// raw.githubusercontent.com/.../... form sourcecapture itself fetches from.
// It never accepts a mutable ref (branch/tag name) in place of a commit.
func parseCitationURL(rawURL string) (owner, repo, commit, path string, ok bool) {
	if match := blobURLPattern.FindStringSubmatch(rawURL); match != nil {
		return match[1], match[2], match[3], match[4], true
	}
	if match := rawURLPattern.FindStringSubmatch(rawURL); match != nil {
		return match[1], match[2], match[3], match[4], true
	}
	return "", "", "", "", false
}

// Citation is one immutable evidence source cited by exactly one rule
// source entry in an existing rule pack.
type Citation struct {
	RulePack  string
	RuleID    string
	Project   string
	SourceID  string
	Owner     string
	Repo      string
	Path      string
	OldCommit string
	OldDigest string
	StartLine int
	EndLine   int
}

func (c Citation) repoKey() string { return c.Owner + "/" + c.Repo }
func (c Citation) key() string     { return c.RulePack + "\x00" + c.RuleID + "\x00" + c.SourceID }

// LoadCitations reads one rule pack (the shape shared by cncfcheck's and
// projectcheck's data/rules.json) and returns every cited source as a
// Citation. It never mutates the input and never opens a write path to a
// rule pack.
func LoadCitations(rulePackPath string, raw []byte) ([]Citation, error) {
	var document struct {
		Entries []struct {
			Project string `json:"project"`
			Rule    struct {
				ID       string `json:"id"`
				Evidence struct {
					Sources []struct {
						ID            string `json:"id"`
						URL           string `json:"url"`
						Revision      string `json:"revision"`
						ContentDigest string `json:"contentDigest"`
						StartLine     int    `json:"startLine"`
						EndLine       int    `json:"endLine"`
					} `json:"sources"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", errRejected, rulePackPath, err)
	}
	var out []Citation
	for _, entry := range document.Entries {
		for _, source := range entry.Rule.Evidence.Sources {
			owner, repo, commit, path, ok := parseCitationURL(source.URL)
			if !ok {
				return nil, fmt.Errorf("%w: unresolvable citation url shape in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			if commit != source.Revision {
				return nil, fmt.Errorf("%w: citation url commit does not match revision in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			if source.StartLine < 1 || source.EndLine < source.StartLine {
				return nil, fmt.Errorf("%w: invalid span in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			out = append(out, Citation{
				RulePack:  rulePackPath,
				RuleID:    entry.Rule.ID,
				Project:   entry.Project,
				SourceID:  source.ID,
				Owner:     owner,
				Repo:      repo,
				Path:      path,
				OldCommit: source.Revision,
				OldDigest: source.ContentDigest,
				StartLine: source.StartLine,
				EndLine:   source.EndLine,
			})
		}
	}
	return out, nil
}

// APIFetcher performs a bounded, unauthenticated-or-token-bearing GET
// against a fixed api.github.com path. It never follows redirects, never
// contacts another host, and never logs the token.
type APIFetcher interface {
	Fetch(ctx context.Context, path string) (body []byte, status int, err error)
}

// GitHubAPIFetcher is the production APIFetcher. It reads an optional
// bearer token supplied by the caller (never read from disk, never logged,
// never written anywhere) to raise GitHub's unauthenticated 60/hour limit
// to 5000/hour when present.
type GitHubAPIFetcher struct {
	// Token is an optional GitHub token. Empty means unauthenticated.
	Token string
}

func (f GitHubAPIFetcher) Fetch(ctx context.Context, path string) ([]byte, int, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "#\\") {
		return nil, 0, errRejected
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return nil, 0, errRejected
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "prufyx-evidence-repin/1")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.Token != "" {
		request.Header.Set("Authorization", "Bearer "+f.Token)
	}
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
			MaxResponseHeaderBytes: 16 << 10,
			TLSClientConfig:        &tls.Config{ServerName: "api.github.com", MinVersion: tls.VersionTLS12},
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: transport: %v", errRejected, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil || int64(len(data)) > maxAPIBytes {
		return nil, 0, errRejected
	}
	return data, response.StatusCode, nil
}

// RepoResolution records the outcome of resolving one repository's current
// release commit.
type RepoResolution struct {
	Owner         string `json:"owner"`
	Repo          string `json:"repo"`
	Status        string `json:"status"`
	CurrentTag    string `json:"currentTag,omitempty"`
	CurrentCommit string `json:"currentCommit,omitempty"`
	Detail        string `json:"detail,omitempty"`
	ResolvedAt    string `json:"resolvedAt,omitempty"`
}

var errRateLimited = errors.New("github api rate limited")

// ResolveCurrentCommit finds an owner/repo's most recent published release
// (falling back to its most recent tag when the project publishes no
// GitHub Releases) and resolves that tag to a commit SHA. It makes at most
// three api.github.com requests and never guesses or searches beyond the
// single most-recent release or tag.
func ResolveCurrentCommit(ctx context.Context, fetcher APIFetcher, owner, repo string) (tag, commit string, err error) {
	tag, err = latestReleaseTag(ctx, fetcher, owner, repo)
	if err != nil {
		return "", "", err
	}
	if tag == "" {
		tag, err = latestTag(ctx, fetcher, owner, repo)
		if err != nil {
			return "", "", err
		}
	}
	if tag == "" {
		return "", "", nil
	}
	commit, err = resolveTagCommit(ctx, fetcher, owner, repo, tag)
	if err != nil {
		return "", "", err
	}
	return tag, commit, nil
}

func apiGet(ctx context.Context, fetcher APIFetcher, path string) ([]byte, error) {
	body, status, err := fetcher.Fetch(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	if status == 403 || status == 429 {
		return nil, errRateLimited
	}
	if status == 404 {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%w: api.github.com returned status %d", errRejected, status)
	}
	return body, nil
}

// releaseListPageSize is fetched in a single request so the first
// non-draft, non-prerelease entry can be picked without extra round trips
// in the common case; GitHub returns releases ordered by creation date
// descending.
const releaseListPageSize = "10"

func latestReleaseTag(ctx context.Context, fetcher APIFetcher, owner, repo string) (string, error) {
	body, err := apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/releases?per_page="+releaseListPageSize)
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var releases []struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", nil
	}
	// "Current release" means the latest published, non-prerelease
	// version: a release candidate is not what an operator upgrades to,
	// so it should not stand in as the staleness baseline.
	for _, release := range releases {
		if !release.Draft && !release.Prerelease {
			return release.TagName, nil
		}
	}
	return "", nil
}

func latestTag(ctx context.Context, fetcher APIFetcher, owner, repo string) (string, error) {
	body, err := apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/tags?per_page=1")
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &tags); err != nil || len(tags) == 0 {
		return "", nil
	}
	return tags[0].Name, nil
}

func resolveTagCommit(ctx context.Context, fetcher APIFetcher, owner, repo, tag string) (string, error) {
	body, err := apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/git/ref/tags/"+url.PathEscape(tag))
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &ref); err != nil || !commitPattern.MatchString(ref.Object.SHA) {
		return "", nil
	}
	if ref.Object.Type == "commit" {
		return ref.Object.SHA, nil
	}
	if ref.Object.Type != "tag" {
		return "", nil
	}
	// Annotated tag: peel one level to the commit it points at.
	body, err = apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/git/tags/"+ref.Object.SHA)
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var annotated struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &annotated); err != nil || annotated.Object.Type != "commit" || !commitPattern.MatchString(annotated.Object.SHA) {
		return "", nil
	}
	return annotated.Object.SHA, nil
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ClassResult is one citation's drift classification.
type ClassResult struct {
	RulePack  string `json:"rulePack"`
	RuleID    string `json:"ruleId"`
	Project   string `json:"project"`
	SourceID  string `json:"sourceId"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
	Path      string `json:"path"`
	OldCommit string `json:"oldCommit"`
	NewCommit string `json:"newCommit,omitempty"`
	OldStart  int    `json:"oldStartLine"`
	OldEnd    int    `json:"oldEndLine"`
	NewStart  int    `json:"newStartLine,omitempty"`
	NewEnd    int    `json:"newEndLine,omitempty"`
	Class     string `json:"class"`
	Detail    string `json:"detail,omitempty"`
}

// costRank orders the worklist cheapest-reviewer-cost first, per section
// 6.2/8 of the design doc: batch-attestable first, full re-review last.
// PENDING sorts last of all because it is not yet actionable.
func costRank(class string) int {
	switch class {
	case ClassNoNewRelease:
		return 0
	case ClassSpanIdentical:
		return 1
	case ClassSpanMoved:
		return 2
	case ClassContentChanged:
		return 3
	case ClassPathGone:
		return 4
	default:
		return 5
	}
}

// spanDigestAt computes the digest of lines [start,end] (1-indexed,
// inclusive) of data using the exact same LF-split/join-with-LF/no-trailing
// convention as maintainer/sourcecorpus, by calling sourcecorpus.SHA for
// the actual hash. It never reimplements SHA-256.
func spanDigestAt(lines [][]byte, start, end int) (string, bool) {
	if start < 1 || end < start || end > len(lines) {
		return "", false
	}
	selected := bytes.Join(lines[start-1:end], []byte{'\n'})
	return sourcecorpus.SHA(selected), true
}

// classifySpan re-resolves one citation's span against the new file bytes.
// It first checks the original line range with maintainer/sourcecorpus's
// own verifier (real reuse of the digest convention for the identical
// case), then, on mismatch, searches for the identical byte span at a
// different line range before concluding the content changed.
func classifySpan(oldDigest string, oldStart, oldEnd int, newData []byte) (class string, newStart, newEnd int) {
	spanCount := oldEnd - oldStart + 1
	spans := []any{map[string]any{"startLine": int64(oldStart), "endLine": int64(oldEnd), "spanDigest": oldDigest}}
	if _, _, err := sourcecorpus.VerifySpans(spans, newData); err == nil {
		return ClassSpanIdentical, oldStart, oldEnd
	}
	lines := bytes.Split(newData, []byte{'\n'})
	if spanCount > len(lines) {
		return ClassContentChanged, 0, 0
	}
	for start := 1; start+spanCount-1 <= len(lines); start++ {
		end := start + spanCount - 1
		digest, ok := spanDigestAt(lines, start, end)
		if !ok {
			continue
		}
		if digest == oldDigest {
			return ClassSpanMoved, start, end
		}
	}
	return ClassContentChanged, 0, 0
}

// Classify resolves one citation against its project's current release
// commit and blob fetcher, returning its drift classification. current is
// the repo's resolved current release commit (possibly equal to the
// citation's own OldCommit, in which case no fetch is needed).
func Classify(ctx context.Context, citation Citation, currentCommit string, blobFetcher sourcecapture.Fetcher) ClassResult {
	result := ClassResult{
		RulePack: citation.RulePack, RuleID: citation.RuleID, Project: citation.Project, SourceID: citation.SourceID,
		Owner: citation.Owner, Repo: citation.Repo, Path: citation.Path,
		OldCommit: citation.OldCommit, OldStart: citation.StartLine, OldEnd: citation.EndLine,
	}
	if currentCommit == "" {
		result.Class = ClassPending
		result.Detail = "current release commit not yet resolved"
		return result
	}
	result.NewCommit = currentCommit
	if currentCommit == citation.OldCommit {
		result.Class = ClassNoNewRelease
		return result
	}
	rawPath := "/" + citation.Owner + "/" + citation.Repo + "/" + currentCommit + "/" + citation.Path
	fetch := blobFetcher.Fetch(ctx, rawPath)
	switch fetch.Kind {
	case "HTTP_200":
		class, newStart, newEnd := classifySpan(citation.OldDigest, citation.StartLine, citation.EndLine, fetch.Body)
		result.Class = class
		if class == ClassSpanMoved {
			result.NewStart, result.NewEnd = newStart, newEnd
		}
	case "HTTP_STATUS":
		if fetch.StatusCode == 404 {
			result.Class = ClassPathGone
			result.Detail = "path not found at current release commit"
		} else {
			result.Class = ClassPending
			result.Detail = "blob fetch returned status " + strconv.Itoa(fetch.StatusCode)
		}
	default:
		result.Class = ClassPending
		result.Detail = "blob fetch " + fetch.Kind
	}
	return result
}

// State is the resumable progress file. Re-running the command with the
// same --state path skips repositories and citations already resolved and
// retries only what is still PENDING, so a corpus-wide pass can proceed
// across several rate-limit windows instead of needing one unbroken run.
type State struct {
	Schema  string                    `json:"schema"`
	Repos   map[string]RepoResolution `json:"repos"`
	Results map[string]ClassResult    `json:"results"`
}

func newState() *State {
	return &State{Schema: StateSchema, Repos: map[string]RepoResolution{}, Results: map[string]ClassResult{}}
}

// LoadState reads a state file, or returns a fresh empty state if path is
// empty or the file does not yet exist.
func LoadState(path string) (*State, error) {
	if path == "" {
		return newState(), nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read state: %v", errRejected, err)
	}
	if int64(len(raw)) > maxStateBytes {
		return nil, fmt.Errorf("%w: state file too large", errRejected)
	}
	state := newState()
	if err := json.Unmarshal(raw, state); err != nil || state.Schema != StateSchema {
		return nil, fmt.Errorf("%w: decode state: %v", errRejected, err)
	}
	if state.Repos == nil {
		state.Repos = map[string]RepoResolution{}
	}
	if state.Results == nil {
		state.Results = map[string]ClassResult{}
	}
	return state, nil
}

// SaveState writes the state file. It is a no-op when path is empty.
func SaveState(path string, state *State) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode state: %v", errRejected, err)
	}
	return os.WriteFile(path, raw, 0o600)
}

// Summary is the classification distribution over resolved citations,
// which is the falsification test named in section 9.6 of the design doc:
// batch re-attestation is viable only if at least half of classified
// citations are SPAN_IDENTICAL.
type Summary struct {
	TotalCitations int            `json:"totalCitations"`
	Classified     int            `json:"classified"`
	Pending        int            `json:"pending"`
	Distribution   map[string]int `json:"distribution"`
	// BatchAttestableFraction is (SPAN_IDENTICAL+NO_NEW_RELEASE)/Classified.
	BatchAttestableFraction float64 `json:"batchAttestableFraction"`
	FalsificationMet        bool    `json:"falsificationConditionMet"`
}

func summarize(results []ClassResult) Summary {
	summary := Summary{Distribution: map[string]int{}}
	summary.TotalCitations = len(results)
	for _, result := range results {
		summary.Distribution[result.Class]++
		if result.Class != ClassPending {
			summary.Classified++
		} else {
			summary.Pending++
		}
	}
	if summary.Classified > 0 {
		batchable := summary.Distribution[ClassSpanIdentical] + summary.Distribution[ClassNoNewRelease]
		summary.BatchAttestableFraction = float64(batchable) / float64(summary.Classified)
		// The design doc's falsification condition is phrased over
		// SPAN_IDENTICAL alone ("under half classify SPAN_IDENTICAL");
		// NO_NEW_RELEASE is also explicitly batch-attestable in the
		// section 6.2 table, so both figures are reported (see Worklist).
		spanIdenticalFraction := float64(summary.Distribution[ClassSpanIdentical]) / float64(summary.Classified)
		summary.FalsificationMet = spanIdenticalFraction < 0.5
	}
	return summary
}

// RuleVerdict rolls citation classifications up to the rule they belong
// to, per section 6.2: a rule is batch re-attestable only if every one of
// its citations is SPAN_IDENTICAL or NO_NEW_RELEASE.
type RuleVerdict struct {
	RulePack        string `json:"rulePack"`
	RuleID          string `json:"ruleId"`
	Project         string `json:"project"`
	CitationCount   int    `json:"citationCount"`
	BatchEligible   bool   `json:"batchEligible"`
	WorstClass      string `json:"worstClass"`
	PendingCitation bool   `json:"pendingCitation"`
}

func ruleVerdicts(results []ClassResult) []RuleVerdict {
	order := []string{}
	byRule := map[string]*RuleVerdict{}
	for _, result := range results {
		key := result.RulePack + "\x00" + result.RuleID
		verdict, exists := byRule[key]
		if !exists {
			verdict = &RuleVerdict{RulePack: result.RulePack, RuleID: result.RuleID, Project: result.Project, BatchEligible: true}
			byRule[key] = verdict
			order = append(order, key)
		}
		verdict.CitationCount++
		if result.Class == ClassPending {
			verdict.PendingCitation = true
			verdict.BatchEligible = false
		} else if result.Class != ClassSpanIdentical && result.Class != ClassNoNewRelease {
			verdict.BatchEligible = false
		}
		if costRank(result.Class) > costRank(verdict.WorstClass) || verdict.WorstClass == "" {
			verdict.WorstClass = result.Class
		}
	}
	out := make([]RuleVerdict, 0, len(order))
	for _, key := range order {
		out = append(out, *byRule[key])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// Worklist is the full command output.
type Worklist struct {
	Schema      string           `json:"schema"`
	Authority   string           `json:"authority"`
	GeneratedAt string           `json:"generatedAt"`
	Scope       WorklistScope    `json:"scope"`
	Repos       []RepoResolution `json:"repos"`
	Citations   []ClassResult    `json:"citations"`
	Rules       []RuleVerdict    `json:"rules"`
	Summary     Summary          `json:"summary"`
	Limitations []string         `json:"limitations"`
}

// WorklistScope records what subset of the corpus this run covered.
type WorklistScope struct {
	RulePacks []string `json:"rulePacks"`
	Projects  []string `json:"projects,omitempty"`
	Limit     int      `json:"limit,omitempty"`
}

var worklistLimitations = []string{
	"this worklist is a mechanical drift classification, not a compatibility claim, a review, or a rule change",
	"it reads existing rule packs and writes only this worklist and an optional state file; it cannot modify a pack or a rule",
	"a repository's \"current release commit\" is its single most recent non-draft GitHub Release, or its single most recent tag when the project publishes no Releases; this is a proxy for \"upstream now\", not a guarantee of the true latest stable line",
	"SPAN_MOVED and CONTENT_CHANGED still require a human reviewer to confirm correspondence; this tool only narrows where reviewer time goes",
}

// BuildWorklist filters citations by project/limit, resolves each unique
// repository's current commit (consulting and updating state), classifies
// every citation whose repository resolved, and returns the worklist plus
// the updated state. It stops issuing further api.github.com requests as
// soon as one is rate-limited, so the run degrades to partial, resumable
// results instead of failing outright.
func BuildWorklist(ctx context.Context, citations []Citation, projects []string, limit int, state *State, apiFetcher APIFetcher, blobFetcher sourcecapture.Fetcher, now func() time.Time, progress io.Writer) (Worklist, error) {
	filtered := filterCitations(citations, projects, limit)

	repoSet := map[string]struct{ owner, repo string }{}
	repoOrder := []string{}
	for _, citation := range filtered {
		key := citation.repoKey()
		if _, exists := repoSet[key]; !exists {
			repoSet[key] = struct{ owner, repo string }{citation.Owner, citation.Repo}
			repoOrder = append(repoOrder, key)
		}
	}
	sort.Strings(repoOrder)

	rateLimited := false
	for _, key := range repoOrder {
		if existing, ok := state.Repos[key]; ok && existing.Status == repoResolved {
			continue
		}
		if rateLimited {
			continue
		}
		target := repoSet[key]
		tag, commit, err := ResolveCurrentCommit(ctx, apiFetcher, target.owner, target.repo)
		resolution := RepoResolution{Owner: target.owner, Repo: target.repo, ResolvedAt: now().UTC().Format(time.RFC3339)}
		switch {
		case errors.Is(err, errRateLimited):
			resolution.Status = repoPendingRateLimited
			resolution.Detail = "github api rate limit reached; re-run with the same --state to resume"
			rateLimited = true
		case err != nil:
			resolution.Status = repoPendingError
			resolution.Detail = "resolution attempt failed; re-run with the same --state to retry"
		case commit == "":
			resolution.Status = repoNoReleasesOrTags
			resolution.Detail = "no GitHub Releases or tags found"
		default:
			resolution.Status = repoResolved
			resolution.CurrentTag = tag
			resolution.CurrentCommit = commit
		}
		state.Repos[key] = resolution
		if progress != nil {
			fmt.Fprintf(progress, "evidence repin: resolved %s/%s -> %s (%s)\n", target.owner, target.repo, resolution.CurrentCommit, resolution.Status)
		}
	}

	results := make([]ClassResult, 0, len(filtered))
	for _, citation := range filtered {
		citationKey := citation.key()
		if existing, ok := state.Results[citationKey]; ok && existing.Class != ClassPending {
			results = append(results, existing)
			continue
		}
		resolution := state.Repos[citation.repoKey()]
		var result ClassResult
		if resolution.Status == repoResolved {
			result = Classify(ctx, citation, resolution.CurrentCommit, blobFetcher)
		} else {
			result = ClassResult{
				RulePack: citation.RulePack, RuleID: citation.RuleID, Project: citation.Project, SourceID: citation.SourceID,
				Owner: citation.Owner, Repo: citation.Repo, Path: citation.Path,
				OldCommit: citation.OldCommit, OldStart: citation.StartLine, OldEnd: citation.EndLine,
				Class: ClassPending, Detail: "repository current commit unresolved: " + resolution.Status,
			}
		}
		state.Results[citationKey] = result
		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if costRank(results[i].Class) != costRank(results[j].Class) {
			return costRank(results[i].Class) < costRank(results[j].Class)
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].SourceID < results[j].SourceID
	})

	repos := make([]RepoResolution, 0, len(repoOrder))
	for _, key := range repoOrder {
		repos = append(repos, state.Repos[key])
	}
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].Owner != repos[j].Owner {
			return repos[i].Owner < repos[j].Owner
		}
		return repos[i].Repo < repos[j].Repo
	})

	rulePackSet := map[string]struct{}{}
	for _, citation := range filtered {
		rulePackSet[citation.RulePack] = struct{}{}
	}
	rulePacks := make([]string, 0, len(rulePackSet))
	for pack := range rulePackSet {
		rulePacks = append(rulePacks, pack)
	}
	sort.Strings(rulePacks)

	worklist := Worklist{
		Schema: Schema, Authority: Authority, GeneratedAt: now().UTC().Format(time.RFC3339),
		Scope:       WorklistScope{RulePacks: rulePacks, Projects: projects, Limit: limit},
		Repos:       repos,
		Citations:   results,
		Rules:       ruleVerdicts(results),
		Summary:     summarize(results),
		Limitations: worklistLimitations,
	}
	return worklist, nil
}

func filterCitations(citations []Citation, projects []string, limit int) []Citation {
	sorted := append([]Citation(nil), citations...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].SourceID < sorted[j].SourceID
	})
	if len(projects) == 0 {
		if limit > 0 && limit < len(sorted) {
			return sorted[:limit]
		}
		return sorted
	}
	allow := map[string]struct{}{}
	for _, project := range projects {
		allow[project] = struct{}{}
	}
	filtered := make([]Citation, 0, len(sorted))
	for _, citation := range sorted {
		if _, ok := allow[citation.Project]; ok {
			filtered = append(filtered, citation)
		}
	}
	if limit > 0 && limit < len(filtered) {
		return filtered[:limit]
	}
	return filtered
}

type stringList []string

func (list *stringList) String() string { return strings.Join(*list, ",") }
func (list *stringList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

// Run is the "evidence repin" CLI adapter, wired from prufyx-maintainer's
// "evidence" command.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, apiFetcher APIFetcher, blobFetcher sourcecapture.Fetcher, now func() time.Time, defaultRulePacks []string) int {
	if len(args) == 0 || args[0] != "repin" {
		fmt.Fprintln(stderr, "evidence: unknown or missing subcommand (expected: repin)")
		return 2
	}
	flags := flag.NewFlagSet("evidence repin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var rulePacks stringList
	var projects stringList
	limit := flags.Int("limit", 0, "cap the number of citations considered (0 = no cap)")
	statePath := flags.String("state", "", "resumable progress file (optional)")
	outputPath := flags.String("output", "", "new worklist output path")
	flags.Var(&rulePacks, "rules", "rule pack path (repeatable; default: the shipped CNCF and community packs)")
	flags.Var(&projects, "project", "restrict to this project slug (repeatable; default: all)")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *outputPath == "" {
		fmt.Fprintln(stderr, "evidence repin: command rejected")
		return 2
	}
	if len(rulePacks) == 0 {
		rulePacks = append(stringList(nil), defaultRulePacks...)
	}

	var citations []Citation
	for _, path := range rulePacks {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: cannot read rule pack %s: %v\n", path, err)
			return 2
		}
		if int64(len(raw)) > maxRulesBytes {
			fmt.Fprintf(stderr, "evidence repin: rule pack %s too large\n", path)
			return 2
		}
		parsed, err := LoadCitations(path, raw)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
		citations = append(citations, parsed...)
	}

	state, err := LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(stderr, "evidence repin: %v\n", err)
		return 2
	}

	worklist, err := BuildWorklist(ctx, citations, projects, *limit, state, apiFetcher, blobFetcher, now, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "evidence repin: %v\n", err)
		return 2
	}

	if err := SaveState(*statePath, state); err != nil {
		fmt.Fprintf(stderr, "evidence repin: %v\n", err)
		return 2
	}

	raw, err := json.MarshalIndent(worklist, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "evidence repin: %v\n", err)
		return 2
	}
	if err := os.WriteFile(*outputPath, raw, 0o644); err != nil {
		fmt.Fprintf(stderr, "evidence repin: cannot write worklist: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "evidence repin: %d citations, %d classified, %d pending, %d rules, batch-attestable fraction %.2f\n",
		worklist.Summary.TotalCitations, worklist.Summary.Classified, worklist.Summary.Pending, len(worklist.Rules), worklist.Summary.BatchAttestableFraction)
	return 0
}
