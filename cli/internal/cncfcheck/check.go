package cncfcheck

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx-cli/internal/constraintengine"
)

type Report struct {
	Schema              string                  `json:"schema"`
	Project             string                  `json:"project"`
	Assessment          string                  `json:"assessment"`
	KnowledgeOrigin     string                  `json:"knowledgeOrigin"`
	KnowledgeRevision   string                  `json:"knowledgeRevision"`
	KnowledgePackDigest string                  `json:"knowledgePackDigest"`
	CatalogueDigest     string                  `json:"catalogueDigest"`
	InputFileDigest     string                  `json:"inputFileDigest"`
	SourceAuthority     string                  `json:"sourceAuthority"`
	RuntimeReproduced   int                     `json:"runtimeReproduced"`
	NetworkUsed         bool                    `json:"networkUsed"`
	NextAction          string                  `json:"nextAction"`
	Check               constraintengine.Report `json:"check"`
	seal                *reportSeal
	digest              string
}
type reportSeal struct{}

// Check uses only the selected project's embedded rules. Local input is parsed
// against the compiled registry; there is no external rule input or fallback.
func Check(project string, inputRaw []byte, now time.Time) (Report, error) {
	b, err := load()
	if err != nil {
		return Report{}, err
	}
	return b.check(project, inputRaw, now)
}

func (b bundle) check(project string, inputRaw []byte, now time.Time) (Report, error) {
	if !b.hasProject(project) {
		return Report{}, ErrInvalid
	}
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		return Report{}, ErrInvalid
	}
	rules, err := b.rulesForAdmittedInput(project, inputRaw)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	result, err := constraintengine.Evaluate(input, rules, now)
	if err != nil {
		return Report{}, ErrInvalid
	}
	if _, err := constraintengine.MarshalReport(result); err != nil {
		return Report{}, ErrIntegrity
	}
	report := Report{
		Schema: "prufyx.io/cncf-source-check/v1alpha1", Project: project, Assessment: "UNKNOWN",
		KnowledgeOrigin: "embedded", KnowledgeRevision: b.pack.Revision, KnowledgePackDigest: b.packDigest,
		CatalogueDigest: b.catalogueDigest, InputFileDigest: digest(inputRaw),
		SourceAuthority: "PACKAGED_MAINTAINER_REVIEWED_SOURCE_RULES_NOT_RUNTIME_PROOF",
		NextAction:      "review each scoped claim; whole-upgrade behavior and runtime evidence remain unverified",
		Check:           result,
	}
	if len(result.Claims) == 0 {
		report.NextAction = "no generic rules are packaged for this project; inspect its existing named checks in the catalogue or contribute an exact transition with primary source evidence"
	}
	report.seal = &reportSeal{}
	raw, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrIntegrity
	}
	report.digest = digest(raw)
	return report, nil
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil || report.Assessment != "UNKNOWN" || report.NetworkUsed || report.RuntimeReproduced != 0 {
		return nil, ErrIntegrity
	}
	if _, err := constraintengine.MarshalReport(report.Check); err != nil {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(report)
	if err != nil || digest(raw) != report.digest {
		return nil, ErrIntegrity
	}
	return raw, nil
}

// Replay checks exact local bytes at the explicitly supplied original clock.
// It does not claim continuing source freshness, non-revocation or a signature.
func Replay(project string, inputRaw []byte, now time.Time, expected []byte) (Report, error) {
	if len(expected) == 0 || len(expected) > 4<<20 {
		return Report{}, ErrInvalid
	}
	report, err := Check(project, inputRaw, now)
	if err != nil {
		return Report{}, err
	}
	raw, err := MarshalReport(report)
	if err != nil || !bytes.Equal(append(raw, '\n'), expected) {
		return Report{}, ErrIntegrity
	}
	return report, nil
}

// ClaimExit concerns only the selected nonempty set of source constraints.
func ClaimExit(report Report) int {
	if _, err := MarshalReport(report); err != nil {
		return 3
	}
	if len(report.Check.Claims) == 0 {
		return 11
	}
	unknown := false
	for _, claim := range report.Check.Claims {
		if claim.Status == "BLOCKED" {
			return 10
		}
		if claim.Status != "PASS" {
			unknown = true
		}
	}
	if unknown {
		return 11
	}
	return 0
}
