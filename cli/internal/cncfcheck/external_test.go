package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type externalFixtureDocument struct {
	Schema                 string   `json:"schema"`
	Revision               string   `json:"revision"`
	Purpose                string   `json:"purpose"`
	EngineCapabilityDigest string   `json:"engineCapabilityDigest"`
	Pack                   rulePack `json:"pack"`
}

func externalFixture(t *testing.T, entries []Entry) []byte {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	capability, err := ExternalCapabilityDigest()
	if err != nil {
		t.Fatal(err)
	}
	pack := base.pack
	pack.Revision = "1"
	pack.Entries = entries
	raw, err := json.Marshal(externalFixtureDocument{Schema: externalBundleSchema, Revision: "1", Purpose: "operator_provided", EngineCapabilityDigest: capability, Pack: pack})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func kyvernoEntry(t *testing.T) Entry {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range base.pack.Entries {
		if entry.Project == "kyverno" {
			return entry
		}
	}
	t.Fatal("kyverno entry missing")
	return Entry{}
}

func kyvernoInput(t *testing.T, want string) []byte {
	t.Helper()
	for _, vector := range reviewedVectors(t) {
		if vector.Project != "kyverno" {
			continue
		}
		for _, scenario := range vector.Cases {
			if scenario.Name == want {
				return scenario.Input
			}
		}
	}
	t.Fatalf("kyverno vector %q missing", want)
	return nil
}

func externalReviewClock() time.Time {
	return time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC)
}

func TestParseExternalBundleEmptyAndAdmissionBinding(t *testing.T) {
	requirements, err := ExternalProfileRequirements()
	if err != nil || requirements.Schema != externalBundleSchema || requirements.PackSchema == "" || requirements.EngineCapabilityDigest == "" || requirements.PolicyID == "" || requirements.PolicyDigest == "" || requirements.RegistryDigest == "" || requirements.LandscapeFileDigest == "" {
		t.Fatalf("invalid scalar profile requirements: %+v err=%v", requirements, err)
	}
	raw := externalFixture(t, []Entry{})
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if admission.Revision != "1" || admission.Purpose != "operator_provided" || admission.HasRule || admission.RuleDigest != "" || admission.EvidenceExpiresAt != "" {
		t.Fatalf("unexpected empty admission: %+v", admission)
	}
	if got, want := bundle.BundleDigest(), digest(raw); got != want {
		t.Fatalf("bundle digest=%s want %s", got, want)
	}
}

func TestParseExternalBundleRuleAdmissionAndExternalAuthority(t *testing.T) {
	raw := externalFixture(t, []Entry{kyvernoEntry(t)})
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil || !admission.HasRule || admission.RuleDigest == "" || admission.EvidenceExpiresAt == "" || admission.EngineCapabilityDigest == "" {
		t.Fatalf("invalid rule admission=%+v err=%v", admission, err)
	}
	report, err := bundle.Evaluate("kyverno", kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil {
		t.Fatal(err)
	}
	if report.KnowledgeOrigin != "external_declared" || report.SourceAuthority != externalSourceAuthority || report.KnowledgeRevision != "1" || report.KnowledgePackDigest != digest(raw) || report.NetworkUsed || report.RuntimeReproduced != 0 || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" {
		t.Fatalf("external authority/result lost: %+v", report)
	}
	if report.Check.RulesAuthority != externalSourceAuthority {
		t.Fatalf("rules authority=%q", report.Check.RulesAuthority)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestExternalBundleDoesNotFallbackToEmbeddedRules(t *testing.T) {
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := bundle.Evaluate("kyverno", kyvernoInput(t, "blocked"), externalReviewClock())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 0 || report.Assessment != "UNKNOWN" {
		t.Fatalf("empty external bundle fell back to embedded rules: %+v", report.Check.Claims)
	}
}

func TestExternalBundleRejectsMalformedClosedShapes(t *testing.T) {
	valid := externalFixture(t, []Entry{})
	tests := [][]byte{
		bytes.Replace(valid, []byte(`"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1"`), []byte(`"Schema":"prufyx.io/operator-cncf-knowledge/v1alpha1"`), 1),
		bytes.Replace(valid, []byte(`"pack":{`), []byte(`"authority":"operator" ,"pack":{`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":null`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[null]`), 1),
		bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":{}`), 1),
		append([]byte(`{"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1","revision":"1","purpose":"operator_provided","engineCapabilityDigest":"`), []byte(strings.Repeat("a", 64)+`","pack":{}}`)...),
	}
	for i, raw := range tests {
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Errorf("malformed external shape %d admitted", i)
		}
	}
	duplicate := bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[],"Entries":[]`), 1)
	if _, err := ParseExternalBundle(duplicate); err == nil {
		t.Fatal("case alias admitted")
	}
	duplicate = bytes.Replace(valid, []byte(`"entries":[]`), []byte(`"entries":[],"entries":[]`), 1)
	if _, err := ParseExternalBundle(duplicate); err == nil {
		t.Fatal("duplicate member admitted")
	}
	oversize := append([]byte(`{"schema":"prufyx.io/operator-cncf-knowledge/v1alpha1","revision":"1","purpose":"operator_provided","engineCapabilityDigest":"`), []byte(strings.Repeat("a", 64)+`","pack":{"schema":"x","revision":"1","policyId":"x","policyDigest":"x","landscapeFileDigest":"x","registryDigest":"x","entries":[],"padding":"`+strings.Repeat("x", maxExternalBundleBytes)+`"}}`)...)
	if _, err := ParseExternalBundle(oversize); err == nil {
		t.Fatal("oversize bundle admitted")
	}
}

func TestExternalBundleRejectsIdentityAndRegistryMismatches(t *testing.T) {
	valid := externalFixture(t, []Entry{})
	mutations := [][]byte{
		bytes.Replace(valid, []byte(`"revision":"1"`), []byte(`"revision":"0"`), 1),
		bytes.Replace(valid, []byte(`"purpose":"operator_provided"`), []byte(`"purpose":"unknown"`), 1),
		bytes.Replace(valid, []byte(`"engineCapabilityDigest":"`), []byte(`"engineCapabilityDigest":"`+strings.Repeat("0", 64)), 1),
		bytes.Replace(valid, []byte(`"registryDigest":"`), []byte(`"registryDigest":"sha256:`+strings.Repeat("0", 64)+`"`), 1),
		bytes.Replace(valid, []byte(`"policyId":"cncf-source-preview-v1"`), []byte(`"policyId":"other"`), 1),
	}
	for i, raw := range mutations {
		if _, err := ParseExternalBundle(raw); err == nil {
			t.Errorf("identity mutation %d admitted", i)
		}
	}
}

func TestExternalBundleSealRejectsMutation(t *testing.T) {
	bundle, err := ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	bundle.raw[0] ^= 1
	if _, err := bundle.Admission(); err == nil || bundle.BundleDigest() != "" {
		t.Fatal("raw mutation retained capability")
	}
	bundle, err = ParseExternalBundle(externalFixture(t, []Entry{}))
	if err != nil {
		t.Fatal(err)
	}
	bundle.admission.Revision = "2"
	if _, err := bundle.Admission(); err == nil {
		t.Fatal("admission mutation retained capability")
	}
}

func TestExternalBundleEvidenceStatesRemainScoped(t *testing.T) {
	entry := kyvernoEntry(t)
	for _, test := range []struct {
		name     string
		replace  []byte
		with     []byte
		expected string
	}{
		{"withdrawn", []byte(`"state": "active"`), []byte(`"state": "withdrawn"`), "UNKNOWN"},
		{"expired", []byte(`"validUntil": "2026-12-07T12:07:56Z"`), []byte(`"validUntil": "2026-09-08T12:09:59Z"`), "UNKNOWN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry.Rule = bytes.Replace(entry.Rule, test.replace, test.with, 1)
			bundle, err := ParseExternalBundle(externalFixture(t, []Entry{entry}))
			if err != nil {
				t.Fatal(err)
			}
			report, err := bundle.Evaluate("kyverno", kyvernoInput(t, "blocked"), externalReviewClock())
			if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != test.expected {
				t.Fatalf("evidence state=%+v err=%v", report.Check.Claims, err)
			}
		})
	}
}
