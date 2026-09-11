package projectprepare

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPrepareGrafanaNativeINI(t *testing.T) {
	for _, tc := range []struct {
		name, raw, state string
		value            *bool
		resolved         bool
	}{
		{"blocked", "[server]\nroot_url = https://private.invalid\n[alerting]\nenabled = true\n", "PREPARED", boolPointer(true), true},
		{"fixed", "[unified_alerting]\nenabled = true\n", "PREPARED", boolPointer(false), true},
		{"unresolved", "[alerting]\nenabled = true\n", "UNKNOWN", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEffectiveConfig(GrafanaProject, []byte(tc.raw), GrafanaFrom, GrafanaTo, true, tc.resolved)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, GrafanaFact, tc.value)
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private.invalid")) {
				t.Fatal("unrelated config leaked")
			}
		})
	}
	if _, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled=true\n[alerting]\nenabled=false\n"), GrafanaFrom, GrafanaTo, true, true); err == nil {
		t.Fatal("duplicate relevant section accepted")
	}
	for _, raw := range []string{"[Alerting]\nenabled=true\n", "[alerting]\nEnabled=true\n"} {
		prepared, err := PrepareEffectiveConfig(GrafanaProject, []byte(raw), GrafanaFrom, GrafanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous case state=%q err=%v", prepared.State, err)
		}
	}
	blank, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled=\n"), GrafanaFrom, GrafanaTo, true, true)
	if err != nil || blank.State != "UNKNOWN" {
		t.Fatalf("blank value state=%q err=%v", blank.State, err)
	}
	if _, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled true\n"), GrafanaFrom, GrafanaTo, true, true); err == nil {
		t.Fatal("malformed relevant INI accepted")
	}
}

func TestPrepareKibanaNativeYAMLAndJSON(t *testing.T) {
	inputs := []string{
		"server.host: 0.0.0.0\nxpack.reporting.roles.allow: [reporting_user]\n",
		"xpack.reporting.roles.allow: {reporting_user: true}\n",
		"xpack:\n  reporting:\n    roles:\n      allow:\n        - reporting_user\n",
		`{"server":{"name":"private-canary"},"xpack":{"reporting":{"roles":{"allow":["reporting_user"]}}}}`,
	}
	for index, raw := range inputs {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "PREPARED" {
			t.Fatalf("case %d state=%q err=%v", index, prepared.State, err)
		}
		assertCanonicalFact(t, prepared.CanonicalInputJSON, KibanaFact, boolPointer(true))
		if bytes.Contains(prepared.CanonicalInputJSON, []byte("private-canary")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("reporting_user")) {
			t.Fatal("raw config leaked")
		}
	}
	fixed, err := PrepareEffectiveConfig(KibanaProject, []byte("server.host: localhost\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonicalFact(t, fixed.CanonicalInputJSON, KibanaFact, boolPointer(false))
	unsupported, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack: &defaults\n  reporting: *defaults\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil || unsupported.State != "UNKNOWN" {
		t.Fatalf("unsupported YAML state=%q err=%v", unsupported.State, err)
	}
	assertCanonicalFact(t, unsupported.CanonicalInputJSON, KibanaFact, nil)
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack.reporting.roles.allow":[],"xpack.reporting.roles.allow":[]}`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack.reporting.roles.allow":[],"xpack":{"reporting":{"roles":{"allow":[]}}}}`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("conflicting dotted and nested JSON accepted")
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack.reporting.roles.allow: []\nxpack:\n  reporting:\n    roles:\n      allow: []\n"), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("conflicting dotted and nested YAML accepted")
	}
	insideArray, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack:\n  reporting:\n    - roles:\n        allow: []\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil || insideArray.State != "UNKNOWN" {
		t.Fatalf("relevant array state=%q err=%v", insideArray.State, err)
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack":`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	for _, raw := range []string{
		"xpack: []\n",
		"xpack:\n  Reporting:\n    roles:\n      allow: []\n",
		`{"xpack":null}`,
		`{"xpack":{"Reporting":{"roles":{"allow":[]}}}}`,
		`{"XPACK.REPORTING.ROLES.ALLOW":[]}`,
		`{"xpack.reporting":{"roles":{"allow":[]}}}`,
		`{"xpack":{"reporting.roles":{"allow":[]}}}`,
		`{"xpack":{"reporting":{"roles.allow":[]}}}`,
		`{"xpack.reporting.roles.allow.child":true}`,
		`{"xpack":{"reporting":{"roles":{"allow.child":true}}}}`,
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous relevant shape %q state=%q err=%v", raw, prepared.State, err)
		}
	}
	for _, raw := range []string{
		"xpack.reporting.roles.allow.child: true\n",
		"xpack:\n  reporting:\n    roles:\n      allow.child: true\n",
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("dotted descendant %q state=%q err=%v", raw, prepared.State, err)
		}
	}
	for _, raw := range []string{
		"defaults: &defaults\n  xpack.reporting.roles.allow: []\nconfig:\n  <<: *defaults\n",
		"defaults: &defaults\n  safe: true\nxpack:\n  reporting:\n    roles:\n      allow: *defaults\n",
		"defaults: !custom value\nserver.host: localhost\n",
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("YAML indirection %q state=%q err=%v", raw, prepared.State, err)
		}
	}
}

func TestPrepareRejectsIdentityAndShapeErrors(t *testing.T) {
	for _, tc := range []struct {
		project, from, to string
		raw               []byte
	}{
		{"unknown", GrafanaFrom, GrafanaTo, []byte("[server]\n")},
		{GrafanaProject, "10.4", GrafanaTo, []byte("[server]\n")},
		{GrafanaProject, GrafanaFrom, GrafanaFrom, []byte("[server]\n")},
		{GrafanaProject, GrafanaFrom, GrafanaTo, []byte("[alerting\nenabled=true\n")},
	} {
		if _, err := PrepareEffectiveConfig(tc.project, tc.raw, tc.from, tc.to, true, true); err == nil {
			t.Fatalf("accepted %#v", tc)
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func assertCanonicalFact(t *testing.T, raw []byte, id string, want *bool) {
	t.Helper()
	var doc struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fact := doc.Proposed.Components[0].Facts[0]
	if fact.ID != id {
		t.Fatalf("fact id %q", fact.ID)
	}
	if want == nil {
		if fact.State != "unsupported" || fact.BoolValue != nil {
			t.Fatalf("unsupported fact=%+v", fact)
		}
		return
	}
	if fact.State != "declared" || fact.BoolValue == nil || *fact.BoolValue != *want {
		t.Fatalf("fact=%+v want=%v", fact, *want)
	}
}
