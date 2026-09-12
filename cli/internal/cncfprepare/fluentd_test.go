package cncfprepare

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fluentdInput(current, proposed string, complete, defaultUsed, preserve bool) []byte {
	return []byte(`{"current":` + quoteJSON(current) + `,"proposed":` + quoteJSON(proposed) + `,"selectedValueComplete":` + boolText(complete) + `,"currentDefaultUsed":` + boolText(defaultUsed) + `,"preserveLiteralTreatment":` + boolText(preserve) + `}`)
}

func quoteJSON(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func fluentdInputEncoded(current, proposed string, complete, defaultUsed, preserve bool) []byte {
	value, err := json.Marshal(struct {
		Current               string `json:"current"`
		Proposed              string `json:"proposed"`
		SelectedValueComplete bool   `json:"selectedValueComplete"`
		CurrentDefaultUsed    bool   `json:"currentDefaultUsed"`
		PreserveLiteral       bool   `json:"preserveLiteralTreatment"`
	}{current, proposed, complete, defaultUsed, preserve})
	if err != nil {
		panic(err)
	}
	return value
}

func TestPrepareFluentDLiteralBoundaries(t *testing.T) {
	tests := []struct {
		name, current, proposed         string
		complete, defaultUsed, preserve bool
		state                           State
		reason                          Reason
	}{
		{"marker is blocked", `{` + "\"path\":\"#{record_tag}\"" + `}`, `{` + "\"path\":\"#{record_tag}\"" + `}`, true, true, true, StatePrepared, ReasonFluentDBlocked},
		{"no marker passes", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\":\"plain\"" + `}`, true, true, true, StatePrepared, ReasonFluentDPass},
		{"single quote wrapper passes", `{` + "\"path\":\"#{record_tag}\"" + `}`, `'` + "{\"path\":\"#{record_tag}\"}" + `'`, true, true, true, StatePrepared, ReasonFluentDPass},
		{"missing declaration unknown", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\":\"plain\"" + `}`, false, true, true, StateUnknown, ReasonFluentDIncomplete},
		{"missing default declaration unknown", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\":\"plain\"" + `}`, true, false, true, StateUnknown, ReasonFluentDIncomplete},
		{"missing preservation declaration unknown", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\":\"plain\"" + `}`, true, true, false, StateUnknown, ReasonFluentDIncomplete},
		{"changed bytes unknown", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\": \"plain\"" + `}`, true, true, true, StateUnknown, ReasonFluentDUnsupported},
		{"multiple markers unknown", `{` + "\"a\":\"#{one}\",\"b\":\"#{two}\"" + `}`, `{` + "\"a\":\"#{one}\",\"b\":\"#{two}\"" + `}`, true, true, true, StateUnknown, ReasonFluentDUnsupported},
		{"unsupported version pair unknown", `{` + "\"path\":\"plain\"" + `}`, `{` + "\"path\":\"plain\"" + `}`, true, true, true, StateUnknown, ReasonFluentDPair},
		{"marker in object key is blocked", `{"#{key}":"plain"}`, `{"#{key}":"plain"}`, true, true, true, StatePrepared, ReasonFluentDBlocked},
		{"marker in array is blocked", `{"paths":["#{path}"]}`, `{"paths":["#{path}"]}`, true, true, true, StatePrepared, ReasonFluentDBlocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			from, to := FluentDFrom, FluentDTo
			if test.reason == ReasonFluentDPair {
				from, to = "1.17.0", FluentDTo
			}
			prepared, err := PrepareFluentDLiteral(fluentdInput(test.current, test.proposed, test.complete, test.defaultUsed, test.preserve), from, to)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "record") {
				t.Fatal("raw literal retained")
			}
		})
	}
}

func TestPrepareFluentDLiteralRejectsExpansionAndReplacementRunes(t *testing.T) {
	for _, current := range []string{
		`{"path":"${PRIVATE_PLACEHOLDER}"}`,
		`{"path":"�"}`,
		`{"path":"\ufffd"}`,
		`{"path":"\ud800"}`,
	} {
		prepared, err := PrepareFluentDLiteral(fluentdInputEncoded(current, current, true, true, true), FluentDFrom, FluentDTo)
		if err != nil {
			t.Fatalf("current=%q prepare: %v", current, err)
		}
		if prepared.State != StateUnknown || prepared.Reason != ReasonFluentDUnsupported {
			t.Fatalf("current=%q state=%s reason=%s", current, prepared.State, prepared.Reason)
		}
		if strings.Contains(string(prepared.CanonicalInputJSON), "PRIVATE_PLACEHOLDER") {
			t.Fatal("private template marker retained")
		}
	}
	invalid := fluentdInputEncoded(`{"path":"plain"}`, `{"path":"plain"}`, true, true, true)
	if index := bytes.Index(invalid, []byte("plain")); index >= 0 {
		invalid[index] = 0xff
	} else {
		t.Fatal("test envelope did not contain selected value")
	}
	if _, err := PrepareFluentDLiteral(invalid, FluentDFrom, FluentDTo); err == nil {
		t.Fatal("accepted invalid UTF-8 inside outer declaration")
	}
	validOuterWithUnpairedEscape := []byte(`{"current":"{\"path\":\"\ud800\"}","proposed":"{\"path\":\"\ud800\"}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`)
	prepared, err := PrepareFluentDLiteral(validOuterWithUnpairedEscape, FluentDFrom, FluentDTo)
	if err != nil {
		t.Fatalf("outer JSON with unpaired escape should be valid: %v", err)
	}
	if prepared.State != StateUnknown || prepared.Reason != ReasonFluentDUnsupported {
		t.Fatalf("unpaired escape state=%s reason=%s", prepared.State, prepared.Reason)
	}
}

func TestPrepareFluentDLiteralRejectsRawNewlineInValidOuterEnvelope(t *testing.T) {
	prepared, err := PrepareFluentDLiteral(fluentdInputEncoded("{\"path\":\"line\nnext\"}", "{\"path\":\"line\nnext\"}", true, true, true), FluentDFrom, FluentDTo)
	if err != nil {
		t.Fatalf("outer JSON should be valid: %v", err)
	}
	if prepared.State != StateUnknown || prepared.Reason != ReasonFluentDUnsupported {
		t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
	}
}

func TestPrepareFluentDLiteralRejectsMissingAndWrongOuterShape(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"current":{},"proposed":"{}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`),
		[]byte(`{"current":"{}","proposed":"{}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true,"extra":false}`),
		[]byte(`{"current":"{}","current":"{}","proposed":"{}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`),
	} {
		if _, err := PrepareFluentDLiteral(raw, FluentDFrom, FluentDTo); err == nil {
			t.Fatalf("accepted malformed outer declaration %s", raw)
		}
	}
}

func TestPrepareFluentDLiteralRejectsMalformedSelectedJSON(t *testing.T) {
	for _, current := range []string{`{"a":1,"a":2}`, `{"a":"#{x"}`, "{\n\"a\":1}", `{"a":"#{x\\y}"}`, `{"a":"#{x}","b":"#{y"}`, `"scalar"`} {
		prepared, err := PrepareFluentDLiteral(fluentdInput(current, current, true, true, true), FluentDFrom, FluentDTo)
		if err == nil && prepared.State != StateUnknown {
			t.Fatalf("current=%q state=%s", current, prepared.State)
		}
	}
}
