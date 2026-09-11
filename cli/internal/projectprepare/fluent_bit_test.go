package projectprepare

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPrepareFluentBitHTTP2Contract(t *testing.T) {
	base := "[OUTPUT]\n  Name opentelemetry\n  Host private.invalid\n"
	for _, tc := range []struct {
		name, raw                   string
		complete, current, preserve bool
		wantState, wantReason       string
		wantEnabled                 bool
	}{
		{"on", base + "  http2 on\n", true, true, true, "PREPARED", fluentBitPreparedReason, true},
		{"force", base + "  http2 force\n", true, true, true, "PREPARED", fluentBitPreparedReason, true},
		{"off", base + "  http2 off\n", true, true, true, "PREPARED", fluentBitPreparedReason, false},
		{"omitted", base, true, true, true, "PREPARED", fluentBitPreparedReason, false},
		{"missing-preservation-intent", base + "  http2 on\n", true, true, false, "UNKNOWN", fluentBitIncompleteReason, false},
		{"missing-current-default", base + "  http2 on\n", true, false, true, "UNKNOWN", fluentBitIncompleteReason, false},
		{"incomplete-proposed", base + "  http2 on\n", false, true, true, "UNKNOWN", fluentBitIncompleteReason, false},
		{"grpc-on", base + "  http2 on\n  grpc on\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"include", "@INCLUDE private.conf\n" + base, true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"wrong-case-key", "[OUTPUT]\n  name opentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"wrong-section", "[SERVICE]\n  Name opentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"indented-header", "  [OUTPUT]\n  Name opentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"unindented-property", "[OUTPUT]\nName opentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"tab-separator", "[OUTPUT]\n  Name\topentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"inconsistent-indentation", "[OUTPUT]\n  Name opentelemetry\n    http2 on\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
		{"unicode-separator", "[OUTPUT]\n  Name\u00a0opentelemetry\n", true, true, true, "UNKNOWN", fluentBitUnsupportedReason, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareFluentBit([]byte(tc.raw), FluentBitFrom, FluentBitTo, tc.complete, tc.current, tc.preserve)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != tc.wantState || prepared.Reason != tc.wantReason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			var doc struct {
				Proposed struct {
					Components []struct {
						Facts []struct {
							State     string `json:"state"`
							BoolValue *bool  `json:"boolValue"`
						} `json:"facts"`
					} `json:"components"`
				} `json:"proposed"`
			}
			if err := json.Unmarshal(prepared.CanonicalInputJSON, &doc); err != nil {
				t.Fatal(err)
			}
			fact := doc.Proposed.Components[0].Facts[0]
			if tc.wantState == "PREPARED" {
				if fact.State != "declared" || fact.BoolValue == nil || *fact.BoolValue != tc.wantEnabled {
					t.Fatalf("fact=%+v want=%v", fact, tc.wantEnabled)
				}
			} else if fact.State != "unsupported" || fact.BoolValue != nil {
				t.Fatalf("unknown fact=%+v", fact)
			}
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private.invalid")) {
				t.Fatal("raw config value leaked")
			}
		})
	}
}

func TestPrepareFluentBitDuplicateKeysRemainUnknown(t *testing.T) {
	for _, raw := range []string{
		"[OUTPUT]\n  Name opentelemetry\n  http2 on\n  http2 off\n",
		"[OUTPUT]\n  Name opentelemetry\n  Host first\n  Host second\n  http2 on\n",
	} {
		prepared, err := PrepareFluentBit([]byte(raw), FluentBitFrom, FluentBitTo, true, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if prepared.State != "UNKNOWN" || prepared.Reason != fluentBitUnsupportedReason {
			t.Fatalf("duplicate input state=%s reason=%s", prepared.State, prepared.Reason)
		}
	}
}
