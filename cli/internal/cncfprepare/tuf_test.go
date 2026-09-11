package cncfprepare

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func tufTestPython(t *testing.T) string {
	t.Helper()
	if selected := os.Getenv("PRUFYX_TEST_PYTHON"); selected != "" {
		if !filepath.IsAbs(selected) {
			t.Fatalf("PRUFYX_TEST_PYTHON must be absolute: %q", selected)
		}
		return selected
	}
	selected, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the TUF AST preparer test")
	}
	selected, err = filepath.Abs(selected)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func tufPreparedFact(t *testing.T, prepared TUFPrepared) map[string]any {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
		t.Fatal(err)
	}
	proposed := input["proposed"].(map[string]any)
	component := proposed["components"].([]any)[0].(map[string]any)
	return component["facts"].([]any)[0].(map[string]any)
}

func TestPrepareTUFUpdaterObservedCallShapes(t *testing.T) {
	python := tufTestPython(t)
	tests := []struct {
		name    string
		source  string
		present bool
	}{
		{"from-import-omitted", "from tuf.ngclient import Updater\nclient = Updater('/metadata', 'https://metadata.invalid/')\n", false},
		{"module-import-present", "import tuf.ngclient\nclient = tuf.ngclient.Updater(metadata_dir='/metadata', metadata_base_url='https://metadata.invalid/', bootstrap=root_bytes)\n", true},
		{"none-is-explicit-presence", "from tuf.ngclient import Updater\nclient = Updater(metadata_dir='/metadata', metadata_base_url='https://metadata.invalid/', bootstrap=None)\n", true},
		{"six-shared-positional", "from tuf.ngclient import Updater\nclient = Updater(a, b, c, d, e, f)\n", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTUFUpdater([]byte(test.source), TUFFrom, TUFTo, python)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonTUFUpdaterCallObserved || prepared.UnsupportedCategory != "" {
				t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
			}
			fact := tufPreparedFact(t, prepared)
			if fact["id"] != TUFBootstrapFact || fact["state"] != "declared" || fact["boolValue"] != test.present {
				t.Fatalf("fact = %#v", fact)
			}
			if prepared.SourceDigest != digestBytes([]byte(test.source)) || prepared.InputDigest != digestBytes(prepared.CanonicalInputJSON) || strings.Contains(string(prepared.CanonicalInputJSON), "metadata.invalid") || strings.Contains(string(prepared.CanonicalInputJSON), "root_bytes") {
				t.Fatalf("source or digest boundary failed: %#v", prepared)
			}
		})
	}
}

func TestPrepareTUFUpdaterObservationIndependentOfTuple(t *testing.T) {
	prepared, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\n"), "6.0.1", "7.0.1", tufTestPython(t))
	if err != nil || prepared.State != StatePrepared || tufPreparedFact(t, prepared)["boolValue"] != false {
		t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
	}
}

func TestPrepareTUFUpdaterUnsupportedCategories(t *testing.T) {
	python := tufTestPython(t)
	tests := []struct{ name, source, category string }{
		{"alias", "from tuf.ngclient import Updater as U\nU('/m', 'https://x.invalid/')\n", "binding_missing"},
		{"competing-imports", "from tuf.ngclient import Updater\nimport tuf.ngclient\nUpdater('/m', 'https://x.invalid/')\n", "binding_ambiguous"},
		{"rebound", "from tuf.ngclient import Updater\nUpdater = factory\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"except-handler-rebound", "from tuf.ngclient import Updater\ntry:\n    pass\nexcept Exception as Updater:\n    Updater('/m', 'https://x.invalid/', bootstrap=None)\n", "binding_rebound"},
		{"match-as-rebound", "from tuf.ngclient import Updater\nmatch payload:\n    case Updater:\n        pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"match-star-rebound", "from tuf.ngclient import Updater\nmatch payload:\n    case [*Updater]:\n        pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"match-rest-rebound", "from tuf.ngclient import Updater\nmatch payload:\n    case {**Updater}:\n        pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"type-parameter-shadow", "from tuf.ngclient import Updater\ndef scope[Updater]():\n    pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"type-var-tuple-shadow", "from tuf.ngclient import Updater\ndef scope[*Updater]():\n    pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"param-spec-shadow", "from tuf.ngclient import Updater\ndef scope[**Updater]():\n    pass\nUpdater('/m', 'https://x.invalid/')\n", "binding_rebound"},
		{"dynamic-reference", "from tuf.ngclient import Updater\nfactory = Updater\nfactory('/m', 'https://x.invalid/')\n", "candidate_call_count"},
		{"multiple-calls", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\nUpdater('/n', 'https://y.invalid/')\n", "candidate_call_count"},
		{"star-args", "from tuf.ngclient import Updater\nUpdater(*args)\n", "star_arguments"},
		{"star-kwargs", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', **options)\n", "star_arguments"},
		{"duplicate-keyword", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m', metadata_dir='/n', metadata_base_url='https://x.invalid/')\n", "duplicate_argument"},
		{"duplicate-positional-keyword", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', metadata_dir='/n')\n", "duplicate_argument"},
		{"unknown-keyword", "from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/', future=True)\n", "unknown_keyword"},
		{"missing-required", "from tuf.ngclient import Updater\nUpdater(metadata_dir='/m')\n", "missing_required_argument"},
		{"v6-seventh-positional-bootstrap", "from tuf.ngclient import Updater\nUpdater(a, b, c, d, e, f, root_bytes)\n", "positional_bootstrap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareTUFUpdater([]byte(test.source), TUFFrom, TUFTo, python)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonTUFUpdaterCallUnsupported || prepared.UnsupportedCategory != test.category {
				t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
			}
			fact := tufPreparedFact(t, prepared)
			if fact["state"] != "unsupported" {
				t.Fatalf("fact = %#v", fact)
			}
			if _, exists := fact["boolValue"]; exists {
				t.Fatalf("unsupported fact contains boolValue: %#v", fact)
			}
		})
	}
}

func TestPrepareTUFUpdaterDoesNotExecuteSuppliedSource(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "must-not-exist")
	source := "from tuf.ngclient import Updater\nopen(" + strconvQuote(canary) + ", 'w').write('executed')\nUpdater('/m', 'https://x.invalid/')\n"
	prepared, err := PrepareTUFUpdater([]byte(source), TUFFrom, TUFTo, tufTestPython(t))
	if err != nil || prepared.State != StatePrepared {
		t.Fatalf("PrepareTUFUpdater() = %#v, %v", prepared, err)
	}
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supplied source executed: %v", err)
	}
}

func TestPrepareTUFUpdaterErrors(t *testing.T) {
	python := tufTestPython(t)
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater("), TUFFrom, TUFTo, python); !errors.Is(err, ErrTUFSourceParse) {
		t.Fatalf("syntax error = %v", err)
	}
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\n"), TUFFrom, TUFTo, "python3"); !errors.Is(err, ErrTUFInterpreter) {
		t.Fatalf("relative interpreter = %v", err)
	}
	fake := filepath.Join(t.TempDir(), "python")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf not-json\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareTUFUpdater([]byte("from tuf.ngclient import Updater\nUpdater('/m', 'https://x.invalid/')\n"), TUFFrom, TUFTo, fake); !errors.Is(err, ErrTUFProtocol) {
		t.Fatalf("bad protocol = %v", err)
	}
}

func strconvQuote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
