package cncfprepare

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func kubeflowPreparedFact(t *testing.T, prepared KubeflowKFPPrepared) map[string]any {
	t.Helper()
	var input map[string]any
	if json.Unmarshal(prepared.CanonicalInputJSON, &input) != nil {
		t.Fatal("canonical input did not decode")
	}
	component := input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)
	return component["facts"].([]any)[0].(map[string]any)
}

func TestPrepareKubeflowKFPObservedFormsAndStableProjection(t *testing.T) {
	python := tufTestPython(t)
	tests := []struct{ name, source, value string }{
		{"legacy", "from kfp.components import create_component_from_func\n@create_component_from_func\ndef build_component():\n    return 'PRIVATE'\n", KubeflowKFPLegacyAPI},
		{"modern", "from kfp import dsl\n@dsl.component\ndef build_component():\n    return 'PRIVATE'\n", KubeflowKFPV2API},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeflowKFP([]byte(test.source), KubeflowKFPFrom, KubeflowKFPTo, python)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKubeflowKFPAuthoringAPIObserved || prepared.UnsupportedCategory != "" {
				t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
			}
			fact := kubeflowPreparedFact(t, prepared)
			if fact["id"] != KubeflowKFPFact || fact["state"] != "declared" || fact["enumValue"] != test.value {
				t.Fatalf("fact = %#v", fact)
			}
			variant := strings.Replace(test.source, "'PRIVATE'", "'OTHER'", 1)
			other, err := PrepareKubeflowKFP([]byte(variant), "1.8.21", "2.0.1", python)
			if err != nil || !strings.Contains(string(other.CanonicalInputJSON), test.value) || other.InputDigest == prepared.InputDigest || other.SourceDigest == prepared.SourceDigest {
				t.Fatalf("tuple/source projection = %#v, %v", other, err)
			}
			// With the same tuple, irrelevant source changes preserve the minimized input.
			other, err = PrepareKubeflowKFP([]byte(variant), KubeflowKFPFrom, KubeflowKFPTo, python)
			if err != nil || other.InputDigest != prepared.InputDigest || other.SourceDigest == prepared.SourceDigest {
				t.Fatalf("stable projection = %#v, %v", other, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "PRIVATE") || strings.Contains(string(prepared.CanonicalInputJSON), "build_component") {
				t.Fatal("private source leaked into canonical input")
			}
		})
	}
	legacy, _ := PrepareKubeflowKFP([]byte(tests[0].source), KubeflowKFPFrom, KubeflowKFPTo, python)
	modern, _ := PrepareKubeflowKFP([]byte(tests[1].source), KubeflowKFPFrom, KubeflowKFPTo, python)
	if legacy.InputDigest == modern.InputDigest {
		t.Fatal("legacy and modern observations must remain distinct")
	}
}

func TestPrepareKubeflowKFPUnsupportedShapes(t *testing.T) {
	python := tufTestPython(t)
	tests := []struct{ name, source, category string }{
		{"alias", "from kfp.components import create_component_from_func as make\n@make\ndef c(): pass\n", "binding_missing"},
		{"mixed", "from kfp.components import create_component_from_func\nfrom kfp import dsl\n@create_component_from_func\ndef c(): pass\n", "binding_ambiguous"},
		{"rebound", "from kfp import dsl\ndsl = other\n@dsl.component\ndef c(): pass\n", "binding_rebound"},
		{"dynamic", "from kfp import dsl\nprint(dsl)\n@dsl.component\ndef c(): pass\n", "binding_dynamic_use"},
		{"decorator-call", "from kfp import dsl\n@dsl.component()\ndef c(): pass\n", "candidate_definition_count"},
		{"multiple", "from kfp import dsl\n@dsl.component\ndef a(): pass\n@dsl.component\ndef b(): pass\n", "candidate_definition_count"},
		{"extra-decorator", "from kfp import dsl\n@other\n@dsl.component\ndef c(): pass\n", "decorator_shape_unsupported"},
		{"async", "from kfp import dsl\n@dsl.component\nasync def c(): pass\n", "definition_shape_unsupported"},
		{"direct-factory", "from kfp.components import create_component_from_func\ndef c(): pass\nx = create_component_from_func(c)\n", "candidate_definition_count"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeflowKFP([]byte(test.source), KubeflowKFPFrom, KubeflowKFPTo, python)
			if err != nil || prepared.State != StateUnknown || prepared.UnsupportedCategory != test.category || kubeflowPreparedFact(t, prepared)["state"] != "unsupported" {
				t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
			}
		})
	}
}

func TestPrepareKubeflowKFPDoesNotExecuteSourceAndSeparatesSetupErrors(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "must-not-exist")
	source := "from kfp import dsl\nopen(" + strconvQuote(canary) + ", 'w').write('executed')\n@dsl.component\ndef c(): pass\n"
	prepared, err := PrepareKubeflowKFP([]byte(source), KubeflowKFPFrom, KubeflowKFPTo, tufTestPython(t))
	if err != nil || prepared.State != StatePrepared {
		t.Fatalf("PrepareKubeflowKFP() = %#v, %v", prepared, err)
	}
	if _, err := os.Stat(canary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supplied source executed: %v", err)
	}
	if _, err := PrepareKubeflowKFP([]byte("from kfp import dsl\n@dsl.component\ndef c("), KubeflowKFPFrom, KubeflowKFPTo, tufTestPython(t)); !errors.Is(err, ErrKubeflowKFPSourceParse) {
		t.Fatalf("syntax error = %v", err)
	}
	if _, err := PrepareKubeflowKFP([]byte(source), KubeflowKFPFrom, KubeflowKFPTo, "python3"); !errors.Is(err, ErrKubeflowKFPInterpreter) {
		t.Fatalf("relative interpreter = %v", err)
	}
}
