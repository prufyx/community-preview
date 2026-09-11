package cncfprepare

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	KubeflowKFPComponent = "pkg:pypi/kfp"
	KubeflowKFPFact      = "component.kubeflow.kfp_component_authoring_api"
	KubeflowKFPFrom      = "1.8.22"
	KubeflowKFPTo        = "2.0.0"

	KubeflowKFPLegacyAPI = "legacy_create_component_from_func"
	KubeflowKFPV2API     = "dsl_component"

	kubeflowKFPProtocol = "prufyx-kubeflow-kfp-ast/v1"
)

const (
	ReasonKubeflowKFPAuthoringAPIObserved    Reason = "KUBEFLOW_KFP_COMPONENT_AUTHORING_API_OBSERVED"
	ReasonKubeflowKFPAuthoringAPIUnsupported Reason = "KUBEFLOW_KFP_COMPONENT_AUTHORING_API_UNSUPPORTED"
)

var (
	ErrKubeflowKFPInterpreter = errors.New("selected Kubeflow KFP CPython interpreter is unavailable or unsupported")
	ErrKubeflowKFPSourceParse = errors.New("selected Kubeflow KFP CPython interpreter could not parse the source")
	ErrKubeflowKFPProtocol    = errors.New("Kubeflow KFP AST helper protocol failure")
)

// KubeflowKFPPrepared retains one closed enum observation and a bounded
// unsupported category. It never retains source text, paths, function names,
// imports, decorator values, or URLs.
type KubeflowKFPPrepared struct {
	Prepared
	InterpreterVersion  string
	UnsupportedCategory string
}

type kubeflowKFPASTResult struct {
	Protocol       string `json:"protocol"`
	Implementation string `json:"implementation"`
	Version        string `json:"version"`
	State          string `json:"state"`
	Category       string `json:"category"`
	AuthoringAPI   string `json:"authoringApi"`
}

// PrepareKubeflowKFP inspects one caller-supplied Python file as data with a
// fixed isolated AST helper. The observation is independent of the declared
// versions; the selected knowledge rule owns exact transition applicability.
func PrepareKubeflowKFP(raw []byte, from, to, interpreter string) (KubeflowKFPPrepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return KubeflowKFPPrepared{}, ErrInvalid
	}
	stdout, err := runFixedPythonAST(raw, interpreter, kubeflowKFPASTHelper)
	if err != nil {
		return KubeflowKFPPrepared{}, ErrKubeflowKFPInterpreter
	}
	var observed kubeflowKFPASTResult
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observed) != nil || decoder.Decode(&struct{}{}) != io.EOF || observed.Protocol != kubeflowKFPProtocol || observed.Implementation != "CPython" || (observed.Version != "3.12" && observed.Version != "3.14") {
		return KubeflowKFPPrepared{}, ErrKubeflowKFPProtocol
	}
	if observed.State == "error" && observed.Category == "syntax_error" && observed.AuthoringAPI == "" {
		return KubeflowKFPPrepared{}, ErrKubeflowKFPSourceParse
	}
	if observed.State == "error" && observed.Category == "unsupported_runtime" && observed.AuthoringAPI == "" {
		return KubeflowKFPPrepared{}, ErrKubeflowKFPInterpreter
	}

	fact := inputFact{ID: KubeflowKFPFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonKubeflowKFPAuthoringAPIUnsupported
	switch observed.State {
	case "declared":
		if observed.Category != "" || (observed.AuthoringAPI != KubeflowKFPLegacyAPI && observed.AuthoringAPI != KubeflowKFPV2API) {
			return KubeflowKFPPrepared{}, ErrKubeflowKFPProtocol
		}
		fact = inputFact{ID: KubeflowKFPFact, State: "declared", EnumValue: observed.AuthoringAPI}
		state, reason = StatePrepared, ReasonKubeflowKFPAuthoringAPIObserved
	case "unsupported":
		if !validKubeflowKFPUnsupportedCategory(observed.Category) || observed.AuthoringAPI != "" {
			return KubeflowKFPPrepared{}, ErrKubeflowKFPProtocol
		}
	default:
		return KubeflowKFPPrepared{}, ErrKubeflowKFPProtocol
	}
	canonical, err := marshalComponentInput(KubeflowKFPComponent, from, to, []inputFact{fact})
	if err != nil {
		return KubeflowKFPPrepared{}, ErrInvalid
	}
	return KubeflowKFPPrepared{Prepared: Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"SELECTED_CPYTHON_EXECUTABLE_NOT_AUTHENTICATED",
			"INSTALLED_KFP_PACKAGE_AND_PROCESS_PROVENANCE_NOT_ESTABLISHED",
			"COMPONENT_INPUT_OUTPUT_DEPENDENCY_COMPILATION_BACKEND_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, InterpreterVersion: observed.Version, UnsupportedCategory: observed.Category}, nil
}

func validKubeflowKFPUnsupportedCategory(value string) bool {
	switch value {
	case "binding_missing", "binding_ambiguous", "binding_rebound", "binding_dynamic_use",
		"candidate_definition_count", "decorator_shape_unsupported", "definition_shape_unsupported":
		return true
	default:
		return false
	}
}

const kubeflowKFPASTHelper = `
import ast
import json
import platform
import sys

PROTOCOL = "prufyx-kubeflow-kfp-ast/v1"
SUPPORTED = {(3, 12), (3, 14)}

def emit(state, category="", api=""):
    print(json.dumps({
        "protocol": PROTOCOL,
        "implementation": platform.python_implementation(),
        "version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "state": state,
        "category": category,
        "authoringApi": api,
    }, sort_keys=True, separators=(",", ":")))

if platform.python_implementation() != "CPython" or sys.version_info[:2] not in SUPPORTED:
    emit("error", "unsupported_runtime")
    raise SystemExit(0)

try:
    source = sys.stdin.buffer.read().decode("utf-8")
    tree = ast.parse(source, filename="<supplied-source>", mode="exec")
except (UnicodeDecodeError, SyntaxError, ValueError, MemoryError):
    emit("error", "syntax_error")
    raise SystemExit(0)

allowed_import = None
binding = None
form = None
for statement in tree.body:
    if isinstance(statement, ast.ImportFrom) and statement.level == 0 and len(statement.names) == 1:
        item = statement.names[0]
        if statement.module == "kfp.components" and item.name == "create_component_from_func" and item.asname is None:
            if allowed_import is not None:
                emit("unsupported", "binding_ambiguous")
                raise SystemExit(0)
            allowed_import, binding, form = statement, "create_component_from_func", "legacy"
        if statement.module == "kfp" and item.name == "dsl" and item.asname is None:
            if allowed_import is not None:
                emit("unsupported", "binding_ambiguous")
                raise SystemExit(0)
            allowed_import, binding, form = statement, "dsl", "modern"

if allowed_import is None:
    emit("unsupported", "binding_missing")
    raise SystemExit(0)

def imported_name(alias):
    if alias.asname:
        return alias.asname
    return alias.name.split(".", 1)[0]

for node in ast.walk(tree):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if node is allowed_import:
            continue
        if any(imported_name(item) == binding or item.name == "*" or item.name.startswith("kfp") for item in node.names):
            emit("unsupported", "binding_ambiguous")
            raise SystemExit(0)
    if isinstance(node, ast.Name) and node.id == binding and isinstance(node.ctx, (ast.Store, ast.Del)):
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if isinstance(node, ast.arg) and node.arg == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if isinstance(node, ast.ExceptHandler) and node.name == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if isinstance(node, (ast.Global, ast.Nonlocal)) and binding in node.names:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if hasattr(ast, "MatchAs") and isinstance(node, ast.MatchAs) and node.name == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if hasattr(ast, "MatchStar") and isinstance(node, ast.MatchStar) and node.name == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if hasattr(ast, "MatchMapping") and isinstance(node, ast.MatchMapping) and node.rest == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)
    if type(node).__name__ in {"TypeVar", "ParamSpec", "TypeVarTuple"} and getattr(node, "name", None) == binding:
        emit("unsupported", "binding_rebound")
        raise SystemExit(0)

def candidate_decorator(node):
    if form == "legacy":
        return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == binding
    return (
        isinstance(node, ast.Attribute) and node.attr == "component"
        and isinstance(node.value, ast.Name) and isinstance(node.value.ctx, ast.Load)
        and node.value.id == binding
    )

candidates = []
for node in tree.body:
    if isinstance(node, ast.AsyncFunctionDef):
        if any(candidate_decorator(item) for item in node.decorator_list):
            emit("unsupported", "definition_shape_unsupported")
            raise SystemExit(0)
    if isinstance(node, ast.FunctionDef):
        for decorator in node.decorator_list:
            if candidate_decorator(decorator):
                candidates.append((node, decorator))

if len(candidates) != 1:
    emit("unsupported", "candidate_definition_count")
    raise SystemExit(0)
function, decorator = candidates[0]
if len(function.decorator_list) != 1:
    emit("unsupported", "decorator_shape_unsupported")
    raise SystemExit(0)

allowed_loads = {id(decorator)} if form == "legacy" else {id(decorator.value)}
for node in ast.walk(tree):
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == binding and id(node) not in allowed_loads:
        emit("unsupported", "binding_dynamic_use")
        raise SystemExit(0)

emit("declared", api="legacy_create_component_from_func" if form == "legacy" else "dsl_component")
`
