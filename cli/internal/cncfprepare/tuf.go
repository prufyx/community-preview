package cncfprepare

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	TUFComponent     = "pkg:github/theupdateframework/python-tuf"
	TUFBootstrapFact = "component.tuf.updater_bootstrap_keyword_present"
	TUFFrom          = "6.0.0"
	TUFTo            = "7.0.0"

	tufASTProtocol = "prufyx-tuf-updater-ast/v1"
)

const (
	ReasonTUFUpdaterCallObserved    Reason = "TUF_UPDATER_CALL_SHAPE_OBSERVED"
	ReasonTUFUpdaterCallUnsupported Reason = "TUF_UPDATER_CALL_SHAPE_UNSUPPORTED"
)

var (
	ErrTUFInterpreter = errors.New("selected TUF CPython interpreter is unavailable or unsupported")
	ErrTUFSourceParse = errors.New("selected TUF CPython interpreter could not parse the source")
	ErrTUFProtocol    = errors.New("TUF AST helper protocol failure")
)

// TUFPrepared retains only the minimized fact and a bounded presentation
// category. InterpreterVersion comes from the explicitly selected parser
// process; it is not an authentication claim about that executable.
type TUFPrepared struct {
	Prepared
	InterpreterVersion  string
	UnsupportedCategory string
}

type tufASTResult struct {
	Protocol                string `json:"protocol"`
	Implementation          string `json:"implementation"`
	Version                 string `json:"version"`
	State                   string `json:"state"`
	Category                string `json:"category"`
	BootstrapKeywordPresent *bool  `json:"bootstrapKeywordPresent"`
}

// PrepareTUFUpdater uses a fixed, isolated CPython AST helper to inspect a
// supplied source file as data. It never imports or executes the supplied
// source and never retains source text, call values, paths, or URLs.
func PrepareTUFUpdater(raw []byte, from, to, interpreter string) (TUFPrepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return TUFPrepared{}, ErrInvalid
	}
	stdout, err := runFixedPythonAST(raw, interpreter, tufASTHelper)
	if err != nil {
		return TUFPrepared{}, ErrTUFInterpreter
	}

	var observed tufASTResult
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observed) != nil || decoder.Decode(&struct{}{}) != io.EOF || observed.Protocol != tufASTProtocol || observed.Implementation != "CPython" || (observed.Version != "3.12" && observed.Version != "3.14") {
		return TUFPrepared{}, ErrTUFProtocol
	}
	if observed.State == "error" && observed.Category == "syntax_error" && observed.BootstrapKeywordPresent == nil {
		return TUFPrepared{}, ErrTUFSourceParse
	}
	if observed.State == "error" && observed.Category == "unsupported_runtime" && observed.BootstrapKeywordPresent == nil {
		return TUFPrepared{}, ErrTUFInterpreter
	}

	fact := inputFact{ID: TUFBootstrapFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonTUFUpdaterCallUnsupported
	switch observed.State {
	case "declared":
		if observed.Category != "" || observed.BootstrapKeywordPresent == nil {
			return TUFPrepared{}, ErrTUFProtocol
		}
		fact = inputFact{ID: TUFBootstrapFact, State: "declared", BoolValue: observed.BootstrapKeywordPresent}
		state, reason = StatePrepared, ReasonTUFUpdaterCallObserved
	case "unsupported":
		if !validTUFUnsupportedCategory(observed.Category) || observed.BootstrapKeywordPresent != nil {
			return TUFPrepared{}, ErrTUFProtocol
		}
	default:
		return TUFPrepared{}, ErrTUFProtocol
	}
	canonical, err := marshalComponentInput(TUFComponent, from, to, []inputFact{fact})
	if err != nil {
		return TUFPrepared{}, ErrInvalid
	}
	return TUFPrepared{Prepared: Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"SELECTED_CPYTHON_EXECUTABLE_NOT_AUTHENTICATED",
			"INSTALLED_TUF_PACKAGE_AND_PROCESS_PROVENANCE_NOT_ESTABLISHED",
			"BOOTSTRAP_VALUE_CACHE_TRUST_METADATA_UPDATE_AND_RUNTIME_NOT_EVALUATED",
			OmissionNoWholeUpgrade,
		},
	}, InterpreterVersion: observed.Version, UnsupportedCategory: observed.Category}, nil
}

func validTUFUnsupportedCategory(value string) bool {
	switch value {
	case "binding_missing", "binding_ambiguous", "binding_rebound", "binding_dynamic_use",
		"candidate_call_count", "star_arguments", "duplicate_argument", "unknown_keyword",
		"missing_required_argument", "positional_bootstrap", "call_shape_unsupported":
		return true
	default:
		return false
	}
}

const tufASTHelper = `
import ast
import json
import platform
import sys

PROTOCOL = "prufyx-tuf-updater-ast/v1"
SHARED = ["metadata_dir", "metadata_base_url", "target_dir", "target_base_url", "fetcher", "config"]
SUPPORTED = {(3, 12), (3, 14)}

def emit(state, category="", present=None):
    result = {
        "protocol": PROTOCOL,
        "implementation": platform.python_implementation(),
        "version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "state": state,
        "category": category,
        "bootstrapKeywordPresent": present,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))

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
    if isinstance(statement, ast.ImportFrom) and statement.module == "tuf.ngclient" and statement.level == 0 and len(statement.names) == 1:
        item = statement.names[0]
        if item.name == "Updater" and item.asname is None:
            if allowed_import is not None:
                emit("unsupported", "binding_ambiguous")
                raise SystemExit(0)
            allowed_import, binding, form = statement, "Updater", "from"
    if isinstance(statement, ast.Import) and len(statement.names) == 1:
        item = statement.names[0]
        if item.name == "tuf.ngclient" and item.asname is None:
            if allowed_import is not None:
                emit("unsupported", "binding_ambiguous")
                raise SystemExit(0)
            allowed_import, binding, form = statement, "tuf", "module"

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
        names = node.names
        if any(imported_name(item) == binding or item.name == "*" or item.name.startswith("tuf") for item in names):
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

def candidate_func(node):
    if form == "from":
        return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == "Updater"
    return (
        isinstance(node, ast.Attribute) and node.attr == "Updater"
        and isinstance(node.value, ast.Attribute) and node.value.attr == "ngclient"
        and isinstance(node.value.value, ast.Name) and isinstance(node.value.value.ctx, ast.Load)
        and node.value.value.id == "tuf"
    )

calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and candidate_func(node.func)]
if len(calls) != 1:
    emit("unsupported", "candidate_call_count")
    raise SystemExit(0)
call = calls[0]
allowed_loads = set()
if form == "from":
    allowed_loads.add(id(call.func))
else:
    allowed_loads.add(id(call.func.value.value))
for node in ast.walk(tree):
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == binding and id(node) not in allowed_loads:
        emit("unsupported", "binding_dynamic_use")
        raise SystemExit(0)

if any(isinstance(arg, ast.Starred) for arg in call.args) or any(keyword.arg is None for keyword in call.keywords):
    emit("unsupported", "star_arguments")
    raise SystemExit(0)
if len(call.args) > len(SHARED):
    emit("unsupported", "positional_bootstrap")
    raise SystemExit(0)

names = [keyword.arg for keyword in call.keywords]
if len(names) != len(set(names)):
    emit("unsupported", "duplicate_argument")
    raise SystemExit(0)
if any(name not in set(SHARED + ["bootstrap"]) for name in names):
    emit("unsupported", "unknown_keyword")
    raise SystemExit(0)
positional = set(SHARED[:len(call.args)])
if positional.intersection(names):
    emit("unsupported", "duplicate_argument")
    raise SystemExit(0)
bound = positional.union(name for name in names if name != "bootstrap")
if not {"metadata_dir", "metadata_base_url"}.issubset(bound):
    emit("unsupported", "missing_required_argument")
    raise SystemExit(0)

emit("declared", present=("bootstrap" in names))
`
