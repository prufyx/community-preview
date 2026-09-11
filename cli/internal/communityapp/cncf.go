package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"time"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
	"github.com/prufyx/prufyx-cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx-cli/internal/cncfprepare"
	"github.com/prufyx/prufyx-cli/internal/currentbundle"
	"github.com/prufyx/prufyx-cli/internal/knowledge"
)

func (r runtime) cncfCatalog(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx catalog cncf [--priority] [--project SLUG] [--format human|json]\nCatalogue identity, generic source-rule coverage and runtime reproduction are separate. This command reads embedded public metadata only.")
		return ExitOK
	}
	fs := flag.NewFlagSet("catalog cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	priority := fs.Bool("priority", false, "show the initial maintainer-selected portfolio")
	project := fs.String("project", "", "inspect a specific project and its rules")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || (*format != "human" && *format != "json") {
		return r.usage("invalid CNCF catalogue arguments; use --help")
	}
	catalogue, err := cncfcheck.Catalog(*priority, *project)
	if err != nil {
		return r.cncfError("CNCF catalogue could not be loaded", err)
	}
	if *format == "json" {
		if json.NewEncoder(r.stdout).Encode(catalogue) != nil {
			return ExitIntegrity
		}
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "CNCF catalogue: %d projects; initial priority: %d\ngeneric source-rule preview: %d projects; runtime transitions reproduced: %d\nlandscape revision: %s\npriority is maintainer selection, not an adoption ranking\n", catalogue.Catalogued, catalogue.PriorityProjects, catalogue.SourceRuleCovered, catalogue.RuntimeReproduced, catalogue.LandscapeRevision)
	for _, item := range catalogue.Projects {
		fmt.Fprintf(r.stdout, "%s: %s (%s); %d generic source rules\n", item.Slug, item.Name, item.CNCFStage, item.SourceRuleCount)
		for _, route := range item.ExistingChecks {
			fmt.Fprintf(r.stdout, "  existing named check: %s\n", route)
		}
		if *project != "" {
			for _, entry := range item.Checks {
				fmt.Fprintf(r.stdout, "  %s\n", entry.Description)
				for _, fact := range entry.RequiredFacts {
					fmt.Fprintf(r.stdout, "    %s: %s\n", fact.ID, fact.Description)
				}
			}
		}
	}
	return ExitOK
}

func (r runtime) cncf(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, `Usage: prufyx check cncf --project SLUG --input FILE (--now RFC3339 | --knowledge-db DIR) [--input-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project argo-cd --config-map FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] --now RFC3339 [--config-map-digest SHA256] [--format human|json]
   or: prufyx check cncf --project knative --service FILE --from VERSION --to VERSION (--now RFC3339 | --knowledge-db DIR) [--service-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project in-toto --in-toto-run-argv FILE --from 2.2.0 --to 3.0.0 (--now RFC3339 | --knowledge-db DIR) [--in-toto-run-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project the-update-framework-tuf --python-source FILE --python-ast-interpreter /absolute/path/to/python3 --from 6.0.0 --to 7.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project kubeflow --python-source FILE --python-ast-interpreter /absolute/path/to/python3 --from 1.8.22 --to 2.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cubefs --metanode-config FILE --from 3.2.1 --to 3.3.2 [--phase metanode-upgrade] (--now RFC3339 | --knowledge-db DIR) [--metanode-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cri-o --image-status-request FILE --artifact-operation named-reference-resolution --from 1.34.0 --to 1.35.0 (--now RFC3339 | --knowledge-db DIR) [--image-status-request-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project buildpacks --current-lifecycle-config FILE --proposed-lifecycle-config FILE --from 0.16.5 --to 0.17.7 --current-platform-api 0.11 --proposed-platform-api 0.12|0.13 (--now RFC3339 | --knowledge-db DIR) [--current-lifecycle-config-digest SHA256] [--proposed-lifecycle-config-digest SHA256] [--replay-report FILE] [--format human|json]

Optional, local source-constraint preview using minimized operator declarations.
Inspect inputs with: prufyx catalog cncf --project SLUG --format json
Input and replay files must be regular private files (0600), without symlinks.
Embedded rules use explicit canonical UTC with whole-second precision. Replay
compares the exact prior JSON at its original time, without current freshness.
Select a separate local signed CNCF store with --knowledge-db DIR. Current
external checks use the verifier's actual clock; omit --now. External replay
with --input FILE requires --replay-report FILE, --input-digest SHA256,
--knowledge-revision REV,
--knowledge-bundle-digest SHA256 and --knowledge-trust-receipt-digest SHA256;
its original time comes from the exact report. There is no embedded fallback.
No cluster, network, model, or database download is used by this command.
The Argo CD ConfigMap mode prepares and checks the local file in memory. It
does not write canonical input, infer RBAC intent, or edit the ConfigMap.
The Knative Serving Service mode derives only the target named HTTP startup-
probe port-match fact. Embedded knowledge reviews only 1.22.0 -> 1.23.0.
An explicit external store is authoritative and never falls back to embedded
rules. Unsupported shapes and version pairs without a selected rule stay
UNKNOWN; this does not edit the Service or validate other admission, startup,
traffic, or runtime behavior. External replay requires --service-digest and
all three knowledge pins. Its report binds minimized prepared input, so retain
the raw Service and its digest separately when raw-byte identity matters.
The Buildpacks mode reads two private Lifecycle config-shaped JSON files and compares
explicit CNB_PLATFORM_API selections with their declared lifecycle support.
Those labels and optional raw digests authenticate only supplied bytes, not
registry provenance. Embedded knowledge covers Lifecycle 0.16.5 -> 0.17.7;
external knowledge is authoritative with no embedded fallback. Historical
replay requires both raw config digests and all three knowledge pins.
The in-toto mode reads one private JSON argv array and inspects only a fixed
in-toto-run prefix before the first valid -- delimiter. Everything after it is
opaque. Embedded knowledge covers Python CLI 2.2.0 -> 3.0.0. A PASS clears
only removal of -k/--key; it does not load or convert keys or run the command.
Historical replay requires the raw argv digest and all three knowledge pins.
The TUF mode runs a fixed AST helper under the explicitly selected CPython
3.12 or 3.14 interpreter with -I -S and sends the private Python source over
stdin as data. The helper parses but never imports or executes supplied source.
The interpreter is caller-trusted, not authenticated; other CNCF modes do not
discover or require it. Embedded knowledge covers Updater 6.0.0 -> 7.0.0 and
checks only explicit bootstrap keyword presence in one admitted direct call.
Historical replay requires the raw source digest and all three knowledge pins.
The Kubeflow mode uses the same isolated AST boundary to recognize only one
unaliased bare create_component_from_func or dsl.component decorator.
Embedded knowledge covers KFP Python SDK 1.8.22 -> 2.0.0 and checks only the
removed authoring API. PASS does not validate component inputs, outputs,
dependencies, compilation, backend, installed package, or runtime behavior.
Historical replay requires the raw source digest and all three knowledge pins.
The CubeFS mode reads one caller-supplied planned MetaNode JSON config and a
caller-declared phase. It checks only the raftSyncSnapFormatVersion guard for
the exact 3.2.1 -> 3.3.2 metanode-upgrade phase. Missing or unsupported phase,
role, setting types, values, and version pairs stay UNKNOWN. PASS does not
verify peer versions, rollout completion, restarts, client ordering, mounts,
runtime behavior, or data safety. Historical replay requires the raw config
digest and all three knowledge pins.
The CRI-O mode reads one caller-supplied native CRI ImageStatusRequest JSON file
and a caller-declared ArtifactStore named-reference-resolution operation. It
classifies only a strict explicit-tag short or fully-qualified image.image for
exact CRI-O 1.34.0 -> 1.35.0. PASS clears only the target short-name guard;
registry aliases, store contents, request routing, access and runtime remain
UNKNOWN. Historical replay requires the raw request digest and all three
knowledge pins.
Exit 0: all selected nonempty claims PASS; 10: at least one claim BLOCKED;
11: UNKNOWN or no rules; 2: invalid input; 3: integrity failure.
Whole-upgrade compatibility remains UNKNOWN in every case.`)
		return ExitOK
	}
	fs := flag.NewFlagSet("check cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "catalogue project slug")
	input := fs.String("input", "", "minimized current and proposed declarations")
	pin := fs.String("input-digest", "", "optional exact input file SHA-256")
	configMap := fs.String("config-map", "", "private proposed Argo CD argocd-cm JSON")
	configMapPin := fs.String("config-map-digest", "", "optional exact ConfigMap SHA-256")
	service := fs.String("service", "", "private proposed Knative Serving Service JSON")
	servicePin := fs.String("service-digest", "", "optional exact Service SHA-256")
	currentLifecycleConfig := fs.String("current-lifecycle-config", "", "private current Lifecycle config-shaped JSON")
	proposedLifecycleConfig := fs.String("proposed-lifecycle-config", "", "private proposed Lifecycle config-shaped JSON")
	currentLifecyclePin := fs.String("current-lifecycle-config-digest", "", "optional exact current Lifecycle config SHA-256")
	proposedLifecyclePin := fs.String("proposed-lifecycle-config-digest", "", "optional exact proposed Lifecycle config SHA-256")
	currentPlatformAPI := fs.String("current-platform-api", "", "explicit current CNB_PLATFORM_API")
	proposedPlatformAPI := fs.String("proposed-platform-api", "", "explicit proposed CNB_PLATFORM_API")
	inTotoRunArgv := fs.String("in-toto-run-argv", "", "private planned in-toto-run JSON argv array")
	inTotoRunArgvPin := fs.String("in-toto-run-argv-digest", "", "optional exact argv file SHA-256")
	pythonSource := fs.String("python-source", "", "private Python source for a supported source-call check")
	pythonSourcePin := fs.String("python-source-digest", "", "optional exact Python source file SHA-256")
	pythonASTInterpreter := fs.String("python-ast-interpreter", "", "absolute caller-selected CPython 3.12 or 3.14 executable")
	metanodeConfig := fs.String("metanode-config", "", "private planned CubeFS MetaNode JSON config")
	metanodeConfigPin := fs.String("metanode-config-digest", "", "optional exact MetaNode config SHA-256")
	phase := fs.String("phase", "", "caller-declared upgrade phase")
	imageStatusRequest := fs.String("image-status-request", "", "private CRI ImageStatusRequest JSON")
	imageStatusRequestPin := fs.String("image-status-request-digest", "", "optional exact ImageStatusRequest SHA-256")
	artifactOperation := fs.String("artifact-operation", "", "caller-declared artifact operation")
	from := fs.String("from", "", "actual declared current component version")
	to := fs.String("to", "", "actual declared proposed component version")
	requiresInheritedPermissions := fs.String("requires-inherited-application-permissions", "", "explicit Argo CD v2 inheritance access intent: true or false")
	nowText := fs.String("now", "", "explicit UTC evaluation time")
	replay := fs.String("replay-report", "", "prior exact JSON output")
	knowledgeDB := fs.String("knowledge-db", "", "explicit separate signed CNCF store")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional exact selected revision")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional exact target digest")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional exact trust receipt digest")
	format := fs.String("format", "human", "human or json")
	digestRE := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *project == "" || (*format != "human" && *format != "json") || (flagProvided(args, "input-digest") && !digestRE.MatchString(*pin)) || (flagProvided(args, "config-map-digest") && !digestRE.MatchString(*configMapPin)) || (flagProvided(args, "service-digest") && !digestRE.MatchString(*servicePin)) || (flagProvided(args, "current-lifecycle-config-digest") && !digestRE.MatchString(*currentLifecyclePin)) || (flagProvided(args, "proposed-lifecycle-config-digest") && !digestRE.MatchString(*proposedLifecyclePin)) || (flagProvided(args, "in-toto-run-argv-digest") && !digestRE.MatchString(*inTotoRunArgvPin)) || (flagProvided(args, "python-source-digest") && !digestRE.MatchString(*pythonSourcePin)) || (flagProvided(args, "metanode-config-digest") && !digestRE.MatchString(*metanodeConfigPin)) || (flagProvided(args, "image-status-request-digest") && !digestRE.MatchString(*imageStatusRequestPin)) || (flagProvided(args, "replay-report") && *replay == "") {
		return r.usage("invalid CNCF check arguments; use --help")
	}
	rawArgoRequested := *project == "argo-cd" && anyFlagProvided(args, "config-map", "config-map-digest", "from", "to", "requires-inherited-application-permissions")
	rawKnativeRequested := *project == "knative" && anyFlagProvided(args, "service", "service-digest", "from", "to")
	rawBuildpacksRequested := *project == "buildpacks" && anyFlagProvided(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "from", "to")
	rawInTotoRequested := *project == "in-toto" && anyFlagProvided(args, "in-toto-run-argv", "in-toto-run-argv-digest", "from", "to")
	rawTUFRequested := *project == "the-update-framework-tuf" && anyFlagProvided(args, "python-source", "python-source-digest", "python-ast-interpreter", "from", "to")
	rawKubeflowRequested := *project == "kubeflow" && anyFlagProvided(args, "python-source", "python-source-digest", "python-ast-interpreter", "from", "to")
	rawCubeFSRequested := *project == "cubefs" && anyFlagProvided(args, "metanode-config", "metanode-config-digest", "phase", "from", "to")
	rawCRIORequested := *project == "cri-o" && anyFlagProvided(args, "image-status-request", "image-status-request-digest", "artifact-operation", "from", "to")
	for _, name := range []string{"knowledge-db", "knowledge-revision", "knowledge-bundle-digest", "knowledge-trust-receipt-digest"} {
		if flagProvided(args, name) && fs.Lookup(name).Value.String() == "" {
			return r.usage("invalid external CNCF knowledge selection; use --help")
		}
	}
	if rawArgoRequested {
		if *configMap == "" || flagProvided(args, "service") || flagProvided(args, "service-digest") || anyFlagProvided(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation") || *input != "" || flagProvided(args, "input") || flagProvided(args, "input-digest") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (flagProvided(args, "requires-inherited-application-permissions") && *requiresInheritedPermissions != "true" && *requiresInheritedPermissions != "false") {
			return r.usage("invalid Argo CD ConfigMap check arguments; use --help")
		}
	} else if rawKnativeRequested {
		if *service == "" || flagProvided(args, "config-map") || flagProvided(args, "config-map-digest") || anyFlagProvided(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation") || flagProvided(args, "requires-inherited-application-permissions") || *input != "" || flagProvided(args, "input") || flagProvided(args, "input-digest") || *from == "" || *to == "" || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Knative Serving Service check arguments; use --help")
		}
	} else if rawBuildpacksRequested {
		if *currentLifecycleConfig == "" || *proposedLifecycleConfig == "" || *currentPlatformAPI == "" || *proposedPlatformAPI == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Buildpacks Lifecycle check arguments; use --help")
		}
	} else if rawInTotoRequested {
		if *inTotoRunArgv == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid in-toto-run argv check arguments; use --help")
		}
	} else if rawTUFRequested {
		if *pythonSource == "" || *pythonASTInterpreter == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid TUF Updater Python source check arguments; use --help")
		}
	} else if rawKubeflowRequested {
		if *pythonSource == "" || *pythonASTInterpreter == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid KFP Python source check arguments; use --help")
		}
	} else if rawCubeFSRequested {
		if *metanodeConfig == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "image-status-request", "image-status-request-digest", "artifact-operation", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CubeFS MetaNode config check arguments; use --help")
		}
	} else if rawCRIORequested {
		if *imageStatusRequest == "" || *from == "" || *to == "" || anyFlagProvided(args, "input", "input-digest", "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "requires-inherited-application-permissions") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CRI-O ImageStatusRequest check arguments; use --help")
		}
	} else if *input == "" || anyFlagProvided(args, "config-map", "config-map-digest", "service", "service-digest", "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "in-toto-run-argv", "in-toto-run-argv-digest", "python-source", "python-source-digest", "python-ast-interpreter", "metanode-config", "metanode-config-digest", "phase", "image-status-request", "image-status-request-digest", "artifact-operation", "from", "to", "requires-inherited-application-permissions") {
		return r.usage("invalid CNCF check arguments; use --help")
	}
	var now time.Time
	var err error
	if *knowledgeDB == "" {
		if *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != "" || *nowText == "" {
			return r.usage("invalid CNCF check arguments; use --help")
		}
		now, err = parseUTC(*nowText)
		if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != *nowText {
			return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
		}
	} else if flagProvided(args, "now") || (*replay != "" && ((!rawKnativeRequested && !rawBuildpacksRequested && !rawInTotoRequested && !rawTUFRequested && !rawKubeflowRequested && !rawCubeFSRequested && !rawCRIORequested && *pin == "") || (rawKnativeRequested && *servicePin == "") || (rawBuildpacksRequested && (*currentLifecyclePin == "" || *proposedLifecyclePin == "")) || (rawInTotoRequested && *inTotoRunArgvPin == "") || ((rawTUFRequested || rawKubeflowRequested) && *pythonSourcePin == "") || (rawCubeFSRequested && *metanodeConfigPin == "") || (rawCRIORequested && *imageStatusRequestPin == "") || *knowledgeRevision == "" || *knowledgeBundleDigest == "" || *knowledgeTrustReceiptDigest == "")) {
		return r.usage("external CNCF checks use verifier time; historical replay requires complete input and knowledge pins")
	}
	if _, err := cncfcheck.Catalog(false, *project); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if rawArgoRequested {
		return r.cncfArgoCDConfigMap(*configMap, *configMapPin, *from, *to, *requiresInheritedPermissions, now, *format)
	}
	if rawKnativeRequested {
		if *knowledgeDB != "" {
			selection := knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
			return r.cncfKnativeService(*service, *servicePin, *from, *to, now, *format, &selection, *replay)
		}
		return r.cncfKnativeService(*service, *servicePin, *from, *to, now, *format, nil, "")
	}
	if rawBuildpacksRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfBuildpacksLifecycle(*currentLifecycleConfig, *proposedLifecycleConfig, *currentLifecyclePin, *proposedLifecyclePin, *from, *to, *currentPlatformAPI, *proposedPlatformAPI, now, *format, selection, *replay)
	}
	if rawInTotoRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfInTotoRun(*inTotoRunArgv, *inTotoRunArgvPin, *from, *to, now, *format, selection, *replay)
	}
	if rawTUFRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfTUFUpdater(*pythonSource, *pythonSourcePin, *pythonASTInterpreter, *from, *to, now, *format, selection, *replay)
	}
	if rawKubeflowRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfKubeflowKFP(*pythonSource, *pythonSourcePin, *pythonASTInterpreter, *from, *to, now, *format, selection, *replay)
	}
	if rawCubeFSRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfCubeFSMetaNode(*metanodeConfig, *metanodeConfigPin, *from, *to, *phase, now, *format, selection, *replay)
	}
	if rawCRIORequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfCRIOArtifactName(*imageStatusRequest, *imageStatusRequestPin, *from, *to, *artifactOperation, now, *format, selection, *replay)
	}
	raw, err := readCNCFPrivate(*input, 1<<20)
	if err != nil {
		return r.cncfError("CNCF input failed local admission", err)
	}
	if *pin != "" {
		sum := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(sum[:]) != *pin {
			return r.fail("CNCF input digest does not match", ExitIntegrity)
		}
	}
	if *knowledgeDB != "" {
		return r.externalCNCF(cncfknowledge.Request{
			Selection: knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest},
			Project:   *project, Input: raw, InputDigest: *pin,
		}, *replay, *format)
	}
	var report cncfcheck.Report
	if *replay != "" {
		expected, readErr := readCNCFPrivate(*replay, 4<<20)
		if readErr != nil {
			return r.cncfError("CNCF replay report failed local admission", readErr)
		}
		report, err = cncfcheck.Replay(*project, raw, now, expected)
	} else {
		report, err = cncfcheck.Check(*project, raw, now)
	}
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
	} else {
		fmt.Fprintf(r.stdout, "%s source-constraint preview\naggregate: UNKNOWN\ninput authority: %s\nknowledge: embedded revision %s\nruntime transitions reproduced: 0\nnetwork used: false\n", report.Project, report.Check.InputAuthority, report.KnowledgeRevision)
		for _, claim := range report.Check.Claims {
			fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction)
		}
		fmt.Fprintf(r.stdout, "input digest: %s\nknowledge pack digest: %s\nnext action: %s\n", report.InputFileDigest, report.KnowledgePackDigest, report.NextAction)
		if *replay != "" {
			fmt.Fprintln(r.stdout, "historical replay: MATCH; current freshness and non-revocation are not established")
		}
	}
	return cncfcheck.ClaimExit(report)
}

func anyFlagProvided(args []string, names ...string) bool {
	for _, name := range names {
		if flagProvided(args, name) {
			return true
		}
	}
	return false
}

func (r runtime) knativeInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("KNATIVE_SERVING_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) buildpacksInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("BUILDPACKS_LIFECYCLE_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) inTotoInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("IN_TOTO_RUN_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) tufInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	if errors.Is(err, cncfprepare.ErrTUFInterpreter) {
		return r.fail("TUF_PYTHON_AST_INTERPRETER_UNAVAILABLE_OR_UNSUPPORTED", ExitUsage)
	}
	if errors.Is(err, cncfprepare.ErrTUFSourceParse) {
		return r.fail("SELECTED_TUF_PYTHON_INTERPRETER_COULD_NOT_PARSE_SOURCE", ExitUsage)
	}
	if errors.Is(err, cncfprepare.ErrTUFProtocol) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("TUF_UPDATER_SOURCE_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) kubeflowKFPInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	if errors.Is(err, cncfprepare.ErrKubeflowKFPInterpreter) {
		return r.fail("KUBEFLOW_KFP_PYTHON_AST_INTERPRETER_UNAVAILABLE_OR_UNSUPPORTED", ExitUsage)
	}
	if errors.Is(err, cncfprepare.ErrKubeflowKFPSourceParse) {
		return r.fail("SELECTED_KUBEFLOW_KFP_PYTHON_INTERPRETER_COULD_NOT_PARSE_SOURCE", ExitUsage)
	}
	if errors.Is(err, cncfprepare.ErrKubeflowKFPProtocol) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("KUBEFLOW_KFP_SOURCE_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) cubeFSInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("CUBEFS_METANODE_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) crioInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail("CRIO_IMAGE_STATUS_REQUEST_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) knativeIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func readCNCFPrivate(path string, limit int) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, cncfcheck.ErrInvalid
	}
	raw, info, err := currentbundle.ReadBoundedFileInfo(absolute, limit)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		return nil, cncfcheck.ErrInvalid
	}
	return raw, nil
}

func (r runtime) cncfError(message string, err error) int {
	if errors.Is(err, cncfcheck.ErrIntegrity) || errors.Is(err, currentbundle.ErrIntegrity) {
		return r.fail(message, ExitIntegrity)
	}
	return r.fail(message, ExitUsage)
}
