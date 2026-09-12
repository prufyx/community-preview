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
	"strconv"
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
   or: prufyx check cncf --project the-update-framework-tuf --python-source FILE --from 6.0.0 --to 7.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project kubeflow --python-source FILE --from 1.8.22 --to 2.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cubefs --metanode-config FILE --from 3.2.1 --to 3.3.2 [--phase metanode-upgrade] (--now RFC3339 | --knowledge-db DIR) [--metanode-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cri-o --image-status-request FILE --artifact-operation named-reference-resolution --from 1.34.0 --to 1.35.0 (--now RFC3339 | --knowledge-db DIR) [--image-status-request-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project distribution --image-manifest FILE --from 2.8.3 --to 3.0.0 (--now RFC3339 | --knowledge-db DIR) [--image-manifest-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project container-network-interface-cni --cni-configuration FILE --from 0.4.0 --to 1.0.0 [--operation configuration-spec-migration] (--now RFC3339 | --knowledge-db DIR) [--cni-configuration-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project emissary-ingress --diagd-argv FILE --from 3.10.0 --to 4.0.1 (--now RFC3339 | --knowledge-db DIR) [--diagd-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project openfga --effective-config FILE --from 1.17.1 --to 1.18.0 [--effective-config-complete] (--now RFC3339 | --knowledge-db DIR) [--effective-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project buildpacks --current-lifecycle-config FILE --proposed-lifecycle-config FILE --from 0.16.5 --to 0.17.7 --current-platform-api 0.11 --proposed-platform-api 0.12|0.13 (--now RFC3339 | --knowledge-db DIR) [--current-lifecycle-config-digest SHA256] [--proposed-lifecycle-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project metallb|contour|kubevirt|thanos|cortex --native-resource FILE --from VERSION --to VERSION (--now RFC3339 | --knowledge-db DIR) [--native-resource-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project flux --native-resource FILE --from 2.6.4 --to 2.7.0 [--resource-scope-complete] (--now RFC3339 | --knowledge-db DIR) [--native-resource-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project nats --nats-config FILE --from 2.10.0 --to 2.11.0 (--now RFC3339 | --knowledge-db DIR) [--nats-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project prometheus --scrape-config FILE --scrape-job NAME --from 2.55.1 --to 3.1.0 --scrape-config-complete --scrape-config-precedence-resolved (--now RFC3339 | --knowledge-db DIR) [--scrape-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cloudnativepg --current-resource FILE --resource FILE --from 1.29.0 --to 1.30.0 (--now RFC3339 | --knowledge-db DIR) [--current-resource-digest SHA256] [--resource-digest SHA256] [--replay-report FILE] [--format human|json]

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
The Prometheus mode reads one caller-selected native scrape_config YAML mapping.
It retains only whether the reviewed old or new key is present; job names,
targets and unrelated settings are discarded. Completeness and precedence are
caller declarations. PASS covers only the selected key rename, not parsing the
whole prometheus.yml, startup, scraping, or native-histogram behavior.
The TUF mode uses a Go lexical parser that admits one unaliased direct import
and one top-level direct Updater call. It reads private Python source as data
and never imports or executes it. Source outside that narrow grammar remains
UNKNOWN. Embedded knowledge covers Updater 6.0.0 -> 7.0.0 and checks only
explicit bootstrap keyword presence in one admitted direct call. Historical
replay requires the raw source digest and all three knowledge pins.
The Kubeflow mode uses a Go lexical parser to recognize only one
unaliased bare create_component_from_func or dsl.component decorator. It never
imports or executes supplied Python source and does not require an interpreter.
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
The Distribution mode reads one private image manifest and classifies only its
bounded schema1, Docker schema2, or OCI image-manifest form for the exact
2.8.3 -> 3.0.0 source plan. It never contacts a registry or validates content,
storage, pull, platform, or runtime behavior. The CNI mode reads one private
configuration for specification 0.4.0 -> 1.0.0 and keeps library/plugin/runtime
identity separate. It requires caller-declared configuration-spec-migration
intent for a scoped result; missing or unsupported intent stays UNKNOWN.
The Emissary-Ingress mode reads one private direct diagd JSON argv array for
the exact 3.10.0 -> 4.0.1 reviewed option removal. The OpenFGA mode reads one
private, strictly parsed nested effective-configuration JSON file for 1.17.1
-> 1.18.0. effective-config-complete is optional: omitted or false keeps
the scoped claim UNKNOWN, while true declares file, environment, and flag
precedence resolved. Neither mode runs a process, reads a cluster, or validates
runtime behavior. Optional raw-input digests bind supplied bytes.
Selected-store checks have no embedded fallback. Historical replay requires
the matching raw native-input digest and all three knowledge pins.
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
	metanodeConfig := fs.String("metanode-config", "", "private planned CubeFS MetaNode JSON config")
	metanodeConfigPin := fs.String("metanode-config-digest", "", "optional exact MetaNode config SHA-256")
	phase := fs.String("phase", "", "caller-declared upgrade phase")
	imageStatusRequest := fs.String("image-status-request", "", "private CRI ImageStatusRequest JSON")
	imageStatusRequestPin := fs.String("image-status-request-digest", "", "optional exact ImageStatusRequest SHA-256")
	artifactOperation := fs.String("artifact-operation", "", "caller-declared artifact operation")
	imageManifest := fs.String("image-manifest", "", "private Distribution image manifest JSON")
	imageManifestPin := fs.String("image-manifest-digest", "", "optional exact image manifest SHA-256")
	cniConfiguration := fs.String("cni-configuration", "", "private CNI configuration JSON")
	cniConfigurationPin := fs.String("cni-configuration-digest", "", "optional exact CNI configuration SHA-256")
	diagdArgv := fs.String("diagd-argv", "", "private direct Emissary diagd JSON argv array")
	diagdArgvPin := fs.String("diagd-argv-digest", "", "optional exact diagd argv SHA-256")
	effectiveConfig := fs.String("effective-config", "", "private resolved OpenFGA effective configuration JSON")
	effectiveConfigPin := fs.String("effective-config-digest", "", "optional exact effective configuration SHA-256")
	effectiveConfigComplete := fs.Bool("effective-config-complete", false, "caller declaration that OpenFGA file, environment, and flag precedence is resolved")
	operation := fs.String("operation", "", "caller-declared scoped operation")
	nativeResource := fs.String("native-resource", "", "private selected native Kubernetes JSON resource")
	nativeResourcePin := fs.String("native-resource-digest", "", "optional exact native resource SHA-256")
	resourceScopeComplete := fs.Bool("resource-scope-complete", false, "caller declaration that the selected Flux rendered-resource JSON set is complete")
	natsConfig := fs.String("nats-config", "", "private standalone NATS JSON-like configuration")
	natsConfigPin := fs.String("nats-config-digest", "", "optional exact NATS configuration SHA-256")
	scrapeConfig := fs.String("scrape-config", "", "private selected native Prometheus scrape_config YAML")
	scrapeConfigPin := fs.String("scrape-config-digest", "", "optional exact selected scrape_config SHA-256")
	scrapeJob := fs.String("scrape-job", "", "exact job_name selecting the supplied scrape_config")
	scrapeConfigComplete := fs.Bool("scrape-config-complete", false, "caller declaration that the selected scrape_config is complete")
	scrapeConfigPrecedenceResolved := fs.Bool("scrape-config-precedence-resolved", false, "caller declaration that configuration precedence is resolved")
	currentResource := fs.String("current-resource", "", "private current native Kubernetes JSON resource")
	currentResourcePin := fs.String("current-resource-digest", "", "optional exact current resource SHA-256")
	resource := fs.String("resource", "", "private proposed native Kubernetes JSON resource")
	resourcePin := fs.String("resource-digest", "", "optional exact proposed resource SHA-256")
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
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *project == "" || (*format != "human" && *format != "json") || (flagProvided(args, "input-digest") && !digestRE.MatchString(*pin)) || (flagProvided(args, "config-map-digest") && !digestRE.MatchString(*configMapPin)) || (flagProvided(args, "service-digest") && !digestRE.MatchString(*servicePin)) || (flagProvided(args, "current-lifecycle-config-digest") && !digestRE.MatchString(*currentLifecyclePin)) || (flagProvided(args, "proposed-lifecycle-config-digest") && !digestRE.MatchString(*proposedLifecyclePin)) || (flagProvided(args, "in-toto-run-argv-digest") && !digestRE.MatchString(*inTotoRunArgvPin)) || (flagProvided(args, "python-source-digest") && !digestRE.MatchString(*pythonSourcePin)) || (flagProvided(args, "metanode-config-digest") && !digestRE.MatchString(*metanodeConfigPin)) || (flagProvided(args, "image-status-request-digest") && !digestRE.MatchString(*imageStatusRequestPin)) || (flagProvided(args, "native-resource-digest") && !digestRE.MatchString(*nativeResourcePin)) || (flagProvided(args, "nats-config-digest") && !digestRE.MatchString(*natsConfigPin)) || (flagProvided(args, "scrape-config-digest") && !digestRE.MatchString(*scrapeConfigPin)) || (flagProvided(args, "current-resource-digest") && !digestRE.MatchString(*currentResourcePin)) || (flagProvided(args, "resource-digest") && !digestRE.MatchString(*resourcePin)) || (flagProvided(args, "image-manifest-digest") && !digestRE.MatchString(*imageManifestPin)) || (flagProvided(args, "cni-configuration-digest") && !digestRE.MatchString(*cniConfigurationPin)) || (flagProvided(args, "diagd-argv-digest") && !digestRE.MatchString(*diagdArgvPin)) || (flagProvided(args, "effective-config-digest") && !digestRE.MatchString(*effectiveConfigPin)) || (flagProvided(args, "replay-report") && *replay == "") {
		return r.usage("invalid CNCF check arguments; use --help")
	}
	for _, name := range []string{"knowledge-db", "knowledge-revision", "knowledge-bundle-digest", "knowledge-trust-receipt-digest"} {
		if flagProvided(args, name) && fs.Lookup(name).Value.String() == "" {
			return r.usage("invalid external CNCF knowledge selection; use --help")
		}
	}
	nativeFlags := anyFlagProvided(args, "native-resource", "native-resource-digest", "current-resource", "current-resource-digest", "resource", "resource-digest")
	fluxNativeRequested := *project == "flux" && anyFlagProvided(args, "native-resource", "native-resource-digest", "resource-scope-complete")
	natsFlags := anyFlagProvided(args, "nats-config", "nats-config-digest")
	prometheusScrapeFlags := anyFlagProvided(args, "scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved")
	nativeProject := *project == "metallb" || *project == "contour" || *project == "kubevirt" || *project == "thanos" || *project == "cortex" || *project == "cloudnativepg" || *project == "flux"
	if (nativeFlags || flagProvided(args, "resource-scope-complete")) && !nativeProject {
		return r.usage("native resource flags require metallb, contour, kubevirt, thanos, cortex, cloudnativepg, or flux; use --help")
	}
	if nativeProject && (nativeFlags || fluxNativeRequested) {
		return r.cncfNativeResourceCheck(*project, *nativeResource, *nativeResourcePin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, *resourceScopeComplete, args)
	}
	if natsFlags && *project != "nats" {
		return r.usage("NATS configuration flags require project nats; use --help")
	}
	if *project == "nats" && natsFlags {
		return r.cncfNativeResourceCheck(*project, *natsConfig, *natsConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, args)
	}
	if prometheusScrapeFlags && *project != "prometheus" {
		return r.usage("Prometheus scrape configuration flags require project prometheus; use --help")
	}
	if *project == "prometheus" && prometheusScrapeFlags {
		return r.cncfNativeResourceCheck(*project, *scrapeConfig, *scrapeConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *scrapeJob, *scrapeConfigComplete, *scrapeConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, args)
	}
	rawArgoRequested := *project == "argo-cd" && anyFlagProvided(args, "config-map", "config-map-digest", "from", "to", "requires-inherited-application-permissions")
	rawKnativeRequested := *project == "knative" && anyFlagProvided(args, "service", "service-digest", "from", "to")
	rawBuildpacksRequested := *project == "buildpacks" && anyFlagProvided(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "from", "to")
	rawInTotoRequested := *project == "in-toto" && anyFlagProvided(args, "in-toto-run-argv", "in-toto-run-argv-digest", "from", "to")
	rawTUFRequested := *project == "the-update-framework-tuf" && anyFlagProvided(args, "python-source", "python-source-digest", "from", "to")
	rawKubeflowRequested := *project == "kubeflow" && anyFlagProvided(args, "python-source", "python-source-digest", "from", "to")
	rawCubeFSRequested := *project == "cubefs" && anyFlagProvided(args, "metanode-config", "metanode-config-digest", "phase", "from", "to")
	rawCRIORequested := *project == "cri-o" && anyFlagProvided(args, "image-status-request", "image-status-request-digest", "artifact-operation", "from", "to")
	rawDistributionRequested := *project == "distribution" && anyFlagProvided(args, "image-manifest", "image-manifest-digest", "from", "to")
	rawCNISpecRequested := *project == "container-network-interface-cni" && anyFlagProvided(args, "cni-configuration", "cni-configuration-digest", "operation", "from", "to")
	rawEmissaryRequested := *project == "emissary-ingress" && anyFlagProvided(args, "diagd-argv", "diagd-argv-digest", "from", "to")
	rawOpenFGARequested := *project == "openfga" && anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "from", "to")
	formatFlagsProvided := anyFlagProvided(args, "image-manifest", "image-manifest-digest", "cni-configuration", "cni-configuration-digest", "operation", "diagd-argv", "diagd-argv-digest", "effective-config", "effective-config-digest", "effective-config-complete")
	if formatFlagsProvided && !rawDistributionRequested && !rawCNISpecRequested && !rawEmissaryRequested && !rawOpenFGARequested {
		return r.usage("invalid native format check arguments; use --help")
	}
	if rawDistributionRequested || rawCNISpecRequested || rawEmissaryRequested || rawOpenFGARequested {
		if *from == "" || *to == "" || (*knowledgeDB == "" && flagProvided(args, "replay-report")) || (rawDistributionRequested && (*imageManifest == "" || cncfUnexpectedModeFlag(args, "image-manifest", "image-manifest-digest"))) || (rawCNISpecRequested && (*cniConfiguration == "" || cncfUnexpectedModeFlag(args, "cni-configuration", "cni-configuration-digest", "operation"))) || (rawEmissaryRequested && (*diagdArgv == "" || cncfUnexpectedModeFlag(args, "diagd-argv", "diagd-argv-digest"))) || (rawOpenFGARequested && (*effectiveConfig == "" || cncfUnexpectedModeFlag(args, "effective-config", "effective-config-digest", "effective-config-complete"))) {
			return r.usage("invalid native format check arguments; use --help")
		}
	}
	if rawDistributionRequested || rawCNISpecRequested || rawEmissaryRequested || rawOpenFGARequested {
		// The closed selector checks above admitted the selected format route.
	} else if rawArgoRequested {
		if *configMap == "" || cncfUnexpectedModeFlag(args, "config-map", "config-map-digest", "requires-inherited-application-permissions") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (flagProvided(args, "requires-inherited-application-permissions") && *requiresInheritedPermissions != "true" && *requiresInheritedPermissions != "false") {
			return r.usage("invalid Argo CD ConfigMap check arguments; use --help")
		}
	} else if rawKnativeRequested {
		if *service == "" || cncfUnexpectedModeFlag(args, "service", "service-digest") || *from == "" || *to == "" || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Knative Serving Service check arguments; use --help")
		}
	} else if rawBuildpacksRequested {
		if *currentLifecycleConfig == "" || *proposedLifecycleConfig == "" || *currentPlatformAPI == "" || *proposedPlatformAPI == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Buildpacks Lifecycle check arguments; use --help")
		}
	} else if rawInTotoRequested {
		if *inTotoRunArgv == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "in-toto-run-argv", "in-toto-run-argv-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid in-toto-run argv check arguments; use --help")
		}
	} else if rawTUFRequested {
		if *pythonSource == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "python-source", "python-source-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid TUF Updater Python source check arguments; use --help")
		}
	} else if rawKubeflowRequested {
		if *pythonSource == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "python-source", "python-source-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid KFP Python source check arguments; use --help")
		}
	} else if rawCubeFSRequested {
		if *metanodeConfig == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "metanode-config", "metanode-config-digest", "phase") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CubeFS MetaNode config check arguments; use --help")
		}
	} else if rawCRIORequested {
		if *imageStatusRequest == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "image-status-request", "image-status-request-digest", "artifact-operation") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CRI-O ImageStatusRequest check arguments; use --help")
		}
	} else if *input == "" || cncfUnexpectedModeFlag(args, "input", "input-digest") || anyFlagProvided(args, "from", "to") {
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
	} else if flagProvided(args, "now") || (*replay != "" && ((!rawKnativeRequested && !rawBuildpacksRequested && !rawInTotoRequested && !rawTUFRequested && !rawKubeflowRequested && !rawCubeFSRequested && !rawCRIORequested && !rawDistributionRequested && !rawCNISpecRequested && !rawEmissaryRequested && !rawOpenFGARequested && *pin == "") || (rawKnativeRequested && *servicePin == "") || (rawBuildpacksRequested && (*currentLifecyclePin == "" || *proposedLifecyclePin == "")) || (rawInTotoRequested && *inTotoRunArgvPin == "") || ((rawTUFRequested || rawKubeflowRequested) && *pythonSourcePin == "") || (rawCubeFSRequested && *metanodeConfigPin == "") || (rawCRIORequested && *imageStatusRequestPin == "") || (rawDistributionRequested && *imageManifestPin == "") || (rawCNISpecRequested && *cniConfigurationPin == "") || (rawEmissaryRequested && *diagdArgvPin == "") || (rawOpenFGARequested && *effectiveConfigPin == "") || *knowledgeRevision == "" || *knowledgeBundleDigest == "" || *knowledgeTrustReceiptDigest == "")) {
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
		return r.cncfTUFUpdater(*pythonSource, *pythonSourcePin, *from, *to, now, *format, selection, *replay)
	}
	if rawKubeflowRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfKubeflowKFP(*pythonSource, *pythonSourcePin, *from, *to, now, *format, selection, *replay)
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
	if rawDistributionRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("distribution", *imageManifest, *imageManifestPin, *from, *to, "", now, *format, selection, *replay)
	}
	if rawCNISpecRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("container-network-interface-cni", *cniConfiguration, *cniConfigurationPin, *from, *to, *operation, now, *format, selection, *replay)
	}
	if rawEmissaryRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("emissary-ingress", *diagdArgv, *diagdArgvPin, *from, *to, "", now, *format, selection, *replay)
	}
	if rawOpenFGARequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		complete := ""
		if flagProvided(args, "effective-config-complete") {
			complete = strconv.FormatBool(*effectiveConfigComplete)
		}
		return r.cncfNativeFormat("openfga", *effectiveConfig, *effectiveConfigPin, *from, *to, complete, now, *format, selection, *replay)
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

// cncfUnexpectedModeFlag rejects an explicitly supplied input selector that
// belongs to another CNCF check mode. Keep this complete when adding a new
// check input flag: otherwise a later route can parse a supplied selector and
// silently ignore it. Common selection, replay, output, and time flags do not
// belong here because their validation is shared by the selected mode.
func cncfUnexpectedModeFlag(args []string, allowed ...string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for _, name := range cncfModeInputFlags {
		if flagProvided(args, name) {
			if _, ok := allowedSet[name]; !ok {
				return true
			}
		}
	}
	return false
}

// cncfModeInputFlags is the closed set of input selectors admitted by check
// cncf. Some names are reserved for accepted upcoming format adapters so their
// eventual FlagSet registration cannot create an ignored cross-mode input.
var cncfModeInputFlags = []string{
	"input", "input-digest",
	"config-map", "config-map-digest", "requires-inherited-application-permissions",
	"service", "service-digest",
	"current-lifecycle-config", "proposed-lifecycle-config",
	"current-lifecycle-config-digest", "proposed-lifecycle-config-digest",
	"current-platform-api", "proposed-platform-api",
	"in-toto-run-argv", "in-toto-run-argv-digest",
	"python-source", "python-source-digest",
	"metanode-config", "metanode-config-digest", "phase",
	"image-status-request", "image-status-request-digest", "artifact-operation",
	"native-resource", "native-resource-digest",
	"resource-scope-complete",
	"nats-config", "nats-config-digest",
	"scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved",
	"current-resource", "current-resource-digest", "resource", "resource-digest",
	"image-manifest", "image-manifest-digest",
	"cni-configuration", "cni-configuration-digest", "operation",
	"effective-config", "effective-config-complete",
	"effective-config-digest", "diagd-argv", "diagd-argv-digest",
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
	if errors.Is(err, cncfprepare.ErrTUFSourceParse) {
		return r.fail("TUF_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX", ExitUsage)
	}
	return r.fail("TUF_UPDATER_SOURCE_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) kubeflowKFPInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	if errors.Is(err, cncfprepare.ErrKubeflowKFPSourceParse) {
		return r.fail("KUBEFLOW_KFP_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX", ExitUsage)
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
