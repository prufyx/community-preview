package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx-cli/internal/cncfprepare"
	"github.com/prufyx/prufyx-cli/internal/currentbundle"
)

func (r runtime) prepareCNCF(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, `Usage: prufyx prepare cncf --project kyverno --input FILE --container NAME --from VERSION --to VERSION [--distribution official_upstream|custom_build] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project linkerd --input FILE --from 2.13.7 --to 2.14.0 [--distribution official_upstream|custom_build] [--schema-validation required|disabled] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project karmada --input FILE --from 1.18.3 --to 1.19.0 [--distribution official_upstream|custom_build] [--target-policy-crd-admission required|disabled] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project argo-cd --input FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cilium --input FILE --from 1.18.6 --to 1.19.0 [--complete-cnp-ccnp-set true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cilium --input FILE --from 1.18.13 --to 1.19.7 [--complete-cnp-ccnp-set true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project etcd --input FILE --from 3.5.17 --to 3.6.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project jaeger --input FILE --from 1.76.0 --to 2.20.0 [--non-memory-storage-required true|false] [--official-jaeger-distribution true|false] [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project metallb|contour --input FILE --from VERSION --to VERSION [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project cloudnativepg --input FILE --from 1.29.0 --to 1.30.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project kubevirt --input FILE --from 1.8.4 --to 1.9.0 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project emissary-ingress --input FILE --from 3.10.0 --to 4.0.1 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project harbor --input FILE --from 2.7.0 --to 2.8.0 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project openfga --input FILE --from 1.17.1 --to 1.18.0 --effective-config-complete [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project opencost --input FILE --from 1.119.0 --to 1.120.0 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project cloud-custodian --input FILE --from 0.9.50 --to 0.9.51 [--input-digest SHA256] [--format human|json|input]
	   or: prufyx prepare cncf --project fluentd --input FILE --from 1.17.1 --to 1.18.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project distribution --input FILE --from 2.8.3 --to 3.0.0 [--input-digest SHA256] [--format human|json|input]
   or: prufyx prepare cncf --project container-network-interface-cni --input FILE --from 0.4.0 --to 1.0.0 --operation configuration-spec-migration [--input-digest SHA256] [--format human|json|input]

Prepare a minimized declaration from one private local supported resource JSON or declaration.
Select the Kyverno container explicitly. A scoped result requires an explicit
distribution declaration and the bare literal reports-controller command. Image
entrypoints, other paths, wrappers and ambiguous arguments remain UNKNOWN.
This prepares operator-declared input. It does not observe a cluster, validate
the complete workload or run an upgrade check. No network or model is used.

Linkerd accepts one private MeshTLSAuthentication JSON resource and derives
only selector emptiness. Its --container option is invalid. It does not parse
a CRD, call API admission, inspect stored objects or establish runtime behavior.

Karmada accepts one private policy.karmada.io/v1alpha1 PropagationPolicy or
ClusterPropagationPolicy JSON resource. It can witness a legacy application
purgeMode blocker but never prove aggregate absence or PASS. Its --container
and --schema-validation options are invalid. It does not validate a CRD, call
API admission, inspect stored resources or establish runtime behavior.

Argo CD accepts one private proposed v1 ConfigMap JSON named argocd-cm. It
reads only the explicit true or false inheritance setting and requires an
explicit access-intent declaration. Missing or malformed configuration stays
UNKNOWN; it does not inspect RBAC, call a cluster, or infer an effective default.

Cilium accepts one private CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or
bounded policy List JSON. A nonempty requires field is a scoped blocker. A
scoped false result requires an explicit complete CNP and CCNP set declaration;
partial List pages, policy semantics, and runtime behavior remain UNKNOWN.

MetalLB accepts one caller-selected legacy ConfigMap or one supported
metallb.io/v1beta1 CR. Contour accepts one caller-selected Gateway API resource
and classifies only the reviewed v1alpha1 group versus v1alpha2. These checks
do not inspect a cluster or establish runtime behavior; unsupported shapes
remain UNKNOWN.

CloudNativePG accepts one JSON envelope containing matching current and
proposed Database, Pooler, Publication, Subscription, or ScheduledBackup
objects. It compares only the namespaced object identity and spec.cluster.name;
both objects are required to establish an update.

KubeVirt accepts one caller-supplied kubevirt.io/v1 VirtualMachine or
VirtualMachineInstance JSON resource. It counts only the five reviewed
interface binding slots and requires exactly one per named interface. Missing
or malformed native paths remain UNKNOWN; it does not inspect feature gates,
plugins, admission, or runtime behavior.

Emissary-Ingress accepts a caller-supplied direct diagd argv JSON array. OpenFGA
accepts strictly parsed nested authn effective-configuration JSON only when the
caller explicitly declares file, environment, and flag precedence complete.
Both retain only reviewed facts; wrappers, custom behavior, and runtime remain UNKNOWN.

Harbor accepts one caller-declared complete literal make/install.sh argv vector.
It checks only the removed --with-chartmuseum option for the reviewed 2.7.0 to
2.8.0 pair. Help, wrappers, values, unknown options, and unresolved inputs remain
UNKNOWN; it does not execute the installer or assess chart, database, or runtime state.

OpenCost accepts one Prufyx operator declaration of enabled cloud-cost source
selection. It is not an OpenCost native config parser. The caller declares
selection completeness and whether a target cloud-integration file is selected
and present; file contents, credentials, mounts, startup, and cloud access are
not inspected.

etcd accepts one private EtcdEffectiveArguments JSON object containing a complete
direct arguments-only vector. The first slice accepts only self-contained
--name=value atoms and recognizes the eight removed v2/proxy options. It never
resolves wrappers, environment/config/response files, or executes etcd.

Jaeger accepts one private direct-invocation JSON declaration with
authority OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY and exactly
one local literal --config=VALUE argv atom. It does not read the location or
infer config content, backend, credentials, distribution, startup, or runtime.
The two rule guards remain explicit operator declarations; other argument forms
remain UNKNOWN.

Distribution accepts one private image manifest JSON document and classifies
only a bounded Docker schema1, Docker schema2, or OCI image-manifest shape.
It does not contact a registry, pull an image, validate content references, or
claim that a complete manifest can be stored or run.

Container Network Interface (CNI) accepts one private CNI configuration JSON
and explicit configuration-spec-migration intent. Its versions identify the
specification, not the CNI Go library, plugins, or a runtime. It checks only
single-plugin versus plugin-list configuration shape.

--format input writes only the canonical declaration for check cncf. Redirect
with umask 077 to a new file so it remains private. --format json also includes
the source digest, preparation reason and omissions, without raw workload data.
Exit 0: prepared; 11: unresolved preparation; 2: invalid input; 3: integrity failure.`)
		return ExitOK
	}
	fs := flag.NewFlagSet("prepare cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "kyverno, linkerd, karmada, argo-cd, cilium, etcd, jaeger, metallb, contour, cloudnativepg, kubevirt, emissary-ingress, harbor, openfga, opencost, cloud-custodian, fluentd, distribution, or container-network-interface-cni")
	input := fs.String("input", "", "private proposed input JSON")
	container := fs.String("container", "", "explicit local Kyverno container selector")
	from := fs.String("from", "", "actual declared current component version")
	to := fs.String("to", "", "actual declared proposed component version")
	distribution := fs.String("distribution", "", "explicit distribution guard: official_upstream or custom_build")
	schemaValidation := fs.String("schema-validation", "", "Linkerd schema intent: required or disabled")
	targetPolicyCRDAdmission := fs.String("target-policy-crd-admission", "", "Karmada target policy CRD intent: required or disabled")
	requiresInheritedPermissions := fs.String("requires-inherited-application-permissions", "", "explicit Argo CD v2 inheritance access intent: true or false")
	completeCNPCCNPSet := fs.String("complete-cnp-ccnp-set", "", "explicit Cilium CNP and CCNP policy-set completeness: true or false")
	jaegerNonMemoryStorage := fs.String("non-memory-storage-required", "", "explicit Jaeger non-memory storage requirement: true or false")
	jaegerOfficialDistribution := fs.String("official-jaeger-distribution", "", "explicit Jaeger official distribution declaration: true or false")
	operation := fs.String("operation", "", "explicit operation for profiles that require one")
	effectiveConfigComplete := fs.Bool("effective-config-complete", false, "caller declaration that OpenFGA file, environment, and flag precedence is resolved")
	pin := fs.String("input-digest", "", "optional exact source file SHA-256")
	format := fs.String("format", "human", "human, json or input")
	if duplicateFlags(args) || fs.Parse(args) != nil {
		return r.usage("invalid CNCF preparation arguments; use --help")
	}
	if concreteCNCFPreparationProject(*project) && (fs.NArg() != 0 || *input == "" || *from == "" || *to == "" || (*format != "human" && *format != "json" && *format != "input") || (flagProvided(args, "input-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*pin))) {
		if *project == "linkerd" {
			return r.fail("LINKERD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "karmada" {
			return r.fail("KARMADA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "cilium" {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "jaeger" {
			return r.fail("JAEGER_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "opencost" {
			return r.fail("OPENCOST_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "cloud-custodian" {
			return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		return r.fail("ARGO_CD_PREPARATION_INPUT_INVALID", ExitUsage)
	}
	if fs.NArg() != 0 || *project == "" || *input == "" || *from == "" || *to == "" || (*project == "kyverno" && *container == "") || (*format != "human" && *format != "json" && *format != "input") || (flagProvided(args, "input-digest") && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*pin)) {
		return r.usage("invalid CNCF preparation arguments; use --help")
	}
	if *project != "openfga" && flagProvided(args, "effective-config-complete") {
		return r.usage("--effective-config-complete is only valid for OpenFGA preparation")
	}
	// Validate project-specific flags before opening the private input. This keeps
	// malformed cross-project invocations from admitting any local file.
	switch *project {
	case "kyverno":
		if *container == "" || flagProvided(args, "schema-validation") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(*distribution != "" && *distribution != cncfprepare.KyvernoDistributionOfficial && *distribution != cncfprepare.KyvernoDistributionCustom) {
			return r.usage("invalid Kyverno preparation arguments; use --help")
		}
	case "linkerd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(flagProvided(args, "schema-validation") && *schemaValidation == "") ||
			(*distribution != "" && *distribution != cncfprepare.LinkerdDistributionOfficial && *distribution != cncfprepare.LinkerdDistributionCustom) ||
			(*schemaValidation != "" && *schemaValidation != cncfprepare.LinkerdSchemaRequired && *schemaValidation != cncfprepare.LinkerdSchemaDisabled) {
			return r.fail("LINKERD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "karmada":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "distribution") && *distribution == "") ||
			(flagProvided(args, "target-policy-crd-admission") && *targetPolicyCRDAdmission == "") ||
			(*distribution != "" && *distribution != cncfprepare.KarmadaDistributionOfficial && *distribution != cncfprepare.KarmadaDistributionCustom) ||
			(*targetPolicyCRDAdmission != "" && *targetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionRequired && *targetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionDisabled) {
			return r.fail("KARMADA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "argo-cd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "requires-inherited-application-permissions") && *requiresInheritedPermissions != "true" && *requiresInheritedPermissions != "false") {
			return r.fail("ARGO_CD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "cilium":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "complete-cnp-ccnp-set") && *completeCNPCCNPSet != "true" && *completeCNPCCNPSet != "false") {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "etcd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("ETCD_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "jaeger":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") ||
			flagProvided(args, "operation") ||
			(flagProvided(args, "non-memory-storage-required") && *jaegerNonMemoryStorage != "true" && *jaegerNonMemoryStorage != "false") ||
			(flagProvided(args, "official-jaeger-distribution") && *jaegerOfficialDistribution != "true" && *jaegerOfficialDistribution != "false") {
			return r.fail("JAEGER_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "metallb", "contour", "cloudnativepg", "kubevirt", "emissary-ingress", "harbor", "cloud-custodian", "fluentd":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			if *project == "cloud-custodian" {
				return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
			}
			return r.fail("NATIVE_MIGRATION_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "opencost":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("OPENCOST_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	case "distribution":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || cncfOptionProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("DISTRIBUTION_MANIFEST_INPUT_INVALID", ExitUsage)
		}
	case "container-network-interface-cni":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || cncfOptionProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") {
			return r.fail("CNI_SPEC_CONFIGURATION_INPUT_INVALID", ExitUsage)
		}
	case "openfga":
		if (*container != "" || flagProvided(args, "container")) || flagProvided(args, "schema-validation") || flagProvided(args, "distribution") || flagProvided(args, "target-policy-crd-admission") || flagProvided(args, "requires-inherited-application-permissions") || flagProvided(args, "complete-cnp-ccnp-set") || flagProvided(args, "non-memory-storage-required") || flagProvided(args, "official-jaeger-distribution") || flagProvided(args, "operation") {
			return r.fail("OPENFGA_PREPARATION_INPUT_INVALID", ExitUsage)
		}
	default:
		return r.usage("invalid CNCF preparation project; use --help")
	}
	raw, err := readCNCFPrivate(*input, 1<<20)
	if err != nil {
		if *project == "linkerd" {
			return r.linkerdInputFailure(err)
		}
		if *project == "karmada" {
			return r.karmadaInputFailure(err)
		}
		if *project == "argo-cd" {
			return r.argoCDInputFailure(err)
		}
		if *project == "cilium" {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "jaeger" {
			return r.jaegerInputFailure(err)
		}
		return r.cncfError("CNCF preparation input failed local admission", err)
	}
	sourceHash := sha256.Sum256(raw)
	sourceDigest := "sha256:" + hex.EncodeToString(sourceHash[:])
	if *pin != "" && *pin != sourceDigest {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation input digest does not match", ExitIntegrity)
	}
	var prepared cncfprepare.Prepared
	switch *project {
	case "kyverno":
		prepared, err = cncfprepare.PrepareKyvernoScoped(raw, *container, *from, *to, *distribution)
	case "linkerd":
		prepared, err = cncfprepare.PrepareLinkerd(raw, *from, *to, *distribution, *schemaValidation)
	case "karmada":
		prepared, err = cncfprepare.PrepareKarmada(raw, *from, *to, *distribution, *targetPolicyCRDAdmission)
	case "argo-cd":
		var required *bool
		if *requiresInheritedPermissions != "" {
			value := *requiresInheritedPermissions == "true"
			required = &value
		}
		prepared, err = cncfprepare.PrepareArgoCD(raw, *from, *to, required)
	case "cilium":
		var complete *bool
		if *completeCNPCCNPSet != "" {
			value := *completeCNPCCNPSet == "true"
			complete = &value
		}
		prepared, err = cncfprepare.PrepareCilium(raw, *from, *to, complete)
	case "etcd":
		prepared, err = cncfprepare.PrepareEtcd(raw, *from, *to)
	case "jaeger":
		var nonMemory, official *bool
		if *jaegerNonMemoryStorage != "" {
			value := *jaegerNonMemoryStorage == "true"
			nonMemory = &value
		}
		if *jaegerOfficialDistribution != "" {
			value := *jaegerOfficialDistribution == "true"
			official = &value
		}
		prepared, err = cncfprepare.PrepareJaeger(raw, *from, *to, nonMemory, official)
	case "metallb", "contour":
		prepared, err = cncfprepare.PrepareNativeMigration(raw, *project, *from, *to)
	case "cloudnativepg":
		prepared, err = cncfprepare.PrepareCloudNativePG(raw, *from, *to)
	case "kubevirt":
		prepared, err = cncfprepare.PrepareKubeVirt(raw, *from, *to)
	case "distribution":
		prepared, err = cncfprepare.PrepareDistributionManifest(raw, *from, *to)
	case "container-network-interface-cni":
		prepared, err = cncfprepare.PrepareCNISpecConfiguration(raw, *from, *to, *operation)
	case "emissary-ingress":
		prepared, err = cncfprepare.PrepareEmissary(raw, *from, *to)
	case "harbor":
		prepared, err = cncfprepare.PrepareHarbor(raw, *from, *to)
	case "openfga":
		prepared, err = cncfprepare.PrepareOpenFGAOIDC(raw, *from, *to, effectiveConfigComplete)
	case "opencost":
		prepared, err = cncfprepare.PrepareOpenCostCloudSource(raw, *from, *to)
	case "cloud-custodian":
		prepared, err = cncfprepare.PrepareCloudCustodian(raw, *from, *to)
	case "fluentd":
		prepared, err = cncfprepare.PrepareFluentDLiteral(raw, *from, *to)
	}
	if err != nil {
		if *project == "linkerd" {
			return r.linkerdInputFailure(err)
		}
		if *project == "karmada" {
			return r.karmadaInputFailure(err)
		}
		if *project == "argo-cd" {
			return r.argoCDInputFailure(err)
		}
		if *project == "cilium" {
			return r.fail("CILIUM_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		if *project == "jaeger" {
			return r.jaegerInputFailure(err)
		}
		if *project == "cloud-custodian" {
			return r.fail("CLOUD_CUSTODIAN_PREPARATION_INPUT_INVALID", ExitUsage)
		}
		return r.fail("CNCF preparation input is invalid", ExitUsage)
	}
	inputHash := sha256.Sum256(prepared.CanonicalInputJSON)
	if prepared.SourceDigest != sourceDigest || prepared.InputDigest != "sha256:"+hex.EncodeToString(inputHash[:]) || !json.Valid(prepared.CanonicalInputJSON) {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation integrity failure", ExitIntegrity)
	}
	exit := ExitOK
	switch prepared.State {
	case cncfprepare.StatePrepared:
	case cncfprepare.StateUnknown:
		exit = ExitUnknown
	default:
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return r.fail("CNCF preparation integrity failure", ExitIntegrity)
	}
	if *format == "input" {
		if _, err := r.stdout.Write(prepared.CanonicalInputJSON); err != nil {
			if concreteCNCFPreparationProject(*project) {
				return r.concretePreparationIntegrityFailure(*project)
			}
			return ExitIntegrity
		}
		return exit
	}
	if *format == "json" {
		envelope := struct {
			Schema         string          `json:"schema"`
			Project        string          `json:"project"`
			Authority      string          `json:"authority"`
			State          string          `json:"state"`
			Reason         string          `json:"reason"`
			SourceDigest   string          `json:"sourceDigest"`
			InputDigest    string          `json:"inputDigest"`
			NetworkUsed    bool            `json:"networkUsed"`
			CheckPerformed bool            `json:"checkPerformed"`
			Omissions      []string        `json:"omissions"`
			Input          json.RawMessage `json:"input"`
		}{"prufyx.io/local-cncf-preparation/v1alpha1", *project, "LOCAL_PREPARATION_OF_OPERATOR_DECLARATION", prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest, false, false, prepared.Omissions, json.RawMessage(prepared.CanonicalInputJSON)}
		if json.NewEncoder(r.stdout).Encode(envelope) != nil {
			if concreteCNCFPreparationProject(*project) {
				return r.concretePreparationIntegrityFailure(*project)
			}
			return ExitIntegrity
		}
		return exit
	}
	label := *project
	if label == "kyverno" {
		label = "Kyverno"
	} else if label == "linkerd" {
		label = "Linkerd"
	} else if label == "karmada" {
		label = "Karmada"
	} else if label == "argo-cd" {
		label = "Argo CD"
	} else if label == "cilium" {
		label = "Cilium"
	} else if label == "jaeger" {
		label = "Jaeger"
	} else if label == "metallb" {
		label = "MetalLB"
	} else if label == "contour" {
		label = "Contour"
	} else if label == "cloudnativepg" {
		label = "CloudNativePG"
	} else if label == "kubevirt" {
		label = "KubeVirt"
	} else if label == "emissary-ingress" {
		label = "Emissary-Ingress"
	} else if label == "harbor" {
		label = "Harbor"
	} else if label == "openfga" {
		label = "OpenFGA"
	} else if label == "opencost" {
		label = "OpenCost"
	} else if label == "cloud-custodian" {
		label = "Cloud Custodian"
	} else if label == "fluentd" {
		label = "Fluentd"
	} else if label == "distribution" {
		label = "Distribution"
	} else if label == "container-network-interface-cni" {
		label = "CNI specification"
	}
	if _, err := fmt.Fprintf(r.stdout, "%s declaration preparation: %s\nreason: %s\nsource digest: %s\nprepared input digest: %s\nnetwork used: false\nupgrade check performed: false\n", label, prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest); err != nil {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return ExitIntegrity
	}
	if concreteCNCFPreparationProject(*project) {
		if _, err := fmt.Fprintf(r.stdout, "omissions: %s\n", strings.Join(prepared.Omissions, ", ")); err != nil {
			return r.concretePreparationIntegrityFailure(*project)
		}
	}
	if exit == ExitUnknown {
		if *project == "kyverno" {
			_, err = fmt.Fprintln(r.stdout, "next action: supply an explicit distribution and inspect the selected literal reports-controller invocation locally; keep unresolved facts UNKNOWN")
		} else {
			_, err = fmt.Fprintln(r.stdout, "next action: inspect the selected private declaration locally, provide any missing guard or fact, and keep unresolved facts UNKNOWN")
		}
	} else {
		_, err = fmt.Fprintln(r.stdout, "next action: inspect --format json, then save --format input privately and run check cncf at the current UTC time")
	}
	if err != nil {
		if concreteCNCFPreparationProject(*project) {
			return r.concretePreparationIntegrityFailure(*project)
		}
		return ExitIntegrity
	}
	return exit
}

func concreteCNCFPreparationProject(project string) bool {
	return project == "linkerd" || project == "karmada" || project == "argo-cd" || project == "cilium" || project == "jaeger" || project == "metallb" || project == "contour" || project == "cloudnativepg" || project == "kubevirt" || project == "emissary-ingress" || project == "harbor" || project == "openfga" || project == "opencost" || project == "cloud-custodian" || project == "fluentd" || project == "distribution" || project == "container-network-interface-cni"
}

func cncfOptionProvided(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--") && strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)[0] == wanted {
			return true
		}
	}
	return false
}

func (r runtime) linkerdInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.linkerdIntegrityFailure()
	}
	return r.fail("LINKERD_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) karmadaInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.karmadaIntegrityFailure()
	}
	return r.fail("KARMADA_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) concretePreparationIntegrityFailure(project string) int {
	if project == "cloud-custodian" {
		return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
	}
	if project == "karmada" {
		return r.karmadaIntegrityFailure()
	}
	if project == "argo-cd" {
		return r.argoCDIntegrityFailure()
	}
	return r.linkerdIntegrityFailure()
}

func (r runtime) karmadaIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) linkerdIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) argoCDInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.argoCDIntegrityFailure()
	}
	return r.fail("ARGO_CD_PREPARATION_INPUT_INVALID", ExitUsage)
}

func (r runtime) argoCDIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

func (r runtime) jaegerInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
	}
	return r.fail("JAEGER_PREPARATION_INPUT_INVALID", ExitUsage)
}
