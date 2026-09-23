package cncfprepare

import (
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	ReasonKubernetesRemovedGVKPresent    Reason = "KUBERNETES_REMOVED_GVK_PRESENT"
	ReasonKubernetesRemovedGVKAbsent     Reason = "KUBERNETES_REMOVED_GVK_ABSENT"
	ReasonKubernetesGVKVersionUnreviewed Reason = "KUBERNETES_GVK_VERSION_UNREVIEWED"
)

// kubernetesRemoval is one reviewed API removal: the named kinds in Group stop
// being served at Removed when a cluster moves to the target release. Served
// lists the versions of the same group and kinds that the cited source names as
// still served at that target. A document of one of these kinds in any other
// version cannot establish the fact either way, so the fact stays unsupported.
type kubernetesRemoval struct {
	Fact    string
	Group   string
	Kinds   []string
	Removed string
	Served  []string
}

// kubernetesRemovalsByTransition maps an exact from/to pair to the reviewed
// removals that apply to it. The 1.31.0 -> 1.32.0 pair is handled by
// PrepareKubernetesFlowControl and deliberately absent here.
var kubernetesRemovalsByTransition = map[[2]string][]kubernetesRemoval{
	{"1.28.0", "1.29.0"}: {
		{Fact: "component.kubernetes.flowcontrol_v1beta2_removed_gvk_present", Group: "flowcontrol.apiserver.k8s.io", Kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}, Removed: "v1beta2", Served: []string{"v1", "v1beta3"}},
	},
	{"1.26.0", "1.27.0"}: {
		{Fact: "component.kubernetes.csistoragecapacity_v1beta1_removed_gvk_present", Group: "storage.k8s.io", Kinds: []string{"CSIStorageCapacity"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	{"1.25.0", "1.26.0"}: {
		{Fact: "component.kubernetes.flowcontrol_v1beta1_removed_gvk_present", Group: "flowcontrol.apiserver.k8s.io", Kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}, Removed: "v1beta1", Served: []string{"v1beta2", "v1beta3"}},
		{Fact: "component.kubernetes.hpa_v2beta2_removed_gvk_present", Group: "autoscaling", Kinds: []string{"HorizontalPodAutoscaler"}, Removed: "v2beta2", Served: []string{"v2"}},
	},
	{"1.24.0", "1.25.0"}: {
		{Fact: "component.kubernetes.cronjob_v1beta1_removed_gvk_present", Group: "batch", Kinds: []string{"CronJob"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.endpointslice_v1beta1_removed_gvk_present", Group: "discovery.k8s.io", Kinds: []string{"EndpointSlice"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.event_v1beta1_removed_gvk_present", Group: "events.k8s.io", Kinds: []string{"Event"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.hpa_v2beta1_removed_gvk_present", Group: "autoscaling", Kinds: []string{"HorizontalPodAutoscaler"}, Removed: "v2beta1", Served: []string{"v2"}},
		{Fact: "component.kubernetes.pdb_v1beta1_removed_gvk_present", Group: "policy", Kinds: []string{"PodDisruptionBudget"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.psp_v1beta1_removed_gvk_present", Group: "policy", Kinds: []string{"PodSecurityPolicy"}, Removed: "v1beta1", Served: nil},
		{Fact: "component.kubernetes.runtimeclass_v1beta1_removed_gvk_present", Group: "node.k8s.io", Kinds: []string{"RuntimeClass"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
}

// KubernetesRemovedAPIFacts returns the fact IDs this adapter can derive for an
// exact transition, in table order. It is empty for any pair without reviewed
// removals.
func KubernetesRemovedAPIFacts(from, to string) []string {
	removals := kubernetesRemovalsByTransition[[2]string{from, to}]
	facts := make([]string, 0, len(removals))
	for _, removal := range removals {
		facts = append(facts, removal.Fact)
	}
	return facts
}

// PrepareKubernetesRemovedAPIs converts a bounded caller-selected rendered apply
// set to one canonical fact per reviewed API removal for the exact transition.
// It never reads a cluster. Pairs without a reviewed removal table, including
// 1.31.0 -> 1.32.0, keep the established flow-control behaviour unchanged.
func PrepareKubernetesRemovedAPIs(raw []byte, from, to, distribution string, targetApplyRequired, complete bool) (Prepared, error) {
	removals, reviewed := kubernetesRemovalsByTransition[[2]string{from, to}]
	if !reviewed {
		return PrepareKubernetesFlowControl(raw, from, to, distribution, targetApplyRequired, complete)
	}
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	unsupported := func() []inputFact {
		facts := make([]inputFact, 0, len(removals))
		for _, removal := range removals {
			facts = append(facts, inputFact{ID: removal.Fact, State: "unsupported"})
		}
		return facts
	}
	if !targetApplyRequired || distribution != "official_upstream" {
		return kubernetesRemovedPrepared(raw, from, to, unsupported(), StateUnknown, ReasonKubernetesTargetGuard)
	}
	documents, paginated, reason, err := kubernetesApplySetDocuments(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	if reason != "" {
		return kubernetesRemovedPrepared(raw, from, to, unsupported(), StateUnknown, reason)
	}
	if !complete {
		return kubernetesRemovedPrepared(raw, from, to, unsupported(), StateUnknown, ReasonKubernetesScopeIncomplete)
	}
	if paginated {
		return kubernetesRemovedPrepared(raw, from, to, unsupported(), StateUnknown, ReasonKubernetesPagination)
	}

	facts := make([]inputFact, 0, len(removals))
	anyPresent, anyUnreviewed := false, false
	for _, removal := range removals {
		present, unreviewed := classifyKubernetesRemoval(documents, removal)
		switch {
		case unreviewed:
			anyUnreviewed = true
			facts = append(facts, inputFact{ID: removal.Fact, State: "unsupported"})
		case present:
			anyPresent = true
			v := true
			facts = append(facts, inputFact{ID: removal.Fact, State: "declared", BoolValue: &v})
		default:
			v := false
			facts = append(facts, inputFact{ID: removal.Fact, State: "declared", BoolValue: &v})
		}
	}
	// A present removed GVK is the decisive signal and is reported even when
	// another fact in the same set is undecidable; the undecidable fact still
	// keeps the overall state UNKNOWN.
	state, overall := StatePrepared, ReasonKubernetesRemovedGVKAbsent
	if anyUnreviewed {
		state, overall = StateUnknown, ReasonKubernetesGVKVersionUnreviewed
	}
	if anyPresent {
		overall = ReasonKubernetesRemovedGVKPresent
	}
	return kubernetesRemovedPrepared(raw, from, to, facts, state, overall)
}

// classifyKubernetesRemoval reports whether the removed GVK is present, and
// whether a document of the same group and kind carries a version the cited
// source does not name, which makes this one fact undecidable.
func classifyKubernetesRemoval(documents []map[string]any, removal kubernetesRemoval) (present, unreviewed bool) {
	for _, document := range documents {
		api, kind, _ := kubernetesGVK(document)
		if !containsString(removal.Kinds, kind) {
			continue
		}
		group, version, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != removal.Group {
			continue
		}
		switch {
		case version == removal.Removed:
			present = true
		case containsString(removal.Served, version):
		default:
			unreviewed = true
		}
	}
	return present, unreviewed
}

// kubernetesApplySetDocuments applies the same bounded shape rules as the
// flow-control adapter: one document or one flat core v1 List, no templating,
// no typed or nested lists. A non-empty reason means the set is unresolved.
func kubernetesApplySetDocuments(raw []byte) ([]map[string]any, bool, Reason, error) {
	if strings.Contains(string(raw), "{{") || strings.Contains(string(raw), "${") {
		return nil, false, ReasonKubernetesTemplated, nil
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return nil, false, "", err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false, ReasonKubernetesUnresolved, nil
	}
	api, kind, ok := kubernetesGVK(root)
	if !ok {
		return nil, false, ReasonKubernetesUnresolved, nil
	}
	if kind != "List" {
		if strings.HasSuffix(kind, "List") {
			return nil, false, ReasonKubernetesUnresolved, nil
		}
		return []map[string]any{root}, false, "", nil
	}
	if api != "v1" {
		return nil, false, ReasonKubernetesUnresolved, nil
	}
	items, found := root["items"].([]any)
	if !found || len(items) == 0 {
		return nil, false, ReasonKubernetesUnresolved, nil
	}
	paginated, metadataOK := kubernetesListPagination(root)
	if !metadataOK {
		return nil, false, ReasonKubernetesUnresolved, nil
	}
	documents := make([]map[string]any, 0, len(items))
	for _, item := range items {
		document, ok := item.(map[string]any)
		if !ok {
			return nil, false, ReasonKubernetesUnresolved, nil
		}
		_, itemKind, ok := kubernetesGVK(document)
		if !ok || itemKind == "List" || strings.HasSuffix(itemKind, "List") {
			return nil, false, ReasonKubernetesUnresolved, nil
		}
		documents = append(documents, document)
	}
	return documents, paginated, "", nil
}

func kubernetesRemovedPrepared(raw []byte, from, to string, facts []inputFact, state State, reason Reason) (Prepared, error) {
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	// Sort by fact ID so the canonical input does not depend on table order.
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	canonical, err := marshalComponentInput(KubernetesComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"SELECTED_RENDERED_APPLY_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION", "CLUSTER_OBJECTS_CRDS_RUNTIME_CLIENTS_AND_STORAGE_VERSIONS_NOT_EVALUATED"}}, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
