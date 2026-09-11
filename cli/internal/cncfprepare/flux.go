package cncfprepare

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Flux 2.7 removes five beta API versions from its CRDs. This adapter examines
// only a caller-selected proposed rendered-resource JSON document. It does not
// inspect stored versions, a cluster inventory, reconciliation, or runtime.
const (
	FluxComponent = "pkg:github/fluxcd/flux2"
	FluxFact      = "component.flux.removed_beta_api_present"
	FluxFrom      = "2.6.4"
	FluxTo        = "2.7.0"
)

const (
	ReasonFluxRemovedAPIWitness   Reason = "FLUX_REMOVED_BETA_API_PRESENT"
	ReasonFluxSelectedSetClear    Reason = "FLUX_SELECTED_RESOURCE_SET_CLEAR"
	ReasonFluxResourceUnsupported Reason = "FLUX_NATIVE_RESOURCE_SET_UNSUPPORTED"
	ReasonFluxPagination          Reason = "FLUX_RESOURCE_LIST_PAGINATION_UNRESOLVED"
	ReasonFluxScopeIncomplete     Reason = "FLUX_SELECTED_RESOURCE_SCOPE_INCOMPLETE"
)

// PrepareFlux derives the existing Flux fact from one selected JSON object or
// a v1 List. A positive removed-API witness is conclusive for that supplied
// resource even when the caller has not declared the selected set complete.
// A clear result requires a nonempty complete selected set with no pagination.
func PrepareFlux(raw []byte, from, to string, selectedScopeComplete bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	removed, completeShape, paginated := fluxRemovedAPI(value)
	fact := inputFact{ID: FluxFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonFluxResourceUnsupported
	if removed {
		value := true
		fact = inputFact{ID: FluxFact, State: "declared", BoolValue: &value}
		state, reason = StatePrepared, ReasonFluxRemovedAPIWitness
	} else if completeShape && selectedScopeComplete && !paginated {
		value := false
		fact = inputFact{ID: FluxFact, State: "declared", BoolValue: &value}
		state, reason = StatePrepared, ReasonFluxSelectedSetClear
	} else if completeShape && paginated {
		reason = ReasonFluxPagination
	} else if completeShape {
		reason = ReasonFluxScopeIncomplete
	}
	canonical, err := marshalComponentInput(FluxComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"SELECTED_RENDERED_RESOURCE_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"STORED_CRD_VERSIONS_CLUSTER_INVENTORY_RECONCILIATION_AND_RUNTIME_NOT_EVALUATED",
		},
	}, nil
}

func fluxRemovedAPI(value any) (removed, completeShape, paginated bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false, false
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	if !apiOK || !fluxIdentity(api) || !kindOK || !fluxIdentity(kind) {
		return false, false, false
	}
	if api == "v1" && kind == "List" {
		if metadata, exists := root["metadata"]; exists {
			if _, ok := metadata.(map[string]any); !ok {
				return false, false, false
			}
		}
		items, ok := root["items"].([]any)
		if !ok || len(items) == 0 {
			return false, false, fluxListPaginated(root)
		}
		paginated = fluxListPaginated(root)
		for _, item := range items {
			itemRemoved, itemOK := fluxResourceAPI(item)
			if !itemOK {
				return false, false, false
			}
			removed = removed || itemRemoved
		}
		return removed, true, paginated
	}
	removed, ok = fluxResourceAPI(root)
	return removed, ok, false
}

func fluxResourceAPI(value any) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return false, false
	}
	api, apiOK := root["apiVersion"].(string)
	kind, kindOK := root["kind"].(string)
	metadata, metadataOK := root["metadata"].(map[string]any)
	if !apiOK || !fluxIdentity(api) || !kindOK || !fluxIdentity(kind) || strings.HasSuffix(strings.ToLower(kind), "list") || !metadataOK || !fluxIdentityString(metadata["name"]) {
		return false, false
	}
	if _, exists := root["items"]; exists {
		return false, false
	}
	return oneOf(api,
		"source.toolkit.fluxcd.io/v1beta1",
		"kustomize.toolkit.fluxcd.io/v1beta1",
		"helm.toolkit.fluxcd.io/v2beta1",
		"image.toolkit.fluxcd.io/v1beta1",
		"notification.toolkit.fluxcd.io/v1beta1",
	), true
}

// fluxIdentity keeps this adapter short of schema validation while rejecting
// whitespace and control-bearing identity values that cannot safely establish
// an absence result from a caller-selected resource.
func fluxIdentity(value string) bool {
	return value != "" && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func fluxIdentityString(value any) bool {
	text, ok := value.(string)
	return ok && fluxIdentity(text)
}

func fluxListPaginated(root map[string]any) bool {
	metadata, ok := root["metadata"].(map[string]any)
	if !ok {
		return false
	}
	if continueToken, exists := metadata["continue"]; exists {
		value, ok := continueToken.(string)
		if !ok || value != "" {
			return true
		}
	}
	if remaining, exists := metadata["remainingItemCount"]; exists {
		number, ok := remaining.(json.Number)
		if !ok {
			return true
		}
		value, err := number.Int64()
		if err != nil || value < 0 || value > 0 {
			return true
		}
	}
	return false
}
