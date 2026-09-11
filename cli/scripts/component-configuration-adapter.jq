# Input is one Kubernetes workload-list response.  Only the `images` result
# contains the already-approved image observation fields.  `configuration`
# contains canonical public identities and registered scalar predicates only;
# command/argument values never cross this filter's output boundary.

def podspec:
  if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
  elif .kind == "ReplicationController" then .spec.template.spec
  else .spec.template.spec
  end;

def public_identity:
  sub("@sha256:[0-9a-fA-F]{64}$"; "")
  | if startswith("docker.io/") then .[10:]
    elif startswith("index.docker.io/") then .[17:]
    else .
    end
  | sub(":([^/:]+)$"; "");

def public_version:
  if test("@sha256:[0-9a-fA-F]{64}$") then null
  else
    ((capture(":(?<version>[^/:]+)$")? | .version) // null)
    | if type == "string" and length <= 128 and test("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$") then . else null end
  end;

def public_version_scheme:
  if test("@sha256:[0-9a-fA-F]{64}$") then "digest"
  elif (public_version != null) then "tag"
  else "unknown"
  end;

# Component-configuration mode passes this explicit negotiation bit because
# the adapter's historical image projection contains raw refs.  Missing or
# false preserves the v1 image projection byte-for-byte; true emits no raw
# image refs at all while retaining publicImages/configuration/omissions.
def safe_output_requested:
  ((($ARGS.named.safeOutput // "false") | tostring) == "true");

def cert_role_predicate($identity):
  if $identity | test("(^|/)cert-manager-controller$") then {id: "component.cert_manager.controller_present", value: true}
  elif $identity | test("(^|/)cert-manager-webhook$") then {id: "component.cert_manager.webhook_present", value: true}
  elif $identity | test("(^|/)cert-manager-cainjector$") then {id: "component.cert_manager.cainjector_present", value: true}
  elif $identity | test("(^|/)cert-manager-startupapicheck$") then {id: "component.cert_manager.startupapicheck_present", value: true}
  else empty
  end;

# Declared-container context is deliberately version-gated. Legacy/absent v1
# requests emit no roles. Explicit v2 may emit only the closed, registry-bound
# declared role and evidence class for an exact public image identity. This is
# not runtime process identity: command overrides, shared images, and missing
# registry bindings remain UNKNOWN, and no raw command, args, image, container,
# or workload identity crosses the output boundary.
def role_evidence_option($name):
  if (($ARGS.named | has($name)) | not) then
    {state: "absent"}
  else
    $ARGS.named[$name] as $value
    | if $name == "roleEvidenceVersion" then
        if ($value | type) == "string" and ($value == "v1" or $value == "v2") then {state: $value}
        elif ($value | type) == "string" then {state: "unsupported"}
        else {state: "malformed"}
        end
      elif ($value | type) == "boolean" then
        if $value then {state: "enabled"} else {state: "disabled"} end
      elif ($value | type) == "string" and ($value == "v1" or $value == "v2") then
        {state: $value}
      elif ($value | type) == "string" then
        {state: "unsupported"}
      else
        {state: "malformed"}
      end
  end;

def role_evidence_selection:
  [
    role_evidence_option("roleEvidenceVersion"),
    role_evidence_option("emitRoleEvidence"),
    role_evidence_option("roleEvidence")
  ] as $options
  | if any($options[]; .state == "malformed" or .state == "enabled" or .state == "unsupported") then "unsupported"
    elif ([$options[] | select(.state != "absent") | .state] | unique | length) > 1 then "unsupported"
    elif any($options[]; .state == "v2") then "v2"
    else "legacy"
    end;

def valid_args($container):
  if ($container | has("args") | not) then {state: "unavailable", values: []}
  elif ($container.args | type) != "array" or ($container.args | length) > 256 then {state: "malformed", values: []}
  elif any($container.args[]?; type != "string" or length > 512 or test("[\u0000\r\n]")) then {state: "malformed", values: []}
  else {state: "observed", values: $container.args}
  end;

def feature_gate_value($text; $name):
  if ($text | type) != "string" or ($text | length) == 0 or ($text | length) > 4096 then
    {state: "malformed"}
  elif any(($text | split(","))[]; (type != "string" or test("^[A-Za-z][A-Za-z0-9]{1,127}=(?:true|false)$") | not)) then
    {state: "malformed"}
  else
    [($text | split(","))[] | capture("^(?<name>[A-Za-z][A-Za-z0-9]{1,127})=(?<value>true|false)$") | select(.name == $name) | {state: "observed", value: (.value == "true")}] as $matches
    | if ($matches | length) == 0 then {state: "absent"}
      elif ([ $matches[] | .value ] | unique | length) > 1 then {state: "conflict"}
      else $matches[0]
      end
  end;

def dns1123_namespace:
  type == "string" and
  length >= 1 and
  length <= 63 and
  test("^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$");

def flag_match($args; $rule):
  if $rule.valueKind == "featureGate" then
    [range(0; ($args | length)) as $i
     | ($args[$i]) as $token
     | if $token == ($rule.flags[0]) then
         if ($i + 1 >= ($args | length) or ($args[$i + 1] | startswith("--"))) then
           {state: "malformed"}
         else feature_gate_value($args[$i + 1]; $rule.featureGate)
         end
       elif ($token | type) == "string" and ($token | startswith(($rule.flags[0]) + "=")) then
         feature_gate_value($token[($rule.flags[0] | length) + 1:]; $rule.featureGate)
       else empty
       end]
  else
  [range(0; ($args | length)) as $i
   | ($args[$i]) as $token
     | if $token == ($rule.flags[0]) then
       if $rule.valueKind == "presence" then
         if $rule.id == "component.argo_workflows.managed_namespace_configured" and role_evidence_selection == "v2" then
           if ($i + 1 < ($args | length) and ($args[$i + 1] | dns1123_namespace)) then
             {state: "observed", value: true, comparison: $args[$i + 1]}
           else
             {state: "malformed"}
           end
         elif ($i + 1 < ($args | length) and (($args[$i + 1] | type) != "string" or ($args[$i + 1] | startswith("--") | not))) then
           {state: "malformed"}
         else
           {state: "observed", value: true}
         end
       elif ($i + 1 >= ($args | length) or ($args[$i + 1] | startswith("--"))) then
         {state: "observed", value: true}
       elif $rule.valueKind == "boolean" and (($args[$i + 1] == "true") or ($args[$i + 1] == "false")) then
         {state: "observed", value: ($args[$i + 1] == "true")}
       elif $rule.valueKind == "enum" and (($rule.allowedValues | index($args[$i + 1])) != null) then
         {state: "observed", value: $args[$i + 1]}
       else
         {state: "malformed"}
       end
     elif ($token | type) == "string" and ($token | startswith(($rule.flags[0]) + "=")) then
       ($token[($rule.flags[0] | length) + 1:]) as $inline
       | if $rule.valueKind == "presence" then
           if $rule.id == "component.argo_workflows.managed_namespace_configured" and role_evidence_selection == "v2" and ($inline | dns1123_namespace) then
             {state: "observed", value: true, comparison: $inline}
           else
             {state: "malformed"}
           end
         elif $rule.valueKind == "boolean" and (($inline == "true") or ($inline == "false")) then
           {state: "observed", value: ($inline == "true")}
         elif $rule.valueKind == "enum" and (($rule.allowedValues | index($inline)) != null) then
           {state: "observed", value: $inline}
         else
           {state: "malformed"}
         end
     else empty
     end]
  end;

def summarize_rule($args; $rule):
  (flag_match($args; $rule)) as $matches
  | if any($matches[]?; .state == "malformed") then {state: "malformed"}
    elif ($matches | length) == 0 then {state: "absent"}
    elif all($matches[]?; .state == "absent") then {state: "absent"}
    elif any($matches[]?; .state == "conflict") then {state: "conflict"}
    elif ([ $matches[] | (.comparison // (.value | tostring)) ] | unique | length) > 1 then {state: "conflict"}
    else {state: "observed", value: $matches[0].value}
    end;

if (type != "object" or (.items | type) != "array" or (.items | length) > 50000) then
  error("invalid or excessive workload response")
elif role_evidence_selection == "unsupported" then
  error("unsupported process-role evidence version")
else
  ([ .items[] as $workload
    | ($workload | podspec) as $podspec
    | if ($podspec | type) != "object" then error("missing workload Pod template")
      elif (($podspec.containers // []) | type) != "array" or (($podspec.initContainers // []) | type) != "array" then error("invalid workload container arrays")
      elif (($podspec.containers // []) | length) == 0 and (($podspec.initContainers // []) | length) > 0 then
        {code: "COMPONENT_CONFIGURATION_NO_REGULAR_CONTAINERS", reason: "Only initContainers were present; init containers are never an effective reviewed component workload.", requiredForEvaluation: true}
      else empty
      end
  ]) as $workloadOmissions
  | [ .items[] as $workload
    | if (($workload.kind | type) != "string" or ($workload.kind | length) == 0) then
        error("invalid workload kind")
      elif ($workload.kind == "ReplicationController" and ($workload.spec.template == null)) then
        empty
      else
        ($workload | podspec) as $podspec
        | if ($podspec | type) != "object" then error("missing workload Pod template")
          elif (($podspec.containers // []) | type) != "array" or (($podspec.initContainers // []) | type) != "array" then
            error("invalid workload container arrays")
          else
            ($podspec.containers // [])[] as $container
            | if (($container.image | type) != "string" or ($container.image | length) == 0 or ($container.image | test("[\u0000\r\n]"))) then
                error("invalid workload image")
              else
                {workloadKind: $workload.kind, image: $container.image, container: $container}
              end
          end
      end
  ] as $containers
  | {
      images: (if safe_output_requested then [] else
        ($containers
          | map({workloadKind, image})
          | sort_by([.workloadKind, .image])
          | group_by(.)
          | map({identity: .[0], declaredContainerCount: length}))
        end),
      publicImages: ($containers
        | map(
            . as $record
            | ($record.image | public_identity) as $identity
            | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0]) as $adapter
            | if $adapter == null or (($adapter.workloadKinds | index($record.workloadKind)) == null) then empty
              else {
                componentId: $adapter.componentId,
                observedVersion: ($record.image | public_version),
                versionScheme: ($record.image | public_version_scheme),
                observationState: "active",
                observationCount: 1,
                versionConflict: false
              }
              end
          )
        | sort_by([.componentId, (.observedVersion // ""), .versionScheme])),
      configuration: ($containers | map(
        . as $record
        | ($record.image
          | sub("@sha256:[0-9a-fA-F]{64}$"; "")
          | if startswith("docker.io/") then .[10:]
            elif startswith("index.docker.io/") then .[17:]
            else .
            end
          | sub(":([^/:]+)$"; "")) as $identity
        | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0]) as $adapter
        | if $adapter == null then
            {row: null, omission: {code: "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED", reason: "No exact public adapter identity matched the workload image.", requiredForEvaluation: true}}
          elif (($adapter.workloadKinds | index($record.workloadKind)) == null) then
            {row: null, omission: {code: "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED", reason: "The workload kind is not an approved controller role for this component adapter.", requiredForEvaluation: true}}
          elif ($record.container | has("command")) then
            {row: null, omission: {code: "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE", reason: "The workload declares a command override whose semantics are not inspected by this bounded adapter.", requiredForEvaluation: true}}
          else
            (valid_args($record.container)) as $args
            | if $args.state == "unavailable" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE", reason: "The workload did not declare an argument array for the approved adapter.", requiredForEvaluation: true}}
              elif $args.state == "malformed" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_ARGS_MALFORMED", reason: "The workload argument surface was malformed or exceeded the local bound.", requiredForEvaluation: true}}
              elif ($record.image | public_version_scheme) == "unknown" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_VERSION_UNRESOLVED", reason: "The approved public identity did not carry a strict release-version tag or digest pin.", requiredForEvaluation: true}}
              else
                ([ $adapter.predicates[] as $rule
                   | summarize_rule($args.values; $rule) as $summary
                   | if $summary.state == "observed" then {id: $rule.id, value: $summary.value}
                     elif $summary.state == "conflict" then {conflict: true}
                     elif $summary.state == "malformed" then {malformed: true}
                     else empty
                     end ]) as $results
                | (($record.image
                    | sub("@sha256:[0-9a-fA-F]{64}$"; "")
                    | if startswith("docker.io/") then .[10:]
                      elif startswith("index.docker.io/") then .[17:]
                      else . end
                    | sub(":([^/:]+)$"; "")) as $normalizedIdentity
                   | ([cert_role_predicate($normalizedIdentity)])) as $roleResults
                | ($results + $roleResults) as $allResults
                | if any($allResults[]?; .malformed == true) then
                    {row: null, omission: {code: "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED", reason: "A registered component predicate had an invalid or disallowed value.", requiredForEvaluation: true}}
                  elif any($allResults[]?; .conflict == true) then
                    {row: null, omission: {code: "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT", reason: "Duplicate arguments disagreed for a registered component predicate.", requiredForEvaluation: true}}
                  elif ($allResults | map(select(.id != null)) | length) == 0 then
                    {row: null, omission: {code: "COMPONENT_CONFIGURATION_PREDICATE_UNOBSERVED", reason: "No registered component predicate was explicitly observed.", requiredForEvaluation: true}}
                  else
                    {row: ({componentId: $adapter.componentId, observedVersion: ($record.image | public_version), versionScheme: ($record.image | public_version_scheme), versionConflict: false, observationState: "observed", observationCount: 1, predicates: (reduce ($allResults[] | select(.id != null)) as $item ({}; .[$item.id] = $item.value))}
                      + (if role_evidence_selection == "v2" and ($adapter.declaredRole | type) == "string" and ($adapter.roleEvidenceClass | type) == "string" then
                          {roles: [$adapter.declaredRole], predicateEvidence: [($allResults[] | select(.id != null) | {predicateId: .id, state: "observed", sourceRole: $adapter.declaredRole, evidenceClass: $adapter.roleEvidenceClass})]}
                        else {} end)), omission: null}
                  end
              end
          end
      ) | map(select(.row != null) | .row)),
      omissions: ($workloadOmissions + ($containers | map(
        . as $record
        | ($record.image | sub("@sha256:[0-9a-fA-F]{64}$"; "") | if startswith("docker.io/") then .[10:] elif startswith("index.docker.io/") then .[17:] else . end | sub(":([^/:]+)$"; "")) as $identity
        | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0]) as $adapter
        | if $adapter == null then {code: "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED", reason: "No exact public adapter identity matched the workload image.", requiredForEvaluation: true}
          elif (($adapter.workloadKinds | index($record.workloadKind)) == null) then {code: "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED", reason: "The workload kind is not an approved controller role for this component adapter.", requiredForEvaluation: true}
          elif (($record.image | public_version_scheme) == "unknown") then {code: "COMPONENT_CONFIGURATION_VERSION_UNRESOLVED", reason: "The approved public identity did not carry a strict release-version tag or digest pin.", requiredForEvaluation: true}
          elif ($record.container | has("command")) then {code: "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE", reason: "The workload declares a command override whose semantics are not inspected by this bounded adapter.", requiredForEvaluation: true}
          else (valid_args($record.container)) as $args
          | if $args.state == "unavailable" then {code: "COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE", reason: "The workload did not declare an argument array for the approved adapter.", requiredForEvaluation: true}
            elif $args.state == "malformed" then {code: "COMPONENT_CONFIGURATION_ARGS_MALFORMED", reason: "The workload argument surface was malformed or exceeded the local bound.", requiredForEvaluation: true}
            else ([ $adapter.predicates[] as $rule | summarize_rule($args.values; $rule) ] ) as $summaries
            | if any($summaries[]?; .state == "malformed") then {code: "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED", reason: "A registered component predicate had an invalid or disallowed value.", requiredForEvaluation: true}
              elif any($summaries[]?; .state == "conflict") then {code: "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT", reason: "Duplicate arguments disagreed for a registered component predicate.", requiredForEvaluation: true}
              elif all($summaries[]?; .state == "absent") then {code: "COMPONENT_CONFIGURATION_PREDICATE_UNOBSERVED", reason: "No registered component predicate was explicitly observed.", requiredForEvaluation: true}
              elif role_evidence_selection == "v2" and (($adapter.declaredRole | type) != "string" or ($adapter.roleEvidenceClass | type) != "string") then {code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_UNAVAILABLE", reason: "The exact public image identity has no approved declared-container role binding; role-bound context remains unknown.", requiredForEvaluation: true}
              else empty
              end
            end
          end
      ))),
      version: "v1"
    }
end
