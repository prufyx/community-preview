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

def declared_image_tag:
  (split("@sha256:")[0])
  | ((capture(":(?<version>[^/:]+)$")? | .version) // null)
  | if type == "string" and test("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$") then sub("^v"; "") else null end;

def declared_image_tag_raw:
  (split("@sha256:")[0])
  | ((capture(":(?<version>[^/:]+)$")? | .version) // null);

def declared_image_digest:
  ((capture("@(?<digest>sha256:[0-9a-f]{64})$")? | .digest) // null);

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
# requests emit no roles. Explicit v2 preserves the image/args-only contract.
# Explicit v3 additionally admits only source-bound entrypoints and exact
# declared command arrays from registry v3. This is not runtime process
# identity: wrappers, shared roles, init-container ambiguity, unsupported
# versions, and missing bindings remain UNKNOWN. No raw command, args, image,
# container, or workload identity crosses the output boundary.
def role_evidence_option($name):
  if (($ARGS.named | has($name)) | not) then
    {state: "absent"}
  else
    $ARGS.named[$name] as $value
    | if $name == "roleEvidenceVersion" then
        if ($value | type) == "string" and ($value == "v1" or $value == "v2" or $value == "v3") then {state: $value}
        elif ($value | type) == "string" then {state: "unsupported"}
        else {state: "malformed"}
        end
      elif ($value | type) == "boolean" then
        if $value then {state: "enabled"} else {state: "disabled"} end
      elif ($value | type) == "string" and ($value == "v1" or $value == "v2" or $value == "v3") then
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
    elif any($options[]; .state == "v3") then "v3"
    elif any($options[]; .state == "v2") then "v2"
    else "legacy"
    end;

def declared_context_requested:
  role_evidence_selection == "v2" or role_evidence_selection == "v3";

def valid_args($container):
  if ($container | has("args") | not) then {state: "unavailable", values: []}
  elif ($container.args | type) != "array" or ($container.args | length) > 256 then {state: "malformed", values: []}
  elif any($container.args[]?; type != "string" or (role_evidence_selection == "v3" and utf8bytelength == 0) or (if role_evidence_selection == "v3" then utf8bytelength else length end) > 512 or test("[\u0000\r\n]")) then {state: "malformed", values: []}
  elif role_evidence_selection == "v3" and (($container.args | map(utf8bytelength) | add // 0) > 16384) then {state: "malformed", values: []}
  elif role_evidence_selection == "v3" and any($container.args[]?; . == "--" or contains("$(")) then {state: "malformed", values: []}
  elif role_evidence_selection == "v3" and ([range(0; ($container.args | length)) as $i
    | select(($container.args[$i] | startswith("--") | not) and
      ($i == 0 or ($container.args[$i - 1] | startswith("--") | not) or ($container.args[$i - 1] | contains("=")) or $container.args[$i - 1] == "--agent" or ($container.args[$i - 1] | startswith("--no-agent"))))] | length) > 0 then {state: "malformed", values: []}
  else {state: "observed", values: $container.args}
  end;

def valid_command($container):
  if ($container | has("command") | not) then {state: "absent", values: []}
  elif ($container.command | type) != "array" or ($container.command | length) == 0 or ($container.command | length) > 8 then {state: "malformed", values: []}
  elif any($container.command[]?; type != "string" or length == 0 or (if role_evidence_selection == "v3" then utf8bytelength else length end) > 128 or test("[\u0000\r\n]")) then {state: "malformed", values: []}
  else {state: "observed", values: $container.command}
  end;

def normalized_public_version($image):
  ($image | declared_image_tag);

def adapter_for_image($image):
  ($image | public_identity) as $identity
  | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0] // null);

# The index.docker.io alias is a known public Prometheus repository spelling,
# but it is outside the strict source-bound image contract.  Recognize it only
# when deciding whether another regular or init container makes the declared
# role ambiguous; it must never become an authority-bearing image match.
def adapter_for_participation($image):
  ($image | public_identity) as $identity
  | (if role_evidence_selection == "v3" and $identity == "index.docker.io/prom/prometheus" then "prom/prometheus" else $identity end) as $participationIdentity
  | ([ $registry.adapters[] | select(.identities | index($participationIdentity)) ] | .[0] // null);

def image_binding($image; $adapter):
  ($image | public_identity) as $identity
  | (normalized_public_version($image)) as $version
  | ($image | declared_image_tag_raw) as $rawTag
  | ($image | declared_image_digest) as $digest
  | ([ $adapter.entrypointContract.imageBindings[]? | select(.version == $version) ] | .[0] // null) as $binding
  | if (($adapter.identities | index($identity)) == null) then {state: "unverified_image"}
    elif $version == null and $digest != null then {state: "unverified_image"}
    elif $binding == null then {state: "unsupported_version"}
    elif $rawTag != ("v" + $version) then {state: "unverified_image", version: $version}
    elif $binding.referenceClass == "tag" and $digest == null then {state: "observed", version: $version, binding: $binding}
    elif $binding.referenceClass == "tag_and_platform_digest" and $digest != null and (($binding.platformDigests | index($digest)) != null) then {state: "observed", version: $version, binding: $binding}
    else {state: "unverified_image", version: $version}
    end;

def source_bound_entrypoint($record; $adapter; $containers):
  (valid_command($record.container)) as $command
  | if role_evidence_selection != "v3" then
      if $command.state == "absent" then {state: "observed"} else {state: "unavailable"} end
    elif ($adapter.entrypointContract | type) != "object" then
      if $command.state == "absent" then {state: "observed"} else {state: "unavailable"} end
    else (image_binding($record.image; $adapter)) as $imageBinding
    | if $imageBinding.state != "observed" then $imageBinding
    elif ([ $containers[]
            | select(.workloadIndex == $record.workloadIndex)
            | (adapter_for_participation(.image)) as $candidate
            | select(($candidate.componentId // null) == $adapter.componentId) ] | length) != 1 then
      {state: "ambiguous_role"}
    elif ([ $record.initContainers[]?
            | select((.image | type) == "string")
            | (adapter_for_participation(.image)) as $candidate
            | select(($candidate.componentId // null) == $adapter.componentId) ] | length) > 0 then
      {state: "ambiguous_role"}
    elif $command.state == "malformed" then {state: "malformed"}
    elif $command.state == "absent" and $imageBinding.binding.referenceClass == "tag_and_platform_digest" then
      {state: "observed"}
    elif $command.state == "observed" and any($adapter.entrypointContract.acceptedExplicitCommands[]; . == $command.values) then
      {state: "observed"}
    else {state: "unavailable"}
    end
    end;

def resolved_args($record; $adapter):
  (valid_args($record.container)) as $args
  | if $args.state == "unavailable" and role_evidence_selection == "v3" and $adapter.componentId == "pkg:oci/prometheus/prometheus" then
      (image_binding($record.image; $adapter)) as $binding
      | if $binding.state == "observed"
          and ($binding.binding.defaultPredicateValues | has("component.prometheus.agent_mode"))
          and ($binding.binding.defaultPredicateValues["component.prometheus.agent_mode"] == false) then
          {state: "observed", values: [], source: "reviewed_image_defaults"}
        else $args
        end
    else $args
    end;

def feature_values($args):
  [range(0; ($args | length)) as $i
   | $args[$i] as $token
   | if $token == "--enable-feature" then
       if ($i + 1 >= ($args | length) or ($args[$i + 1] | startswith("--"))) then {state: "malformed"}
       else {state: "observed", value: $args[$i + 1]}
       end
     elif $token | startswith("--enable-feature=") then
       {state: "observed", value: $token[17:]}
     else empty end];

def prometheus_agent_mode($args; $version):
  (feature_values($args)) as $features
  | if any($features[]?; .state == "malformed") then {state: "malformed"}
    elif $version == "2.55.1" then
      if any($args[]; . == "--agent" or startswith("--no-agent") or startswith("--agent=")) then {state: "malformed"}
      else {state: "observed", value: any($features[]?; .state == "observed" and any((.value | split(","))[]; . == "agent"))}
      end
    elif $version == "3.1.0" then
      ([range(0; ($args | length)) as $i
        | select($args[$i] == "--agent")
        | {index: $i, value: $args[$i]}]) as $dedicated
      | if any($args[]; startswith("--no-agent") or (startswith("--agent") and . != "--agent")) then {state: "malformed"}
        elif any($dedicated[]?; .index > 0 and ($args[.index - 1] | startswith("--")) and $args[.index - 1] != "--agent" and ($args[.index - 1] | contains("=") | not)) then {state: "malformed"}
        elif any($dedicated[]?; (.index + 1) < ($args | length) and ($args[.index + 1] | startswith("--") | not)) then {state: "malformed"}
        elif ($dedicated | length) > 1 then {state: "conflict"}
        elif ($dedicated | length) == 1 then {state: "observed", value: true}
        else {state: "observed", value: false}
        end
    else {state: "unsupported"}
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
         if $rule.id == "component.argo_workflows.managed_namespace_configured" and declared_context_requested then
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
           if $rule.id == "component.argo_workflows.managed_namespace_configured" and declared_context_requested and ($inline | dns1123_namespace) then
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

def summarize_rule($args; $rule; $version; $record; $adapter):
  (if $rule.valueKind == "versionedAgentMode" then prometheus_agent_mode($args; $version)
   elif $rule.valueKind == "publicImageDigest" then
     (image_binding($record.image; $adapter)) as $binding
     | if $binding.state == "observed" then {state: "observed", value: ($record.image | declared_image_digest)} else {state: "unsupported"} end
   else
     (flag_match($args; $rule)) as $matches
  | if any($matches[]?; .state == "malformed") then {state: "malformed"}
    elif ($matches | length) == 0 then {state: "absent"}
    elif all($matches[]?; .state == "absent") then {state: "absent"}
    elif any($matches[]?; .state == "conflict") then {state: "conflict"}
    elif ([ $matches[] | (.comparison // (.value | tostring)) ] | unique | length) > 1 then {state: "conflict"}
    else {state: "observed", value: $matches[0].value}
    end
   end);

# Prometheus mode and image digest are one paired declared-controller fact.
# A complete row must not survive merely because another eligible controller
# for the same component failed projection. ReplicaSets and Pods are not
# eligible controller rows and therefore do not participate in this check.
def prometheus_controller_complete($record; $adapter; $containers):
  if (($adapter.workloadKinds | index($record.workloadKind)) == null) then false
  else (source_bound_entrypoint($record; $adapter; $containers)) as $entrypoint
  | if $entrypoint.state != "observed" then false
    else (resolved_args($record; $adapter)) as $args
    | if $args.state != "observed" then false
      else all($adapter.predicates[];
        (summarize_rule($args.values; .; normalized_public_version($record.image); $record; $adapter).state == "observed"))
      end
    end
  end;

def prometheus_component_context_complete($adapter; $containers):
  [ $containers[] as $candidate
    | select(($adapter.workloadKinds | index($candidate.workloadKind)) != null)
    | select((((adapter_for_participation($candidate.image) | .componentId) // null) == $adapter.componentId))
    | $candidate ] as $eligible
  | ($eligible | length) > 0 and all($eligible[]; prometheus_controller_complete(.; $adapter; $containers));

if (type != "object" or (.items | type) != "array" or (.items | length) > 50000) then
  error("invalid or excessive workload response")
elif role_evidence_selection == "unsupported" then
  error("unsupported process-role evidence version")
elif role_evidence_selection == "v3" and ($registry.metadata.registryVersion != "v3" or $registry.metadata.schemaVersion != "1.2.0") then
  error("unsupported process-role evidence version")
else
  ([ .items[] as $workload
    | ($workload | podspec) as $podspec
    | if ($podspec | type) != "object" then error("missing workload Pod template")
      elif (($podspec.containers // []) | type) != "array" or (($podspec.initContainers // []) | type) != "array" then error("invalid workload container arrays")
      elif (($podspec.containers // []) | length) == 0 and (($podspec.initContainers // []) | length) > 0 then
        {code: "COMPONENT_CONFIGURATION_NO_REGULAR_CONTAINERS", reason: "Only initContainers were present; init containers are never an effective reviewed component workload.", requiredForEvaluation: true}
      elif role_evidence_selection == "v3" and (($podspec.containers // []) | length) > 0 and (($podspec.initContainers // []) | length) > 0 then
        {code: "COMPONENT_CONFIGURATION_INIT_CONTAINERS_IGNORED", reason: "Init containers were present but are outside the reviewed effective component configuration surface.", requiredForEvaluation: true}
      else empty
      end
  ]) as $workloadOmissions
  | [ range(0; (.items | length)) as $workloadIndex
    | .items[$workloadIndex] as $workload
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
                {workloadIndex: $workloadIndex, workloadKind: $workload.kind, image: $container.image, container: $container, initContainers: ($podspec.initContainers // [])}
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
            else .
            end
          | sub(":([^/:]+)$"; "")) as $identity
        | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0]) as $adapter
        | if $adapter == null then
            {row: null, omission: {code: "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED", reason: "No exact public adapter identity matched the workload image.", requiredForEvaluation: true}}
          elif role_evidence_selection == "v3" and $adapter.componentId == "pkg:oci/prometheus/prometheus" and ($record.workloadKind == "ReplicaSet" or $record.workloadKind == "Pod") then
            {row: null, omission: null}
          elif (($adapter.workloadKinds | index($record.workloadKind)) == null) then
            {row: null, omission: {code: "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED", reason: "The workload kind is not an approved controller role for this component adapter.", requiredForEvaluation: true}}
          elif role_evidence_selection == "v3" and $adapter.componentId == "pkg:oci/prometheus/prometheus" and (prometheus_component_context_complete($adapter; $containers) | not) then
            {row: {componentId: $adapter.componentId, internalParticipationState: "incomplete"}, omission: {code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", reason: "At least one recognized eligible component controller lacked complete source-bound declared context; no subset is retained.", requiredForEvaluation: true}}
          else (source_bound_entrypoint($record; $adapter; $containers)) as $entrypoint
          | if $entrypoint.state != "observed" then
            {row: null, omission: {code: (if $entrypoint.state == "unsupported_version" then "COMPONENT_CONFIGURATION_ENTRYPOINT_VERSION_UNSUPPORTED" elif $entrypoint.state == "unverified_image" then "COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED" elif $entrypoint.state == "ambiguous_role" then "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS" else "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE" end), reason: (if $entrypoint.state == "unsupported_version" then "The declared command/entrypoint contract is not source-bound for this exact component version." elif $entrypoint.state == "unverified_image" then "The declared image tag and selected platform digest do not match one approved public image binding." elif $entrypoint.state == "ambiguous_role" then "The workload contains multiple candidate component roles across regular or init containers." else "The workload command is not an exact source-bound command admitted by this component profile." end), requiredForEvaluation: true}}
          else
            (resolved_args($record; $adapter)) as $args
            | if $args.state == "unavailable" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE", reason: "The workload did not declare an argument array for the approved adapter.", requiredForEvaluation: true}}
              elif $args.state == "malformed" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_ARGS_MALFORMED", reason: "The workload argument surface was malformed or exceeded the local bound.", requiredForEvaluation: true}}
              elif ($record.image | public_version_scheme) == "unknown" then
                {row: null, omission: {code: "COMPONENT_CONFIGURATION_VERSION_UNRESOLVED", reason: "The approved public identity did not carry a strict release-version tag or digest pin.", requiredForEvaluation: true}}
              else
                ([ $adapter.predicates[] as $rule
                   | summarize_rule($args.values; $rule; normalized_public_version($record.image); $record; $adapter) as $summary
                   | if $summary.state == "observed" then {id: $rule.id, value: $summary.value}
                     elif $summary.state == "conflict" then {conflict: true}
                     elif $summary.state == "malformed" then {malformed: true}
                     else empty
                     end ]) as $results
                | (($record.image
                    | sub("@sha256:[0-9a-fA-F]{64}$"; "")
                    | if startswith("docker.io/") then .[10:]
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
                    {row: ({componentId: $adapter.componentId, observedVersion: (if role_evidence_selection == "v3" and ($adapter.entrypointContract | type) == "object" then normalized_public_version($record.image) else ($record.image | public_version) end), versionScheme: (if role_evidence_selection == "v3" and ($adapter.entrypointContract | type) == "object" then "tag" else ($record.image | public_version_scheme) end), versionConflict: false, observationState: "observed", observationCount: 1, predicates: (reduce ($allResults[] | select(.id != null)) as $item ({}; .[$item.id] = $item.value))}
                      + (if declared_context_requested and ($adapter.declaredRole | type) == "string" and ($adapter.roleEvidenceClass | type) == "string" then
                          {roles: [$adapter.declaredRole], predicateEvidence: [($allResults[] | select(.id != null) | {predicateId: .id, state: "observed", sourceRole: $adapter.declaredRole, evidenceClass: $adapter.roleEvidenceClass})]}
                        else {} end)), omission: null}
                  end
              end
          end
        end
      ) | map(select(.row != null) | .row)),
      omissions: ($workloadOmissions + ($containers | map(
        . as $record
        | ($record.image | sub("@sha256:[0-9a-fA-F]{64}$"; "") | if startswith("docker.io/") then .[10:] else . end | sub(":([^/:]+)$"; "")) as $identity
        | ([ $registry.adapters[] | select(.identities | index($identity)) ] | .[0]) as $adapter
        | if $adapter == null then {code: "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED", reason: "No exact public adapter identity matched the workload image.", requiredForEvaluation: true}
          elif role_evidence_selection == "v3" and $adapter.componentId == "pkg:oci/prometheus/prometheus" and ($record.workloadKind == "ReplicaSet" or $record.workloadKind == "Pod") then empty
          elif (($adapter.workloadKinds | index($record.workloadKind)) == null) then {code: "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED", reason: "The workload kind is not an approved controller role for this component adapter.", requiredForEvaluation: true}
          elif (($record.image | public_version_scheme) == "unknown") then {code: "COMPONENT_CONFIGURATION_VERSION_UNRESOLVED", reason: "The approved public identity did not carry a strict release-version tag or digest pin.", requiredForEvaluation: true}
          else (source_bound_entrypoint($record; $adapter; $containers)) as $entrypoint
          | if $entrypoint.state != "observed" then
              {code: (if $entrypoint.state == "unsupported_version" then "COMPONENT_CONFIGURATION_ENTRYPOINT_VERSION_UNSUPPORTED" elif $entrypoint.state == "unverified_image" then "COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED" elif $entrypoint.state == "ambiguous_role" then "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS" else "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE" end), reason: (if $entrypoint.state == "unsupported_version" then "The declared command/entrypoint contract is not source-bound for this exact component version." elif $entrypoint.state == "unverified_image" then "The declared image tag and selected platform digest do not match one approved public image binding." elif $entrypoint.state == "ambiguous_role" then "The workload contains multiple candidate component roles across regular or init containers." else "The workload command is not an exact source-bound command admitted by this component profile." end), requiredForEvaluation: true}
            else (resolved_args($record; $adapter)) as $args
          | if $args.state == "unavailable" then {code: "COMPONENT_CONFIGURATION_ARGS_UNAVAILABLE", reason: "The workload did not declare an argument array for the approved adapter.", requiredForEvaluation: true}
            elif $args.state == "malformed" then {code: "COMPONENT_CONFIGURATION_ARGS_MALFORMED", reason: "The workload argument surface was malformed or exceeded the local bound.", requiredForEvaluation: true}
            else ([ $adapter.predicates[] as $rule | summarize_rule($args.values; $rule; normalized_public_version($record.image); $record; $adapter) ] ) as $summaries
            | if any($summaries[]?; .state == "malformed") then {code: "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED", reason: "A registered component predicate had an invalid or disallowed value.", requiredForEvaluation: true}
              elif any($summaries[]?; .state == "conflict") then {code: "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT", reason: "Duplicate arguments disagreed for a registered component predicate.", requiredForEvaluation: true}
              elif all($summaries[]?; .state == "absent") then {code: "COMPONENT_CONFIGURATION_PREDICATE_UNOBSERVED", reason: "No registered component predicate was explicitly observed.", requiredForEvaluation: true}
              elif role_evidence_selection == "v3" and $adapter.componentId == "pkg:oci/prometheus/prometheus" and (prometheus_component_context_complete($adapter; $containers) | not) then {code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", reason: "At least one recognized eligible component controller lacked complete source-bound declared context; no subset is retained.", requiredForEvaluation: true}
              elif declared_context_requested and (($adapter.declaredRole | type) != "string" or ($adapter.roleEvidenceClass | type) != "string") then {code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_UNAVAILABLE", reason: "The exact public image identity has no approved declared-container role binding; role-bound context remains unknown.", requiredForEvaluation: true}
              else empty
              end
            end
          end
        end
      ))),
      version: "v1"
    }
end
