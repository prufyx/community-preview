# Build one minimized cert-manager predicate row from already filtered files.
# No names, namespaces, endpoints, addresses, Secret data, or raw arguments are
# consumed here. Missing API files are represented by explicit omissions.
def cm: "pkg:oci/cert-manager/cert-manager";
def certWebhookTarget:
  any(.rules[]?.apiGroups[]?; . == "cert-manager.io" or . == "acme.cert-manager.io");
def crdPred($items; $group; $plural; $stem):
  ([ $items[]? | select(.group == $group and .plural == $plural) ] | if length != 1 then {}
   else ([.[0].versions[] | select(.name == "v1" and .served == true and ((.storage | type) == "boolean"))] | if length != 1 then {}
     else {($stem + "_served"): .[0].served, ($stem + "_storage"): .[0].storage} end)
   end);

($configuration // []) as $configurationRows
| ([ $configurationRows[] | select(.componentId == cm and .observedVersion != null) | .observedVersion ] | unique) as $versions
| ([ $configurationRows[] | select(.componentId == cm) | .versionScheme ] | unique) as $schemes
| ([ $configurationRows[] | select(.componentId == cm) ] | length > 0) as $hasComponent
| ($crds[0] // []) as $crdItems
| ([ $crdItems[]? | select(
      ((.group == "cert-manager.io" and (.plural == "certificates" or .plural == "certificaterequests" or .plural == "issuers" or .plural == "clusterissuers"))
       or (.group == "acme.cert-manager.io" and (.plural == "challenges" or .plural == "orders")))
      and any(.versions[]?; .name == "v1" and .served == true and ((.storage | type) == "boolean"))
    ) ] | length) as $validCrdCount
| ($validating[0] // []) as $validatingItems
| ($mutating[0] // []) as $mutatingItems
| (if (($rbac[0] // null) | type) == "object" then $rbac[0] else {} end) as $rbacSummary
| (if (($roles[0] // null) | type) == "object" then $roles[0] else {} end) as $roleSummary
| (if (($rolebindings[0] // null) | type) == "object" then $rolebindings[0] else {} end) as $roleBindingSummary
| (if (($clusterrolebindings[0] // null) | type) == "object" then $clusterrolebindings[0] else {} end) as $clusterRoleBindingSummary
| (if (($metrics[0] // null) | type) == "object" then $metrics[0] else {} end) as $metricsSummary
| (if (($health[0] // null) | type) == "object" then $health[0] else {} end) as $healthSummary
| def bound($class): (($roleBindingSummary[$class] == true) or ($clusterRoleBindingSummary[$class] == true));
  def rule($summary; $class; $name): (($summary[$class] // {})[$name] == true);
  ({
    componentId: cm,
    observedVersion: (if ($versions | length) == 1 then $versions[0] else null end),
    versionScheme: (if ($versions | length) == 1 then ($schemes[0] // "tag") else "unknown" end),
    versionConflict: (($versions | length) > 1),
    observationState: "observed",
    observationCount: 1,
    predicates: (
      # No safe retained signal distinguishes Helm/static/operator here. The
      # closed enum is therefore explicitly conservative until such evidence
      # is added; it is never inferred from names or labels.
      {"component.cert_manager.install_mode": "unknown"}
      +
      (if $crdAvailable then
        (crdPred($crdItems; "cert-manager.io"; "certificates"; "component.cert_manager.crd_certificates_v1")
         + crdPred($crdItems; "cert-manager.io"; "certificaterequests"; "component.cert_manager.crd_certificaterequests_v1")
         + crdPred($crdItems; "cert-manager.io"; "issuers"; "component.cert_manager.crd_issuers_v1")
         + crdPred($crdItems; "cert-manager.io"; "clusterissuers"; "component.cert_manager.crd_clusterissuers_v1")
         + crdPred($crdItems; "acme.cert-manager.io"; "challenges"; "component.cert_manager.crd_challenges_v1")
         + crdPred($crdItems; "acme.cert-manager.io"; "orders"; "component.cert_manager.crd_orders_v1"))
       else {} end)
      + (if $validatingAvailable and $mutatingAvailable then {
        "component.cert_manager.admission_webhook_v1": ([ $validatingItems[]?.webhooks[]?, $mutatingItems[]?.webhooks[]? | select(.identityPresent == true and certWebhookTarget) | .admissionReviewVersions[]? | select(. == "v1") ] | length > 0),
        "component.cert_manager.admission_webhook_failure_policy_fail": ([ $validatingItems[]?.webhooks[]?, $mutatingItems[]?.webhooks[]? | select(.identityPresent == true and certWebhookTarget and .failurePolicy == "Fail") ] | length > 0),
        "component.cert_manager.admission_webhook_identity_present": ([ $validatingItems[]?.webhooks[]?, $mutatingItems[]?.webhooks[]? | select(.identityPresent == true and certWebhookTarget) ] | length > 0)
      } else {} end)
      + (if $rbacAvailable then {
        "component.cert_manager.rbac_serviceaccounts_token_create": any(["controller", "webhook", "cainjector", "startupapicheck"][]; bound(.) and (rule($rbacSummary; .; "serviceaccountsTokenCreate") or rule($roleSummary; .; "serviceaccountsTokenCreate"))),
        "component.cert_manager.rbac_cert_manager_api_groups": any(["controller", "webhook", "cainjector", "startupapicheck"][]; bound(.) and (rule($rbacSummary; .; "certManagerAPIGroups") or rule($roleSummary; .; "certManagerAPIGroups"))),
        "component.cert_manager.rbac_acme_api_group": any(["controller", "webhook", "cainjector", "startupapicheck"][]; bound(.) and (rule($rbacSummary; .; "acmeAPIGroup") or rule($roleSummary; .; "acmeAPIGroup")))
      } else {} end)
      + (if $metricsAvailable and (($metricsSummary.monitorIdentityProven // false) == true) then {
        "component.cert_manager.metrics_servicemonitor_present": ($metricsSummary.serviceMonitorPresent == true),
        "component.cert_manager.metrics_podmonitor_present": ($metricsSummary.podMonitorPresent == true),
        "component.cert_manager.metrics_scrape_port_present": ($metricsSummary.scrapePortPresent == true),
        "component.cert_manager.metrics_scrape_path_present": ($metricsSummary.scrapePathPresent == true)
      } else {} end)
      + (if $healthAvailable then {
        "component.cert_manager.health_desired_count": ($healthSummary.desiredCount // 0),
        "component.cert_manager.health_ready_count": ($healthSummary.readyCount // 0),
        "component.cert_manager.health_available_count": ($healthSummary.availableCount // 0)
      } else {} end)
    )
  }) as $row
| {
    row: (if $hasComponent and ($row.predicates | length) > 0 then $row else null end),
    omissions: (if $hasComponent then ((if ($crdAvailable and $validCrdCount == 6) then [] else [{code:"COMPONENT_CONFIGURATION_CRD_SURFACE_UNAVAILABLE", reason:"The exact six cert-manager CRD served/storage surface was unavailable or incomplete.", requiredForEvaluation:true}] end)
      + (if $validatingAvailable and $mutatingAvailable then [] else [{code:"COMPONENT_CONFIGURATION_API_UNAVAILABLE", reason:"The cert-manager admission webhook API surface was unavailable.", requiredForEvaluation:true}] end)
      + (if $rbacAvailable then [] else [{code:"COMPONENT_CONFIGURATION_RBAC_FORBIDDEN", reason:"Scoped cert-manager RBAC predicates were unavailable or forbidden.", requiredForEvaluation:true}] end)
      + (if $metricsAvailable and (($metricsSummary.monitorIdentityProven // false) == true) then [] else [{code:"COMPONENT_CONFIGURATION_API_UNAVAILABLE", reason:"ServiceMonitor/PodMonitor APIs or a cert-manager target workload identity were unavailable; scrape predicates remain UNKNOWN.", requiredForEvaluation:true}] end)
      + (if $healthAvailable then [] else [{code:"COMPONENT_CONFIGURATION_HEALTH_UNAVAILABLE", reason:"Aggregated cert-manager desired/ready/available health counts were unavailable.", requiredForEvaluation:true}] end)) else [] end)
  }
