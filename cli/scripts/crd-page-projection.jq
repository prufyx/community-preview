if (type != "object" or .apiVersion != "apiextensions.k8s.io/v1" or .kind != "CustomResourceDefinitionList" or (.items | type) != "array" or (.items | length) > $pageLimit or (.metadata | type) != "object" or (.metadata.resourceVersion | type) != "string" or (.metadata.resourceVersion | length) == 0 or (.metadata.resourceVersion | length) > 256) then
  error("invalid or excessive CRD page")
elif (.metadata.continue != null and ((.metadata.continue | type) != "string" or (.metadata.continue | length) > 4096 or any(.metadata.continue | explode[]; . == 0 or . == 10 or . == 13))) then
  error("invalid CRD continue token")
elif any(.items[]?;
  (.spec | type) != "object" or
  (.spec.group | type) != "string" or (.spec.group | length) == 0 or (.spec.group | length) > 256 or
  (.spec.names | type) != "object" or
  (.spec.names.kind | type) != "string" or (.spec.names.kind | length) == 0 or (.spec.names.kind | length) > 256 or
  (.spec.names.plural | type) != "string" or (.spec.names.plural | length) == 0 or (.spec.names.plural | length) > 256 or
  (.spec.scope | type) != "string" or (.spec.scope | length) == 0 or (.spec.scope | length) > 64 or
  (.spec.versions | type) != "array" or (.spec.versions | length) == 0 or (.spec.versions | length) > 32 or
  any(.spec.versions[]?;
    type != "object" or (.name | type) != "string" or (.name | length) == 0 or (.name | length) > 128 or
    (.served | type) != "boolean" or (.storage | type) != "boolean" or
    (.deprecated != null and (.deprecated | type) != "boolean") or
    (.schema != null and ((.schema | type) != "object" or (.schema.openAPIV3Schema != null and (.schema.openAPIV3Schema | type) != "object"))) or
    (.subresources != null and ((.subresources | type) != "object" or
      (.subresources.status != null and (.subresources.status | type) != "object") or
      (.subresources.scale != null and (.subresources.scale | type) != "object")))
  ) or
  (.spec.conversion != null and ((.spec.conversion | type) != "object" or
    (.spec.conversion.strategy != null and ((.spec.conversion.strategy | type) != "string" or (.spec.conversion.strategy | length) > 64)) or
    (.spec.conversion.webhook != null and (.spec.conversion.webhook | type) != "object"))) or
  (.spec.preserveUnknownFields != null and (.spec.preserveUnknownFields | type) != "boolean")
) then
  error("invalid CRD nested shape")
elif ([.items[] | (.spec.group + "/" + .spec.names.plural)] | length) != ([.items[] | (.spec.group + "/" + .spec.names.plural)] | unique | length) then
  error("duplicate CRD identity")
elif any(.items[]?; ([.spec.versions[].name] | length) != ([.spec.versions[].name] | unique | length)) then
  error("duplicate CRD version")
else
  {
    resourceVersion: .metadata.resourceVersion,
    items: [
      .items[] | {
        group: .spec.group,
        kind: .spec.names.kind,
        plural: .spec.names.plural,
        scope: .spec.scope,
        versions: [
          .spec.versions[] | {
            name,
            served,
            storage,
            deprecated: (.deprecated // false),
            schemaPresent: (.schema.openAPIV3Schema != null),
            statusSubresource: (.subresources.status != null),
            scaleSubresource: (.subresources.scale != null)
          }
        ],
        conversionStrategy: (.spec.conversion.strategy // "None"),
        conversionWebhookConfigured: (.spec.conversion.webhook != null),
        preserveUnknownFields: (.spec.preserveUnknownFields // false)
      }
    ],
    continue: (.metadata.continue // "")
  }
end
