def merge_components:
  group_by(.componentId)
  | map(
      . as $rows
      | ([ $rows[].predicates | keys[] ] | unique) as $names
      | ([ $names[] as $name
           | ([ $rows[] | select(.predicates | has($name)) ]) as $predicateRows
           | ([ $predicateRows[] | .predicateEvidence[]? | select(.predicateId == $name) ]) as $evidenceRows
           | select(($evidenceRows | length) > 0 and
               ((($evidenceRows | unique | length) != 1) or
                (any($predicateRows[]; . as $predicateRow |
                  ([$predicateRow.predicateEvidence[]? | select(.predicateId == $name)] | length) != 1 or
                  (($predicateRow.roles // []) | index(([$predicateRow.predicateEvidence[]? | select(.predicateId == $name)][0].sourceRole))) == null))))
           | $name ]) as $evidenceConflicts
      | ([ $names[] as $name | ([$rows[] | select(.predicates | has($name)) | .predicates[$name]] | unique | length) > 1 ] | any) as $valueConflict
      | ([$rows[].observedVersion] | unique) as $versions
      | ([$rows[].versionScheme] | unique) as $schemes
      | (($versions | length) > 1) as $versionConflict
      | (reduce $names[] as $name ({};
          ([$rows[] | select(.predicates | has($name)) | .predicates[$name]] | unique) as $values
          | if ($values | length) == 1 and (($evidenceConflicts | index($name)) == null) then .[$name] = $values[0] else . end
        )) as $merged
      | ([ $names[] as $name
           | ([ $rows[] | select(.predicates | has($name)) ]) as $predicateRows
           | ([ $predicateRows[] | .predicateEvidence[]? | select(.predicateId == $name) ] | unique) as $evidenceRows
           | select(($evidenceRows | length) == 1 and (($evidenceConflicts | index($name)) == null)
                    and all($predicateRows[]; . as $predicateRow | ([$predicateRow.predicateEvidence[]? | select(.predicateId == $name)] | length) == 1))
           | $evidenceRows[0] ]) as $mergedEvidence
      | {
          component: ({
            componentId: $rows[0].componentId,
            observedVersion: (if ($valueConflict or $versionConflict) then null else $versions[0] end),
            versionScheme: (if ($valueConflict or $versionConflict) then "unknown" else $schemes[0] end),
            versionConflict: ($valueConflict or $versionConflict),
            observationState: (if ($valueConflict or $versionConflict) then "conflict" else "observed" end),
            observationCount: ([$rows[].observationCount] | add),
            predicates: (if ($valueConflict or $versionConflict) then {} else $merged end)
          } + (if ($mergedEvidence | length) > 0 and ($valueConflict | not) and ($versionConflict | not) then
                 {roles: ([$mergedEvidence[].sourceRole] | unique), predicateEvidence: ($mergedEvidence | sort_by(.predicateId))}
               else {} end)),
          evidenceConflicts: $evidenceConflicts
        }
    );

($configuration // []) as $configurationRows
| ($inputOmissions // []) as $omissionRows
| ($configurationRows | merge_components) as $mergedRows
| ([ $mergedRows[] as $merged
     | $merged.evidenceConflicts[]
     | {code: "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS", reason: "Declared-container role evidence was missing, mixed, or contradictory; collect one exact unshared image role and evidence class for the predicate.", requiredForEvaluation: true, sourceFile: "component-configuration-aggregate", count: 1} ]) as $evidenceOmissions
| {
    apiVersion: $apiVersion,
    kind: $kind,
    metadata: {
      schemaVersion: "1.0.0",
      adapterVersion: $adapterVersion,
      registryVersion: $registryVersion,
      registryDigest: $registryDigest,
      filterDigest: $filterDigest,
      aggregateDigest: $aggregateDigest,
      strictJsonDigest: $strictJsonDigest,
      kubectlStderrClassifierDigest: $kubectlStderrClassifierDigest,
      kubectlBoundedRunnerDigest: $kubectlBoundedRunnerDigest,
      kubectlStderrClassifierTaxonomyVersion: $kubectlStderrClassifierTaxonomyVersion,
      kubectlStderrClassifierAuthority: $kubectlStderrClassifierAuthority,
      certManagerProjectionDigest: ($certManagerProjectionDigest // null)
    },
    components: ($mergedRows | map(.component)),
    omissions: (($omissionRows + $evidenceOmissions)
      | map(. + {count: (.count // 1)})
      | sort_by([.code, .sourceFile])
      | group_by([.code, .sourceFile])
      | map({
          code: .[0].code,
          reason: .[0].reason,
          requiredForEvaluation: (all(.[]; .requiredForEvaluation == true)),
          sourceFile: .[0].sourceFile,
          count: (map(.count) | add)
        })),
    licenseCopyrightDisposition: $licenseDisposition
  }
