#!/usr/bin/env python3
"""Generate the canonical Community support inventory from committed evidence inputs.

The selected-source manifest is intentionally separate from executable rules. It
must name retained source records; landscape identities are never treated as
support records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA = "prufyx.io/community-support-inventory/v1alpha1"
SELECTED_SCHEMA = "prufyx.io/selected-source-records/v1"
PROJECT_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SOURCE_KINDS = {"changelog", "helm_chart", "migration_guide", "release_note", "repository_metadata", "source_code"}
MAX_URL = 2048
MAX_ID = 160
MAX_TEXT = 240


class Invalid(ValueError):
    pass


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON object field")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_object)
    except (json.JSONDecodeError, Invalid) as exc:
        raise Invalid(f"invalid JSON: {path}") from exc
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def text(value: Any, label: str, maximum: int = MAX_TEXT) -> str:
    require(isinstance(value, str) and 0 < len(value) <= maximum and not any(ord(character) < 32 or ord(character) == 127 for character in value), f"invalid {label}")
    return value


def https_url(value: Any, label: str) -> str:
    value = text(value, f"{label} URL", MAX_URL)
    require(not any(character.isspace() or character in "<>" for character in value), f"invalid {label} URL")
    parsed = urlparse(value)
    require(parsed.scheme == "https" and parsed.netloc and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment, f"invalid {label} URL")
    return value


def github_repository_url(value: Any, label: str) -> str:
    value = https_url(value, label)
    parsed = urlparse(value)
    require(parsed.netloc == "github.com" and len([part for part in parsed.path.split("/") if part]) == 2, f"invalid {label} GitHub repository URL")
    return value


def immutable_github_url(value: Any, label: str) -> tuple[str, str]:
    value = https_url(value, label)
    parsed = urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc == "github.com":
        require(len(parts) >= 5 and parts[2] == "blob" and COMMIT_RE.fullmatch(parts[3]) is not None, f"invalid {label} immutable GitHub URL")
        return value, parts[3]
    if parsed.netloc == "raw.githubusercontent.com":
        require(len(parts) >= 4 and COMMIT_RE.fullmatch(parts[2]) is not None, f"invalid {label} immutable GitHub URL")
        return value, parts[2]
    raise Invalid(f"invalid {label} immutable GitHub URL")


def markdown_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def markdown_link(label: str, url: str) -> str:
    return f"[`{markdown_cell(label)}`](<{url}>)"


def source_spans(value: Any) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value and len(value) <= 32, "invalid executable evidence spans")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, str):
            match = re.fullmatch(r"([1-9][0-9]{0,6})-([1-9][0-9]{0,6})", item)
            require(match is not None and int(match.group(2)) >= int(match.group(1)), "invalid executable evidence line span")
            normalized.append({"startLine": int(match.group(1)), "endLine": int(match.group(2))})
        else:
            require(isinstance(item, dict) and set(item) == {"startLine", "endLine", "textDigest"}, "invalid executable evidence span")
            start, end, digest = item.get("startLine"), item.get("endLine"), item.get("textDigest")
            require(isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool) and 0 < start <= end <= 10_000_000 and isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None, "invalid executable evidence span")
            normalized.append({"startLine": start, "endLine": end, "textDigest": digest})
    require(len({canonical(item) for item in normalized}) == len(normalized), "duplicate executable evidence span")
    return sorted(normalized, key=canonical)


def source_record(raw: dict[str, Any], project_id: str) -> dict[str, Any]:
    allowed = {"id", "sourceId", "url", "revision", "immutableCommit", "contentDigest", "startLine", "endLine", "spans"}
    require(isinstance(raw, dict) and set(raw).issubset(allowed), "unexpected executable evidence source field")
    has_id, has_source_id = "id" in raw, "sourceId" in raw
    has_revision, has_immutable_commit = "revision" in raw, "immutableCommit" in raw
    require(has_id != has_source_id, "ambiguous executable evidence source identity")
    if has_source_id:
        require(has_immutable_commit and not has_revision, "invalid Prometheus evidence source identity")
        record_id, revision = raw["sourceId"], raw["immutableCommit"]
    else:
        require(not has_immutable_commit, "invalid generic evidence source identity")
        record_id, revision = raw["id"], raw.get("revision")
    digest = raw.get("contentDigest")
    require(isinstance(record_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", record_id) is not None, "missing executable evidence source id")
    require(isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None, "invalid executable evidence digest")
    url, immutable_commit = immutable_github_url(raw.get("url"), "executable evidence")
    result: dict[str, Any] = {"id": record_id, "url": url, "contentDigest": digest}
    if has_revision or has_immutable_commit:
        require(isinstance(revision, str) and COMMIT_RE.fullmatch(revision) is not None and revision == immutable_commit, "invalid executable evidence revision")
        result["revision"] = revision
    if "startLine" in raw or "endLine" in raw:
        start, end = raw.get("startLine"), raw.get("endLine")
        require(isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool) and 0 < start <= end <= 10_000_000, "invalid executable evidence line range")
        result["startLine"] = start
        result["endLine"] = end
    if "spans" in raw:
        result["spans"] = source_spans(raw["spans"])
    result["projectID"] = project_id
    return result


def selected_records(document: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    require(isinstance(document, dict) and set(document) == {"schema", "provenance", "records"} and document.get("schema") == SELECTED_SCHEMA, "invalid selected-source manifest schema")
    provenance = document.get("provenance")
    require(isinstance(provenance, dict) and set(provenance) == {"collectionIndexDigest", "referenceState", "licenseState"}, "invalid selected-source provenance")
    index_digest = provenance.get("collectionIndexDigest")
    require(isinstance(index_digest, str) and DIGEST_RE.fullmatch(index_digest) is not None, "invalid source collection index digest")
    require(provenance.get("referenceState") == "reference_only" and provenance.get("licenseState") == "license_unreviewed", "invalid source reference state")
    records = document.get("records")
    require(isinstance(records, list) and records, "selected-source records required")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        require(isinstance(record, dict) and set(record) == {"id", "projectID", "canonicalRepositoryURL", "repositoryURL", "immutableURL", "commit", "version", "sourceKind", "contentDigest", "byteLength", "spans"}, "unexpected selected-source record field")
        record_id, project_id = record.get("id"), record.get("projectID")
        require(isinstance(record_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", record_id) is not None and record_id not in seen, "duplicate or missing selected-source record ID")
        require(isinstance(project_id, str) and PROJECT_RE.fullmatch(project_id) is not None and len(project_id) <= 80, "invalid selected-source project ID")
        require(COMMIT_RE.fullmatch(record.get("commit", "")) is not None, "invalid selected-source commit")
        text(record.get("version"), "selected-source version", 128)
        require(record.get("sourceKind") in SOURCE_KINDS, "invalid selected-source kind")
        require(isinstance(record.get("contentDigest"), str) and DIGEST_RE.fullmatch(record["contentDigest"]) is not None, "invalid selected-source digest")
        require(isinstance(record.get("byteLength"), int) and not isinstance(record["byteLength"], bool) and 0 < record["byteLength"] <= 1024 * 1024, "invalid selected-source byte length")
        require(github_repository_url(record.get("canonicalRepositoryURL"), "canonical repository") == record["canonicalRepositoryURL"], "invalid canonical repository")
        require(github_repository_url(record.get("repositoryURL"), "source repository") == record["repositoryURL"], "invalid source repository")
        immutable_url, immutable_commit = immutable_github_url(record.get("immutableURL"), "immutable source")
        require(immutable_url == record["immutableURL"] and immutable_commit == record["commit"], "invalid immutable source")
        spans = record.get("spans")
        require(isinstance(spans, list) and spans, "selected-source spans required")
        normalized_spans: list[dict[str, Any]] = []
        for span in spans:
            require(isinstance(span, dict) and set(span) == {"startLine", "endLine", "spanDigest"}, "invalid selected-source span")
            start, end, digest = span.get("startLine"), span.get("endLine"), span.get("spanDigest")
            require(isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool) and 0 < start <= end <= 10_000_000 and isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None, "invalid selected-source span bounds")
            normalized_spans.append({"startLine": start, "endLine": end, "spanDigest": digest})
        require(len({canonical(item) for item in normalized_spans}) == len(normalized_spans), "duplicate selected-source span")
        seen.add(record_id)
        result.append({**{key: record[key] for key in ["id", "projectID", "canonicalRepositoryURL", "repositoryURL", "immutableURL", "commit", "version", "sourceKind", "contentDigest", "byteLength"]}, "spans": sorted(normalized_spans, key=lambda item: (item["startLine"], item["endLine"], item["spanDigest"])), "referenceState": "reference_only", "licenseState": "license_unreviewed"})
    return sorted(result, key=lambda item: item["id"]), {"collectionIndexDigest": index_digest, "referenceState": "reference_only", "licenseState": "license_unreviewed"}


def preparer_projects(path: Path) -> set[str]:
    text = path.read_text()
    dispatch = re.search(
        r'var prepared cncfprepare\.Prepared\s+switch \*project \{(?P<body>.*?)^\t\}',
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    require(dispatch is not None, "CNCF preparer dispatch block is missing")
    values = set(re.findall(r'^\tcase "([a-z0-9-]+)":', dispatch.group("body"), flags=re.MULTILINE))
    require(values, "CNCF preparer dispatch has no project cases")
    return values


def transition(raw: dict[str, Any]) -> dict[str, str]:
    subject = raw.get("subject")
    require(isinstance(subject, dict), "missing rule subject")
    component, current, proposed = subject.get("component"), subject.get("from"), subject.get("to")
    text(component, "rule component")
    require(isinstance(current, str) and VERSION_RE.fullmatch(current), "invalid rule current version")
    require(isinstance(proposed, str) and VERSION_RE.fullmatch(proposed), "invalid rule proposed version")
    return {"component": component, "from": current, "to": proposed, "semantics": "exact_declared_endpoints_only"}


def generic_projects(rules: dict[str, Any], identities: dict[str, dict[str, Any]], preparers: set[str]) -> list[dict[str, Any]]:
    require(rules.get("schema") == "prufyx.io/cncf-source-rule-pack/v1alpha1", "invalid rule-pack schema")
    entries = rules.get("entries")
    require(isinstance(entries, list) and entries, "missing rule-pack entries")
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen_rules: set[str] = set()
    for entry in entries:
        require(isinstance(entry, dict), "invalid rule entry")
        project_id = entry.get("project")
        require(isinstance(project_id, str) and project_id in identities, "rule project is absent from landscape")
        rule = entry.get("rule")
        require(isinstance(rule, dict), "invalid rule definition")
        rule_id = rule.get("id")
        require(isinstance(rule_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", rule_id) is not None and rule_id not in seen_rules, "duplicate or missing executable rule ID")
        seen_rules.add(rule_id)
        evidence = rule.get("evidence")
        require(isinstance(evidence, dict) and evidence.get("state") == "active", "rule lacks active evidence")
        sources = evidence.get("sources")
        require(isinstance(sources, list) and sources, "rule lacks evidence sources")
        grouped.setdefault(project_id, []).append({
            "ruleID": rule_id,
            "transition": transition(rule),
            "evidence": [source_record(item, project_id) for item in sources],
            "evidenceState": evidence["state"],
            "limit": "Scoped operator-declared constraint; a PASS, BLOCKED, or UNKNOWN claim never proves whole-upgrade safety or runtime behavior.",
        })
    projects: list[dict[str, Any]] = []
    for project_id in sorted(grouped):
        identity = identities[project_id]
        capability: dict[str, Any] = {
            "kind": "embedded_cncf_source_rule",
            "command": ["check", "cncf", "--project", project_id],
            "rules": sorted(grouped[project_id], key=lambda item: item["ruleID"]),
            "metadataState": "embedded_active_source_rule_pack",
        }
        if project_id in preparers:
            capability["localPreparer"] = {
                "command": ["prepare", "cncf", "--project", project_id],
                "metadataState": "implemented_local_minimizing_adapter",
                "limit": "The adapter prepares only a bounded operator declaration from one local private input; it does not inspect a cluster, run an upgrade, or establish runtime behavior.",
            }
        require(identity["repositoryURL"] is not None, "executable rule project lacks canonical repository")
        github_repository_url(identity["repositoryURL"], "executable rule project repository")
        projects.append({
            "projectID": project_id,
            "displayName": identity["name"],
            "repositoryURL": identity["repositoryURL"],
            "supportState": "executable",
            "capabilities": [capability],
            "selectedSourceRecords": [],
        })
    return projects


def named_project(contract: dict[str, Any], digest: str, identities: dict[str, dict[str, Any]], check: str) -> dict[str, Any]:
    if check == "cert-manager-values":
        require(contract.get("schema") == "prufyx.io/cert-manager-removed-monitor-values-source-contract/v1", "invalid cert-manager source contract")
        project_id = "cert-manager"
        component = contract.get("component")
        current, proposed = contract.get("current"), contract.get("target")
        sources = contract.get("sources")
        limit = "Checks only three curated removed values paths; it does not validate the full target schema, runtime behavior, or whole-upgrade compatibility."
    else:
        require(contract.get("schema") == "prufyx.io/prometheus-mode-source-contract/v1", "invalid Prometheus source contract")
        project_id = "prometheus"
        component = contract.get("componentId")
        current, proposed = contract.get("current"), contract.get("proposed")
        sources = contract.get("sources")
        limit = contract.get("claimLimit")
    require(project_id in identities, "named check project is absent from landscape")
    require(isinstance(current, dict) and isinstance(proposed, dict), "invalid named check transition")
    text(component, "named check component")
    from_version, to_version = current.get("version"), proposed.get("version")
    require(isinstance(from_version, str) and VERSION_RE.fullmatch(from_version), "invalid named-check current version")
    require(isinstance(to_version, str) and VERSION_RE.fullmatch(to_version), "invalid named-check target version")
    require(isinstance(sources, list) and sources, "invalid named-check evidence")
    text(limit, "named-check limit")
    identity = identities[project_id]
    require(identity["repositoryURL"] is not None, "named check project lacks canonical repository")
    github_repository_url(identity["repositoryURL"], "named check project repository")
    return {
        "projectID": project_id,
        "displayName": identity["name"],
        "repositoryURL": identity["repositoryURL"],
        "supportState": "executable",
        "capabilities": [{
            "kind": "named_local_check",
            "command": ["check", check],
            "transitions": [{"component": component, "from": from_version, "to": to_version, "semantics": "exact_reviewed_transition_only"}],
            "evidence": [source_record(item, project_id) for item in sources],
            "metadataState": "embedded_source_contract",
            "sourceContractDigest": digest,
            "limit": limit,
        }],
        "selectedSourceRecords": [],
    }


def spiffe_conformance_project(profile: dict[str, Any], digest: str, identities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(profile.get("apiVersion") == "prufyx.io/spiffe-x509-svid-profile/v1" and profile.get("kind") == "SPIFFEX509SVIDProfile", "invalid SPIFFE X.509-SVID profile")
    require(profile.get("purpose") == "standards_conformance" and profile.get("engineCapabilityDigest") == "sha256:33c6a42388c6d1f340c97dc03179423a1d24d5c92292fea97414c61350f1abbf", "invalid SPIFFE profile purpose or capability")
    require(profile.get("revision") == "1", "invalid embedded SPIFFE profile revision")
    rules = profile.get("rules")
    require(isinstance(rules, list) and len(rules) == 1 and rules[0].get("id") == "spiffe-x509-svid-public-leaf-uri-san-v1", "invalid embedded SPIFFE profile rule")
    source = profile.get("normativeSource")
    require(isinstance(source, dict) and source.get("repositoryURL") == "https://github.com/spiffe/spiffe" and source.get("path") == "standards/X509-SVID.md", "invalid SPIFFE normative source")
    project_id = "spiffe"
    require(project_id in identities and identities[project_id]["repositoryURL"] == source["repositoryURL"], "SPIFFE project identity mismatch")
    evidence = source_record({"id": "spiffe-x509-svid-public-leaf-profile", "url": f"{source['repositoryURL']}/blob/{source['commit']}/{source['path']}", "revision": source["commit"], "contentDigest": source["contentDigest"], "spans": [f"{item['startLine']}-{item['endLine']}" for item in source["spans"]]}, project_id)
    return {
        "projectID": project_id,
        "displayName": identities[project_id]["name"],
        "repositoryURL": identities[project_id]["repositoryURL"],
        "supportState": "executable",
        "capabilities": [{
            "kind": "standards_conformance_profile",
            "command": ["check", "spiffe-x509-svid"],
            "profileID": "public-non-ca-leaf-single-spiffe-uri-non-root-path-v1",
            "metadataState": "embedded_reviewed_profile_with_optional_explicit_signed_local_selection",
            "profileDigest": digest,
            "evidence": [evidence],
            "limit": "Checks one named URI-SAN subset only; it does not validate a complete SPIFFE ID, X.509-SVID, trust chain, possession, authentication, issuance, or runtime use.",
        }],
        "selectedSourceRecords": [],
    }


def cloudevents_conformance_project(profile: dict[str, Any], digest: str, identities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(profile.get("apiVersion") == "prufyx.io/cloudevents-structured-json-profile/v1" and profile.get("kind") == "CloudEventsStructuredJSONProfile", "invalid CloudEvents structured JSON profile")
    require(profile.get("purpose") == "standards_conformance" and profile.get("engineCapabilityDigest") == "sha256:94cc3006e46ce20a4c2579eb4d1eb99dfaee9fe00a4396ec3f4ee5ed204313bb", "invalid CloudEvents profile purpose or capability")
    require(profile.get("revision") == "1", "invalid embedded CloudEvents profile revision")
    rules = profile.get("rules")
    require(isinstance(rules, list) and len(rules) == 1 and rules[0].get("id") == "cloudevents-v1-structured-json-core-envelope-v1", "invalid embedded CloudEvents profile rule")
    sources = profile.get("normativeSources")
    require(isinstance(sources, list) and len(sources) == 2, "invalid CloudEvents normative sources")
    source_by_role = {item.get("role"): item for item in sources if isinstance(item, dict)}
    require(set(source_by_role) == {"spec", "json-format"}, "invalid CloudEvents normative source roles")
    expected_paths = {"spec": "spec.md", "json-format": "json-format.md"}
    project_id = "cloudevents"
    require(project_id in identities and identities[project_id]["repositoryURL"] == "https://github.com/cloudevents/spec", "CloudEvents project identity mismatch")
    evidence = []
    for role in ("spec", "json-format"):
        source = source_by_role[role]
        require(source.get("repositoryURL") == identities[project_id]["repositoryURL"] and source.get("path") == expected_paths[role], "invalid CloudEvents normative source")
        evidence.append(source_record({"id": f"cloudevents-structured-json-{role}-profile", "url": f"{source['repositoryURL']}/blob/{source['commit']}/{source['path']}", "revision": source["commit"], "contentDigest": source["contentDigest"], "spans": [f"{item['startLine']}-{item['endLine']}" for item in source["spans"]]}, project_id))
    return {
        "projectID": project_id,
        "displayName": identities[project_id]["name"],
        "repositoryURL": identities[project_id]["repositoryURL"],
        "supportState": "executable",
        "capabilities": [{
            "kind": "standards_conformance_profile",
            "command": ["check", "cloudevents-structured-json"],
            "profileID": "structured-json-core-envelope-v1",
            "metadataState": "embedded_reviewed_profile_with_optional_explicit_signed_local_selection",
            "profileDigest": digest,
            "evidence": evidence,
            "limit": "Checks one named CloudEvents 1.0 structured JSON core-envelope subset only; it does not validate source URI semantics, source-plus-id uniqueness, data schemas, base64 decoding, extensions, batching, transport, SDK/runtime behavior, delivery, signing, or authentication.",
        }],
        "selectedSourceRecords": [],
    }


def tikv_target_preflight_project(profile: dict[str, Any], digest: str, identities: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(profile.get("apiVersion") == "prufyx.io/tikv-gcp-v2-wif-backup-profile/v1" and profile.get("kind") == "TiKVGCPV2WIFBackupProfile", "invalid TiKV target-preflight profile")
    require(profile.get("purpose") == "planned_operation_preflight" and profile.get("engineCapabilityDigest") == "sha256:f342ee3a3a997add0a234937499a8e2327baad4e4329b12b590e6e5fb1528d8a", "invalid TiKV profile purpose or capability")
    require(profile.get("revision") == "1" and profile.get("target") == {"component": "pkg:github/tikv/tikv", "version": "8.5.8"}, "invalid embedded TiKV target")
    rules = profile.get("rules")
    require(isinstance(rules, list) and len(rules) == 1 and rules[0].get("id") == "tikv-8.5.8-gcp-v2-wif-full-backup-enabled-v1", "invalid embedded TiKV rule")
    sources = profile.get("normativeSources")
    require(isinstance(sources, list) and len(sources) == 3, "invalid TiKV sources")
    source_by_role = {item.get("role"): item for item in sources if isinstance(item, dict)}
    expected = {
        "target_setting_declaration": ("https://github.com/tikv/tikv", "src/config/mod.rs"),
        "target_full_backup_caller": ("https://github.com/tikv/tikv", "components/backup/src/endpoint.rs"),
        "operator_action_guidance": ("https://github.com/pingcap/docs", "tikv-configuration-file.md"),
    }
    require(set(source_by_role) == set(expected), "invalid TiKV source roles")
    project_id = "tikv"
    require(project_id in identities and identities[project_id]["repositoryURL"] == "https://github.com/tikv/tikv", "TiKV project identity mismatch")
    evidence = []
    for role, (repository, path) in expected.items():
        source = source_by_role[role]
        require(source.get("repositoryURL") == repository and source.get("path") == path, "invalid TiKV source identity")
        evidence.append(source_record({"id": f"tikv-gcp-v2-wif-{role.replace('_', '-')}", "url": f"{repository}/blob/{source['commit']}/{path}", "revision": source["commit"], "contentDigest": source["contentDigest"], "spans": [f"{item['startLine']}-{item['endLine']}" for item in source["spans"]]}, project_id))
    return {
        "projectID": project_id,
        "displayName": identities[project_id]["name"],
        "repositoryURL": identities[project_id]["repositoryURL"],
        "supportState": "executable",
        "capabilities": [{
            "kind": "target_preflight_profile",
            "command": ["check", "tikv-gcp-v2-wif-backup"],
            "target": {"component": "pkg:github/tikv/tikv", "version": "8.5.8", "operation": "gcs-full-backup-wif"},
            "profileID": "tikv-8.5.8-gcp-v2-wif-full-backup-v1",
            "metadataState": "embedded_reviewed_profile_with_optional_explicit_signed_local_selection",
            "profileDigest": digest,
            "evidence": evidence,
            "limit": "Checks one explicit TiKV 8.5.8 planned GCS WIF full-backup setting only; aggregate backup readiness, credentials, GCS access, execution, completion, restore, log backup, runtime behavior, and data safety remain UNKNOWN.",
        }],
        "selectedSourceRecords": [],
    }


def render_markdown(inventory: dict[str, Any]) -> str:
    counts = inventory["counts"]
    lines = [
        "# Community support inventory",
        "",
        "Generated by `scripts/generate_support_inventory.py`; do not edit by hand.",
        "",
        "This inventory separates executable scoped checks from selected public-source records. Catalogue discovery identities are not support entries. A scoped result never proves a whole upgrade safe or runtime behavior.",
        "",
        f"- CNCF embedded source rules: **{counts['cncfSourceRules']}** across **{counts['cncfRuleProjects']}** projects.",
        f"- Named local checks: **{counts['namedChecks']}** across **{counts['namedCheckProjects']}** projects.",
        f"- Standards-conformance profiles: **{counts['conformanceProfiles']}** across **{counts['conformanceProjects']}** projects; these are not version-transition checks.",
        f"- Target-preflight profiles: **{counts['targetPreflightProfiles']}** across **{counts['targetPreflightProjects']}** projects; these are not version-transition checks.",
        f"- Executable-project union: **{counts['executableProjects']}** projects.",
        f"- Selected retained public-source records: **{counts['selectedSourceRecords']}** across **{counts['selectedSourceProjects']}** projects; **{counts['selectedSourceOnlyProjects']}** are source-only and have no executable-support capability.",
        "",
        "## Executable projects",
        "",
        "| Project | Executable capability | Exact reviewed transition(s) | Pinned evidence | Local preparer | Limits |",
        "| --- | --- | --- | --- | --- |",
    ]
    for project in inventory["projects"]:
        if project["supportState"] == "selected_source_only":
            continue
        capabilities = project["capabilities"]
        labels = []
        transitions = []
        preparers = []
        limits = []
        evidence_links = []
        for capability in capabilities:
            labels.append("`prufyx " + " ".join(capability["command"]) + "`")
            if capability.get("kind") == "standards_conformance_profile":
                transitions.append("standards subset (no from/to transition)")
            if capability.get("kind") == "target_preflight_profile":
                transitions.append("target preflight (no from/to transition)")
            for rule in capability.get("rules", []):
                transitions.append(f"`{rule['ruleID']}` {rule['transition']['from']} → {rule['transition']['to']}")
                limits.append(rule["limit"])
                evidence_links.extend(markdown_link(item["id"], item["url"]) for item in rule["evidence"])
            for item in capability.get("transitions", []):
                transitions.append(f"{item['from']} → {item['to']}")
            evidence_links.extend(markdown_link(item["id"], item["url"]) for item in capability.get("evidence", []))
            if "localPreparer" in capability:
                preparers.append("`prufyx " + " ".join(capability["localPreparer"]["command"]) + "`")
                limits.append(capability["localPreparer"]["limit"])
            if "limit" in capability:
                limits.append(capability["limit"])
        lines.append("| [{name}](<{url}>) | {capability} | {transition} | {evidence} | {preparer} | {limit} |".format(
            name=markdown_cell(project["displayName"]), url=project["repositoryURL"], capability="<br>".join(markdown_cell(item) for item in labels),
            transition="<br>".join(markdown_cell(item) for item in transitions), evidence="<br>".join(sorted(set(evidence_links))),
            preparer="<br>".join(markdown_cell(item) for item in preparers) or "—", limit="<br>".join(markdown_cell(item) for item in sorted(set(limits))),
        ))
    lines.extend(["", "## Selected-source-only projects", "", "These projects have retained public-source records but no executable check in this binary. They are **reference-only** and **license-unreviewed**, not upgrade support.", "", "| Project | Retained immutable source reference(s) | Metadata state |", "| --- | --- | --- |"])
    source_only = [p for p in inventory["projects"] if p["supportState"] == "selected_source_only"]
    if source_only:
        for project in source_only:
            references = ", ".join(markdown_link(item["id"], item["immutableURL"]) for item in project["selectedSourceRecords"])
            lines.append(f"| {markdown_cell(project['projectID'])} | {references} | reference-only; license-unreviewed |")
    else:
        lines.append("| — | — | — |")
    lines.append("")
    return "\n".join(lines)


def generate(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    rules, rules_digest = read_json(args.rules)
    landscape, landscape_digest = read_json(args.landscape)
    cert, cert_digest = read_json(args.cert_contract)
    prom, prom_digest = read_json(args.prometheus_contract)
    spiffe, spiffe_digest = read_json(args.spiffe_profile)
    cloudevents, cloudevents_digest = read_json(args.cloudevents_profile)
    tikv, tikv_digest = read_json(args.tikv_profile)
    selected, selected_digest = read_json(args.selected_source_manifest)
    require(landscape.get("schema") == "prufyx.io/cncf-landscape/v1", "invalid landscape schema")
    raw_projects = landscape.get("projects")
    require(isinstance(raw_projects, list), "missing landscape projects")
    identities: dict[str, dict[str, Any]] = {}
    for identity in raw_projects:
        require(isinstance(identity, dict), "invalid landscape identity")
        project_id, name, url = identity.get("slug"), identity.get("name"), identity.get("repositoryURL")
        require(isinstance(project_id, str) and PROJECT_RE.fullmatch(project_id) is not None and len(project_id) <= 80 and project_id not in identities, "invalid landscape project ID")
        text(name, "landscape name")
        require(url is None or (isinstance(url, str) and (url == "" or text(url, "landscape project repository", MAX_URL))), "invalid landscape project repository")
        identities[project_id] = {"name": name, "repositoryURL": url or None}
    generic = generic_projects(rules, identities, preparer_projects(args.cncf_prepare_source))
    named = [named_project(cert, cert_digest, identities, "cert-manager-values"), named_project(prom, prom_digest, identities, "prometheus-mode")]
    conformance = [
        spiffe_conformance_project(spiffe, spiffe_digest, identities),
        cloudevents_conformance_project(cloudevents, cloudevents_digest, identities),
    ]
    target_preflight = [tikv_target_preflight_project(tikv, tikv_digest, identities)]
    projects = {item["projectID"]: item for item in generic}
    for item in named + conformance + target_preflight:
        require(item["projectID"] not in projects, "named check unexpectedly overlaps CNCF rule project")
        projects[item["projectID"]] = item
    selected_items, selected_provenance = selected_records(selected)
    selected_by_project: dict[str, list[dict[str, Any]]] = {}
    for record in selected_items:
        selected_by_project.setdefault(record["projectID"], []).append(record)
    for project_id, records in selected_by_project.items():
        if project_id in projects:
            projects[project_id]["selectedSourceRecords"] = records
            projects[project_id]["supportState"] = "executable_with_selected_source_records"
        else:
            projects[project_id] = {"projectID": project_id, "displayName": identities.get(project_id, {}).get("name", project_id), "repositoryURL": records[0]["canonicalRepositoryURL"], "supportState": "selected_source_only", "capabilities": [], "selectedSourceRecords": records}
    executable = [item for item in projects.values() if item["capabilities"]]
    source_only = [item for item in projects.values() if item["supportState"] == "selected_source_only"]
    cncf_rule_count = sum(len(item["capabilities"][0].get("rules", [])) for item in generic)
    require(cncf_rule_count == len(rules["entries"]), "CNCF rule count did not derive from the full rule pack")
    require(len({item["projectID"] for item in executable}) == len(executable), "duplicate executable project")
    inventory = {
        "schema": SCHEMA,
        "inputDigests": {"rules": rules_digest, "landscape": landscape_digest, "certManagerSourceContract": cert_digest, "prometheusSourceContract": prom_digest, "spiffeX509SVIDProfile": spiffe_digest, "cloudEventsStructuredJSONProfile": cloudevents_digest, "tikvGCPV2WIFBackupProfile": tikv_digest, "selectedSourceManifest": selected_digest},
        "selectedSourceProvenance": selected_provenance,
        "counts": {"cncfSourceRules": cncf_rule_count, "cncfRuleProjects": len(generic), "namedChecks": len(named), "namedCheckProjects": len(named), "conformanceProfiles": len(conformance), "conformanceProjects": len(conformance), "targetPreflightProfiles": len(target_preflight), "targetPreflightProjects": len(target_preflight), "executableProjects": len(executable), "selectedSourceRecords": len(selected_items), "selectedSourceProjects": len(selected_by_project), "selectedSourceOnlyProjects": len(source_only)},
        "scope": {"cncfRules": "embedded active source-rule pack; exact declared endpoints only", "namedChecks": "embedded local source contracts; exact reviewed transitions only", "conformanceProfiles": "named standards subsets without invented from/to transitions", "targetPreflightProfiles": "named target-only planned-operation setting checks without invented from/to transitions", "selectedSourceRecords": "retained public-source records; source selection alone does not create executable upgrade support", "wholeUpgrade": "UNKNOWN"},
        "projects": sorted(projects.values(), key=lambda item: item["projectID"]),
    }
    return inventory, render_markdown(inventory)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=Path, default=root / "internal/cncfcheck/data/rules.json")
    parser.add_argument("--landscape", type=Path, default=root / "internal/cncfcheck/data/landscape-projects.json")
    parser.add_argument("--cert-contract", type=Path, default=root / "internal/certmanagervalues/source-contract-v1.json")
    parser.add_argument("--prometheus-contract", type=Path, default=root / "internal/prometheusmode/source-contract-v1.json")
    parser.add_argument("--spiffe-profile", type=Path, default=root / "internal/spiffex509svid/data/profile.json")
    parser.add_argument("--cloudevents-profile", type=Path, default=root / "internal/cloudeventsstructuredjson/data/profile.json")
    parser.add_argument("--tikv-profile", type=Path, default=root / "internal/tikvgcpv2/data/profile.json")
    parser.add_argument("--cncf-prepare-source", type=Path, default=root / "internal/communityapp/cncf_prepare.go")
    parser.add_argument("--selected-source-manifest", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        inventory, markdown = generate(args)
        rendered_json = canonical(inventory)
        if args.check:
            require(args.json_output.is_file() and args.markdown_output.is_file(), "generated inventory is missing")
            require(args.json_output.read_bytes() == rendered_json, "generated JSON inventory is stale")
            require(args.markdown_output.read_text() == markdown, "generated Markdown inventory is stale")
        else:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_bytes(rendered_json)
            args.markdown_output.write_text(markdown)
    except (OSError, Invalid) as exc:
        print(f"support inventory: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
