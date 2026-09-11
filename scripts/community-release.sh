#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly REQUIRED_GO_VERSION="go1.26.8"
readonly MODULE_PATH="github.com/prufyx/prufyx-cli"
readonly BUILD_IDENTITY_PACKAGE="${MODULE_PATH}/internal/buildidentity"
readonly COMMUNITY_ENTRYPOINT="./cmd/prufyx-community"
readonly COMMUNITY_GATE="cli/release/community-release-gate.py"
readonly COMMUNITY_POLICY="cli/release/community-shipping-policy-v2.json"
CLEANUP_PATH=""

cleanup() {
  if [ -n "$CLEANUP_PATH" ] && [ -d "$CLEANUP_PATH" ]; then
    rm -rf -- "$CLEANUP_PATH"
  fi
}
trap cleanup EXIT HUP INT TERM

die() {
  printf 'community release: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

repository_root() {
  git rev-parse --show-toplevel 2>/dev/null || die "run this command in a Git checkout"
}

resolve_output_dir() {
  local root=$1 candidate=$2 resolved
  mkdir -p "$candidate"
  [ ! -L "$candidate" ] || die "output directory cannot be a symlink"
  resolved=$(cd "$candidate" && pwd -P)
  case "$resolved" in
    "$root"|"$root"/*) die "OUTPUT_DIR must be outside the Git checkout" ;;
  esac
  printf '%s\n' "$resolved"
}

validate_version() {
  local version=$1
  [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
    die "version must be a v-prefixed semantic version"
}

validate_checkout() {
  local root=$1
  local revision expected_revision
  revision=$(git -C "$root" rev-parse --verify HEAD)
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die "HEAD is not an exact lowercase Git revision"
  git -C "$root" diff --quiet -- || die "tracked worktree changes are not release inputs"
  git -C "$root" diff --cached --quiet -- || die "staged changes are not release inputs"
  [ -z "$(git -C "$root" ls-files --others --exclude-standard)" ] ||
    die "untracked files are not release inputs"
  [ -z "$(git -C "$root" ls-files --others --ignored --exclude-standard)" ] ||
    die "ignored files are not release inputs"
  expected_revision=${EXPECTED_REVISION:-$revision}
  [ "$revision" = "$expected_revision" ] || die "checked-out revision differs from EXPECTED_REVISION"
  printf '%s\n' "$revision"
}

validate_toolchain() {
  local root=$1
  local actual module
  need go
  actual=$(GOOS= GOARCH= GOWORK=off GOTOOLCHAIN=local go env GOVERSION)
  [ "$actual" = "$REQUIRED_GO_VERSION" ] ||
    die "Go toolchain must be $REQUIRED_GO_VERSION, found $actual"
  [ -z "$(GOEXPERIMENT= go env GOEXPERIMENT)" ] || die "release builds require an empty GOEXPERIMENT"
  module=$(cd "$root/cli" && GOOS= GOARCH= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go list -mod=vendor -m)
  [ "$module" = "$MODULE_PATH" ] || die "release module identity differs"
  (cd "$root/cli" && GOOS= GOARCH= GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go list -mod=vendor -deps "$COMMUNITY_ENTRYPOINT" >/dev/null) ||
    die "vendored release module closure is inconsistent"
}

validate_jq() {
  local version
  need jq
  version=$(jq --version)
  JQ_VERSION="$version" python3 -B - <<'PY'
import os
import re

match = re.fullmatch(r"jq-(\d+)\.(\d+)(?:\.\d+)?(?:[-+].*)?", os.environ["JQ_VERSION"])
if match is None or tuple(map(int, match.groups())) < (1, 7):
    raise SystemExit("community release: jq 1.7 or newer is required for parity tests")
PY
}

source_tree_digest() {
  local stage=$1 archive=$2
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -cf "$archive" -C "$stage" .
  printf 'sha256:%s\n' "$(sha256_file "$archive")"
}

write_release_manifest() {
  local root=$1 output=$2
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python3 -B "$root/$COMMUNITY_GATE" \
    --source-root "$root" --policy "$root/$COMMUNITY_POLICY" --go "$(command -v go)" \
    generate --output "$output" >/dev/null
}

stage_release_source() {
  local root=$1 manifest=$2 stage=$3
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python3 -B "$root/$COMMUNITY_GATE" \
    --source-root "$root" --policy "$root/$COMMUNITY_POLICY" --go "$(command -v go)" \
    stage --manifest "$manifest" --output "$stage" >/dev/null
}

build_epoch() {
  git -C "$1" show -s --format=%ct "$2"
}

build_epoch_rfc3339() {
  date -u -d "@$1" '+%Y-%m-%dT%H:%M:%SZ'
}

validate_source_inputs() {
  local root=$1
  [ -f "$root/LICENSE" ] && [ ! -L "$root/LICENSE" ] || die "root LICENSE is required"
  [ -f "$root/NOTICE" ] && [ ! -L "$root/NOTICE" ] || die "root NOTICE is required"
  [ -f "$root/THIRD-PARTY.md" ] && [ ! -L "$root/THIRD-PARTY.md" ] || die "root THIRD-PARTY.md is required"
  [ -f "$root/LICENSES/Go-BSD-3-Clause.txt" ] && [ ! -L "$root/LICENSES/Go-BSD-3-Clause.txt" ] ||
    die "repository Go toolchain license is required"
  cmp -s "$root/LICENSES/Go-BSD-3-Clause.txt" "$(go env GOROOT)/LICENSE" ||
    die "repository Go license differs from the pinned toolchain license"
  if find "$root/LICENSES" -type l -o \! -type d \! -type f | grep . >/dev/null; then
    die "LICENSES may contain only regular files and directories"
  fi
  [ -n "$(find "$root/LICENSES" -type f -print -quit)" ] || die "LICENSES inventory is empty"
}

run_full_tests() {
  local root revision work manifest stage
  root=$(repository_root)
  revision=$(validate_checkout "$root")
  validate_source_inputs "$root"
  validate_toolchain "$root"
  need python3
  validate_jq
  printf 'testing revision %s on %s/%s\n' "$revision" "$(go env GOOS)" "$(go env GOARCH)" >&2
  work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-community-test.XXXXXX")
  CLEANUP_PATH=$work
  manifest="$work/SOURCE-MANIFEST.json"
  stage="$work/source"
  write_release_manifest "$root" "$manifest"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python3 -B "$root/$COMMUNITY_GATE" \
    --source-root "$root" --policy "$root/$COMMUNITY_POLICY" --go "$(command -v go)" \
    stage --manifest "$manifest" --output "$stage" --run-native-checks >/dev/null
  (cd "$stage/cli" && CGO_ENABLED=1 GOEXPERIMENT= GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go test -race ./... -count=1)
}

write_metadata() {
  local path=$1 version=$2 revision=$3 source_digest=$4 manifest_digest=$5 target=$6 epoch=$7 go_version=$8
  VERSION="$version" REVISION="$revision" SOURCE_DIGEST="$source_digest" TARGET="$target" \
    MANIFEST_DIGEST="$manifest_digest" BUILD_EPOCH="$epoch" GO_VERSION="$go_version" python3 -B - "$path" <<'PY'
import json
import os
import pathlib
import sys

value = {
    "schemaVersion": "prufyx.io/community-release-metadata/v1",
    "version": os.environ["VERSION"],
    "sourceRevision": os.environ["REVISION"],
    "sourceTreeDigest": os.environ["SOURCE_DIGEST"],
    "sourceTreeDigestAlgorithm": "sha256(canonical tar of exact Community source stage)",
    "allowlistDigest": os.environ["MANIFEST_DIGEST"],
    "releaseManifestDigest": os.environ["MANIFEST_DIGEST"],
    "releaseManifestAlgorithm": "sha256(canonical JSON source-manifest receipt bytes)",
    "target": os.environ["TARGET"],
    "targetArchitectureLevel": "v1" if os.environ["TARGET"] == "linux-amd64" else "v8.0",
    "cgoEnabled": False,
    "buildEpoch": int(os.environ["BUILD_EPOCH"]),
    "goVersion": os.environ["GO_VERSION"],
    "trustRootDigest": "UNPINNED",
    "candidateOnly": True,
    "compatibilityAuthority": "none",
    "artifactProvenance": "Metadata is not an OIDC attestation; independently verify any separately published attestation against the exact artifact and trusted workflow identity",
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

verify_version_output() {
  local binary=$1 metadata=$2 output
  output=$("$binary" version)
  VERSION_OUTPUT="$output" python3 -B - "$metadata" <<'PY'
import json
import os
import sys

metadata = json.loads(open(sys.argv[1], encoding="utf-8").read())
reported = json.loads(os.environ["VERSION_OUTPUT"])
data = reported.get("data", {})
expected = {
    "version": metadata["version"],
    "releaseState": "release",
    "sourceRevision": metadata["sourceRevision"],
    "sourceTreeDigest": metadata["sourceTreeDigest"],
    "allowlistDigest": metadata["allowlistDigest"],
    "buildProfile": metadata["target"],
    "goVersion": metadata["goVersion"],
    "trustRootDigest": "UNPINNED",
    "candidateOnly": True,
}
for key, value in expected.items():
    if data.get(key) != value:
        raise SystemExit(f"version identity mismatch for {key}")
if reported.get("result", {}).get("status") != "OK":
    raise SystemExit("version command did not return OK")
PY
}

verify_prometheus_demo() {
  local binary=$1 output status
  set +e
  output=$("$binary" check prometheus-mode --demo --format json)
  status=$?
  set -e
  [ "$status" -eq 11 ] || die "Prometheus demo must return aggregate UNKNOWN with exit 11, got $status"
  DEMO_OUTPUT="$output" python3 -B - <<'PY'
import json
import os

raw = os.environ["DEMO_OUTPUT"]
value = json.loads(raw)
if value.get("aggregate") != "UNKNOWN" or value.get("status") != "SYNTHETIC_DEMONSTRATION":
    raise SystemExit("Prometheus demo aggregate is not UNKNOWN")
for required in ("2.55.1", "3.1.0", "linux/arm64/v8"):
    if required not in raw:
        raise SystemExit(f"Prometheus demo omitted exact pin {required}")
PY
}

smoke_binary_archive() {
  local version=$1 target=$2 out_dir=$3 os_name arch version_number archive package_name
  local work package_dir binary values karmada prepared version_report cert_report karmada_report status archive_digest
  validate_version "$version"
  case "$target" in
    linux-amd64) os_name=linux; arch=amd64 ;;
    linux-arm64) os_name=linux; arch=arm64 ;;
    *) die "release target must be linux-amd64 or linux-arm64" ;;
  esac
  [ -d "$out_dir" ] && [ ! -L "$out_dir" ] || die "archive output directory is unavailable"
  out_dir=$(cd "$out_dir" && pwd -P)
  version_number=${version#v}
  archive="$out_dir/prufyx-cli_${version_number}_${os_name}_${arch}.tar.gz"
  [ -f "$archive" ] && [ ! -L "$archive" ] || die "native archive is unavailable"
  archive_digest="sha256:$(sha256_file "$archive")"
  work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-community-smoke.XXXXXX")
  CLEANUP_PATH=$work
  umask 077
  tar -xzf "$archive" -C "$work"
  package_name="prufyx-cli_${version_number}_${os_name}_${arch}"
  package_dir="$work/$package_name"
  binary="$package_dir/prufyx"
  [ -d "$package_dir" ] && [ ! -L "$package_dir" ] && [ -f "$binary" ] && [ ! -L "$binary" ] ||
    die "archive package layout is invalid"
  [ "$(find "$work" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" = "1" ] ||
    die "archive extraction contains unexpected top-level paths"
  [ ! -e "$package_dir/go.mod" ] && [ ! -e "$package_dir/.git" ] ||
    die "archive-only smoke must not contain a source tree"
  chmod 0755 "$binary"
  mkdir -m 0700 "$work/home"
  version_report="$work/version.json"
  env -i PATH="$PATH" HOME="$work/home" TZ=UTC "$binary" version >"$version_report"
  VERSION_REPORT="$version_report" METADATA="$package_dir/RELEASE-METADATA.json" VERSION="$version" TARGET="$target" python3 -B - <<'PY'
import json
import os
import pathlib

metadata = json.loads(pathlib.Path(os.environ["METADATA"]).read_text(encoding="utf-8"))
report = json.loads(pathlib.Path(os.environ["VERSION_REPORT"]).read_text(encoding="utf-8"))
data = report.get("data", {})
if report.get("result", {}).get("status") != "OK":
    raise SystemExit("archive version command did not return OK")
for key, value in {
    "version": os.environ["VERSION"],
    "buildProfile": os.environ["TARGET"],
    "sourceRevision": metadata.get("sourceRevision"),
    "sourceTreeDigest": metadata.get("sourceTreeDigest"),
    "allowlistDigest": metadata.get("allowlistDigest"),
    "candidateOnly": True,
    "trustRootDigest": "UNPINNED",
}.items():
    if data.get(key) != value:
        raise SystemExit(f"archive version identity mismatch for {key}")
expected_revision = os.environ.get("EXPECTED_REVISION", "")
if expected_revision and (metadata.get("sourceRevision") != expected_revision or data.get("sourceRevision") != expected_revision):
    raise SystemExit("archive version source revision differs from EXPECTED_REVISION")
if not metadata.get("artifactProvenance", "").startswith("Metadata is not an OIDC attestation"):
    raise SystemExit("archive metadata must not claim a local production attestation")
PY
  values="$work/cert-manager-values.json"
  printf '%s\n' '{"prometheus":{"servicemonitor":{"path":"/release-smoke"}}}' >"$values"
  chmod 0600 "$values"
  cert_report="$work/cert-manager-report.json"
  set +e
  env -i PATH="$PATH" HOME="$work/home" TZ=UTC "$binary" check cert-manager-values \
    --from 1.20.3 --to 1.21.1 --values "$values" --format json >"$cert_report"
  status=$?
  set -e
  [ "$status" -eq 10 ] || die "cert-manager archive smoke must return scoped BLOCKED/10"
  CERT_REPORT="$cert_report" python3 -B - <<'PY'
import json
import os
import pathlib

report = json.loads(pathlib.Path(os.environ["CERT_REPORT"]).read_text(encoding="utf-8"))
if report.get("assessment") != "UNKNOWN" or report.get("claim", {}).get("status") != "BLOCKED":
    raise SystemExit("cert-manager archive smoke changed scoped or aggregate result")
PY
  karmada="$work/karmada-policy.json"
  printf '%s\n' '{"apiVersion":"policy.karmada.io/v1alpha1","kind":"PropagationPolicy","metadata":{"name":"release-smoke"},"spec":{"failover":{"application":{"purgeMode":"Immediately"}}}}' >"$karmada"
  chmod 0600 "$karmada"
  prepared="$work/karmada-input.json"
  env -i PATH="$PATH" HOME="$work/home" TZ=UTC "$binary" prepare cncf --project karmada \
    --input "$karmada" --from 1.18.3 --to 1.19.0 --distribution official_upstream \
    --target-policy-crd-admission required --format input >"$prepared"
  chmod 0600 "$prepared"
  karmada_report="$work/karmada-report.json"
  set +e
  env -i PATH="$PATH" HOME="$work/home" TZ=UTC "$binary" check cncf --project karmada \
    --input "$prepared" --now 2026-09-09T05:00:00Z --format json >"$karmada_report"
  status=$?
  set -e
  [ "$status" -eq 10 ] || die "Karmada archive smoke must return scoped BLOCKED/10"
  KARMADA_REPORT="$karmada_report" python3 -B - <<'PY'
import json
import os
import pathlib

report = json.loads(pathlib.Path(os.environ["KARMADA_REPORT"]).read_text(encoding="utf-8"))
claims = report.get("check", {}).get("claims", [])
if report.get("assessment") != "UNKNOWN" or not any(claim.get("status") == "BLOCKED" for claim in claims):
    raise SystemExit("Karmada archive smoke changed scoped or aggregate result")
if report.get("runtimeReproduced") != 0 or report.get("networkUsed") is not False:
    raise SystemExit("Karmada archive smoke claimed runtime or network evidence")
PY
  VERSION="$version" TARGET="$target" ARCHIVE_DIGEST="$archive_digest" METADATA="$package_dir/RELEASE-METADATA.json" python3 -B - <<'PY'
import json
import os
import pathlib

metadata = json.loads(pathlib.Path(os.environ["METADATA"]).read_text(encoding="utf-8"))
receipt = {
    "schemaVersion": "prufyx.io/community-archive-smoke/v1",
    "archiveDigest": os.environ["ARCHIVE_DIGEST"],
    "candidateOnly": True,
    "certManager": {"aggregate": "UNKNOWN", "exitCode": 10, "scopedStatus": "BLOCKED"},
    "karmada": {"aggregate": "UNKNOWN", "atLeastOneScopedBlocked": True, "exitCode": 10, "networkUsed": False, "runtimeReproduced": 0},
    "sourceRevision": metadata["sourceRevision"],
    "target": os.environ["TARGET"],
    "trustRootDigest": "UNPINNED",
    "version": os.environ["VERSION"],
    "versionCommandStatus": "OK",
}
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
PY
}

build_binary_archive() {
  local version=$1 target=$2 out_dir=$3
  local root revision os_name arch host_os host_arch epoch epoch_text version_number
  local work source_stage source_tar release_manifest source_digest allowlist_digest go_version marker binary archive package_dir metadata
  validate_version "$version"
  case "$target" in
    linux-amd64) os_name=linux; arch=amd64 ;;
    linux-arm64) os_name=linux; arch=arm64 ;;
    *) die "release target must be linux-amd64 or linux-arm64" ;;
  esac
  root=$(repository_root)
  revision=$(validate_checkout "$root")
  validate_source_inputs "$root"
  validate_toolchain "$root"
  host_os=$(GOOS= GOARCH= GOWORK=off go env GOHOSTOS)
  host_arch=$(GOOS= GOARCH= GOWORK=off go env GOHOSTARCH)
  [ "$host_os/$host_arch" = "$os_name/$arch" ] ||
    die "$target must be built and exercised on a native $os_name/$arch runner"
  out_dir=$(resolve_output_dir "$root" "$out_dir")
  version_number=${version#v}
  archive="$out_dir/prufyx-cli_${version_number}_${os_name}_${arch}.tar.gz"
  [ ! -e "$archive" ] || die "refusing to overwrite $archive"
  work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-community-release.XXXXXX")
  CLEANUP_PATH=$work
  source_stage="$work/source"
  source_tar="$work/source-tree.tar"
  release_manifest="$work/SOURCE-MANIFEST.json"
  write_release_manifest "$root" "$release_manifest"
  stage_release_source "$root" "$release_manifest" "$source_stage"
  source_digest=$(source_tree_digest "$source_stage" "$source_tar")
  allowlist_digest="sha256:$(sha256_file "$release_manifest")"
  epoch=$(build_epoch "$root" "$revision")
  epoch_text=$(build_epoch_rfc3339 "$epoch")
  go_version=$(go env GOVERSION)
  marker="PRUFYX_BUILD_IDENTITY_V1_BEGIN|${version}|release|${revision}|${source_digest}|${allowlist_digest}|${target}|${epoch_text}|${go_version}|UNPINNED|true|PRUFYX_BUILD_IDENTITY_V1_END"
  package_dir="$work/prufyx-cli_${version_number}_${os_name}_${arch}"
  mkdir -m 0755 "$package_dir"
  binary="$package_dir/prufyx"
  (
    cd "$source_stage/cli"
    CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT= \
      GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' \
      SOURCE_DATE_EPOCH="$epoch" GOOS="$os_name" GOARCH="$arch" \
      go build -trimpath -buildvcs=false \
      -ldflags="-buildid= -s -w \
        -X ${BUILD_IDENTITY_PACKAGE}.Version=${version} \
        -X ${BUILD_IDENTITY_PACKAGE}.SourceRevision=${revision} \
        -X ${BUILD_IDENTITY_PACKAGE}.SourceTreeDigest=${source_digest} \
        -X ${BUILD_IDENTITY_PACKAGE}.AllowlistDigest=${allowlist_digest} \
        -X ${BUILD_IDENTITY_PACKAGE}.BuildProfile=${target} \
        -X ${BUILD_IDENTITY_PACKAGE}.BuildEpoch=${epoch} \
        -X ${BUILD_IDENTITY_PACKAGE}.TrustRootDigest=UNPINNED \
        -X ${BUILD_IDENTITY_PACKAGE}.EmbeddedIdentity=${marker}" \
      -o "$binary" "$COMMUNITY_ENTRYPOINT"
  )
  chmod 0755 "$binary"
  metadata="$package_dir/RELEASE-METADATA.json"
  write_metadata "$metadata" "$version" "$revision" "$source_digest" "$allowlist_digest" "$target" "$epoch" "$go_version"
  install -m 0644 "$source_stage/LICENSE" "$package_dir/LICENSE"
  install -m 0644 "$source_stage/NOTICE" "$package_dir/NOTICE"
  install -m 0644 "$source_stage/THIRD-PARTY.md" "$package_dir/THIRD-PARTY.md"
  cp -R "$source_stage/LICENSES" "$package_dir/LICENSES"
  find "$package_dir/LICENSES" -type d -exec chmod 0755 {} +
  find "$package_dir/LICENSES" -type f -exec chmod 0644 {} +
  printf '%s\n' "$revision" >"$package_dir/SOURCE-REVISION"
  verify_version_output "$binary" "$metadata"
  verify_prometheus_demo "$binary"
  find "$package_dir" -exec touch -h -d "@$epoch" {} +
  tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -cf - -C "$work" "$(basename "$package_dir")" |
    gzip -n >"$archive"
  printf '%s\n' "$archive"
}

build_source_archive() {
  local version=$1 out_dir=$2 root revision version_number archive work source_stage source_tar source_digest release_manifest
  validate_version "$version"
  root=$(repository_root)
  revision=$(validate_checkout "$root")
  validate_source_inputs "$root"
  out_dir=$(resolve_output_dir "$root" "$out_dir")
  version_number=${version#v}
  archive="$out_dir/prufyx-cli_${version_number}_source.tar.gz"
  [ ! -e "$archive" ] || die "refusing to overwrite $archive"
  work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-community-source.XXXXXX")
  CLEANUP_PATH=$work
  source_stage="$work/source"
  source_tar="$work/source-tree.tar"
  release_manifest="$out_dir/SOURCE-MANIFEST.json"
  write_release_manifest "$root" "$release_manifest"
  stage_release_source "$root" "$release_manifest" "$source_stage"
  source_digest=$(source_tree_digest "$source_stage" "$source_tar")
  mv "$source_stage" "$work/prufyx-cli_${version_number}_source"
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -cf - -C "$work" "prufyx-cli_${version_number}_source" |
    gzip -n >"$archive"
  printf '%s\n' "$revision" >"$out_dir/SOURCE-REVISION"
  printf '%s  source-tree.tar\n' "${source_digest#sha256:}" >"$out_dir/SOURCE-TREE.sha256"
  printf '%s\n' "$archive"
}

write_sbom() {
  local path=$1 version=$2 revision=$3 epoch=$4 go_version=$5 root
  root=$(repository_root)
  VERSION="$version" REVISION="$revision" BUILD_EPOCH="$epoch" GO_VERSION="$go_version" POLICY_PATH="$root/$COMMUNITY_POLICY" \
    python3 -B - "$path" <<'PY'
import datetime
import json
import os
import pathlib
import sys

version = os.environ["VERSION"]
revision = os.environ["REVISION"]
go_version = os.environ["GO_VERSION"]
created = datetime.datetime.fromtimestamp(
    int(os.environ["BUILD_EPOCH"]), datetime.timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")
policy = json.loads(pathlib.Path(os.environ["POLICY_PATH"]).read_text(encoding="utf-8"))
value = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"prufyx-cli-{version}-release-components",
    "documentNamespace": f"https://github.com/prufyx/prufyx-cli/releases/tag/{version}/sbom-{revision}",
    "creationInfo": {
        "created": created,
        "creators": ["Tool: prufyx-community-release"],
    },
    "documentDescribes": ["SPDXRef-Package-PrufyxCLI"],
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-PrufyxCLI",
            "name": "prufyx-cli",
            "versionInfo": version,
            "downloadLocation": f"https://github.com/prufyx/prufyx-cli/tree/{revision}",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "Copyright 2026 Spas Atanasov",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:golang/github.com/prufyx/prufyx-cli@{version}",
            }],
        },
        {
            "SPDXID": "SPDXRef-Package-Go",
            "name": "Go runtime and standard library",
            "versionInfo": go_version.removeprefix("go"),
            "downloadLocation": f"https://go.dev/dl/{go_version}.src.tar.gz",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "BSD-3-Clause",
            "copyrightText": "Copyright 2009 The Go Authors",
            "checksums": [{
                "algorithm": "SHA256",
                "checksumValue": "4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e",
            }],
            "comment": "The reviewed LICENSES directory carries exact notices for the selected CGO-disabled linux/amd64 and linux/arm64 Go 1.26.8 build closure.",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:golang/std@{go_version.removeprefix('go')}",
            }],
        },
        {
            "SPDXID": "SPDXRef-Package-Python",
            "name": "Python interpreter floor for shipped operator tools",
            "versionInfo": "3.8",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": "The shipped local collector helpers require Python 3.8 or newer; Python is not embedded in the Prufyx binary or source archive.",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:generic/python@3.8",
            }],
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-PrufyxCLI",
        },
        {
            "spdxElementId": "SPDXRef-Package-PrufyxCLI",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-Go",
        },
        {
            "spdxElementId": "SPDXRef-Package-PrufyxCLI",
            "relationshipType": "OTHER",
            "relatedSpdxElement": "SPDXRef-Package-Python",
            "comment": "Optional operator-tool runtime dependency",
        },
    ],
}
for index, module in enumerate(policy["externalModules"], 1):
    spdx_id = f"SPDXRef-Package-GoModule-{index:02d}"
    value["packages"].append({
        "SPDXID": spdx_id,
        "name": module["path"],
        "versionInfo": module["version"],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": module["licenseDeclared"],
        "copyrightText": "NOASSERTION",
        "comment": f"Vendored Go module bound by module sum {module['moduleSum']} and go.mod sum {module['goModSum']}.",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": f"pkg:golang/{module['path']}@{module['version']}",
        }],
    })
    value["relationships"].append({
        "spdxElementId": "SPDXRef-Package-PrufyxCLI",
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": spdx_id,
    })
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

finalize_release() {
  local version=$1 out_dir=$2 root revision version_number expected actual epoch go_version
  validate_version "$version"
  root=$(repository_root)
  revision=$(validate_checkout "$root")
  validate_toolchain "$root"
  validate_source_inputs "$root"
  version_number=${version#v}
  out_dir=$(resolve_output_dir "$root" "$out_dir")
  install -m 0644 "$root/LICENSE" "$out_dir/LICENSE"
  install -m 0644 "$root/NOTICE" "$out_dir/NOTICE"
  install -m 0644 "$root/THIRD-PARTY.md" "$out_dir/THIRD-PARTY.md"
  install -m 0644 "$root/LICENSES/Go-BSD-3-Clause.txt" "$out_dir/Go-BSD-3-Clause.txt"
  epoch=$(build_epoch "$root" "$revision")
  go_version=$(go env GOVERSION)
  write_sbom "$out_dir/SBOM.spdx.json" "$version" "$revision" "$epoch" "$go_version"
  expected=$(printf '%s\n' \
    LICENSE \
    NOTICE \
    THIRD-PARTY.md \
    Go-BSD-3-Clause.txt \
    SBOM.spdx.json \
    SOURCE-MANIFEST.json \
    SOURCE-REVISION \
    SOURCE-TREE.sha256 \
    "prufyx-cli_${version_number}_linux_amd64.tar.gz" \
    "prufyx-cli_${version_number}_linux_arm64.tar.gz" \
    "prufyx-cli_${version_number}_source.tar.gz" | LC_ALL=C sort)
  actual=$(find "$out_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort)
  [ "$actual" = "$expected" ] || die "release output contains missing or unexpected files before checksums"
  (
    cd "$out_dir"
    : >SHA256SUMS
    while IFS= read -r name; do
      printf '%s  %s\n' "$(sha256_file "$name")" "$name" >>SHA256SUMS
    done <<<"$expected"
  )
}

verify_release() {
  local version=$1 out_dir=$2 root revision version_number expected actual work source_archive source_digest epoch go_version
  validate_version "$version"
  root=$(repository_root)
  revision=$(validate_checkout "$root")
  version_number=${version#v}
  validate_toolchain "$root"
  validate_source_inputs "$root"
  out_dir=$(resolve_output_dir "$root" "$out_dir")
  expected=$(printf '%s\n' \
    LICENSE \
    NOTICE \
    THIRD-PARTY.md \
    Go-BSD-3-Clause.txt \
    SHA256SUMS \
    SBOM.spdx.json \
    SOURCE-MANIFEST.json \
    SOURCE-REVISION \
    SOURCE-TREE.sha256 \
    "prufyx-cli_${version_number}_linux_amd64.tar.gz" \
    "prufyx-cli_${version_number}_linux_arm64.tar.gz" \
    "prufyx-cli_${version_number}_source.tar.gz" | LC_ALL=C sort)
  actual=$(find "$out_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort)
  [ "$actual" = "$expected" ] || die "release output contains missing or unexpected files"
  (cd "$out_dir" && sha256sum -c SHA256SUMS)
  [ "$(tr -d '\n' <"$out_dir/SOURCE-REVISION")" = "$revision" ] || die "source revision asset mismatch"
  work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-community-verify.XXXXXX")
  CLEANUP_PATH=$work
  source_archive="$out_dir/prufyx-cli_${version_number}_source.tar.gz"
  gzip -cd "$source_archive" >"$work/source-prefixed.tar"
  tar -tf "$work/source-prefixed.tar" | grep -Fx "prufyx-cli_${version_number}_source/LICENSE" >/dev/null ||
    die "source archive omits LICENSE"
  write_release_manifest "$root" "$work/SOURCE-MANIFEST.json"
  stage_release_source "$root" "$work/SOURCE-MANIFEST.json" "$work/expected-source"
  source_digest=$(source_tree_digest "$work/expected-source" "$work/source-tree.tar")
  [ "$(awk '{print $1}' "$out_dir/SOURCE-TREE.sha256")" = "${source_digest#sha256:}" ] ||
    die "source tree digest asset mismatch"
  cmp -s "$work/SOURCE-MANIFEST.json" "$out_dir/SOURCE-MANIFEST.json" || die "source manifest differs from exact Community policy and source bytes"
  mv "$work/expected-source" "$work/prufyx-cli_${version_number}_source"
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -cf - -C "$work" "prufyx-cli_${version_number}_source" |
    gzip -n >"$work/source-expected.tar.gz"
  cmp -s "$work/source-expected.tar.gz" "$source_archive" || die "source archive differs from exact Community source stage"
  epoch=$(build_epoch "$root" "$revision")
  go_version=$(go env GOVERSION)
  write_sbom "$work/SBOM.spdx.json" "$version" "$revision" "$epoch" "$go_version"
  cmp -s "$work/SBOM.spdx.json" "$out_dir/SBOM.spdx.json" || die "SBOM differs from exact release inputs"
  for target in linux_amd64 linux_arm64; do
    local package_name expected_members actual_members license_members target_profile
    package_name="prufyx-cli_${version_number}_${target}"
    target_profile=${target/_/-}
    license_members=$(find "$root/LICENSES" -print | while IFS= read -r path; do
      if [ -d "$path" ]; then
        printf '%s/%s/\n' "$package_name" "${path#"$root/"}"
      else
        printf '%s/%s\n' "$package_name" "${path#"$root/"}"
      fi
    done)
    expected_members=$(printf '%s\n' \
      "$package_name/" \
      "$package_name/LICENSE" \
      "$package_name/NOTICE" \
      "$package_name/RELEASE-METADATA.json" \
      "$package_name/SOURCE-REVISION" \
      "$package_name/THIRD-PARTY.md" \
      "$package_name/prufyx" \
      "$license_members" | LC_ALL=C sort)
    actual_members=$(tar -tzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" | LC_ALL=C sort)
    [ "$actual_members" = "$expected_members" ] || die "$target archive member set differs"
    ARCHIVE="$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" PACKAGE_NAME="$package_name" \
      REPOSITORY_ROOT="$root" BUILD_EPOCH="$epoch" python3 -B - <<'PY'
import os
import pathlib
import tarfile

archive = pathlib.Path(os.environ["ARCHIVE"])
package = os.environ["PACKAGE_NAME"]
root = pathlib.Path(os.environ["REPOSITORY_ROOT"])
epoch = int(os.environ["BUILD_EPOCH"])
seen = set()
with tarfile.open(archive, "r:gz") as source:
    for member in source.getmembers():
        if member.name in seen:
            raise SystemExit("binary archive contains a duplicate member")
        seen.add(member.name)
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise SystemExit("binary archive contains an unsafe member name")
        if member.pax_headers or member.linkname or member.uid != 0 or member.gid != 0 or member.uname or member.gname or member.mtime != epoch:
            raise SystemExit("binary archive contains non-canonical header metadata")
        relative = pathlib.PurePosixPath(*path.parts[1:]).as_posix() if len(path.parts) > 1 else ""
        repository_path = root / relative if relative else None
        should_be_directory = relative == "" or (
            (relative == "LICENSES" or relative.startswith("LICENSES/"))
            and repository_path is not None
            and repository_path.is_dir()
        )
        if should_be_directory:
            if not member.isdir() or member.mode != 0o755:
                raise SystemExit("binary archive directory header differs")
        else:
            expected_mode = 0o755 if relative == "prufyx" else 0o644
            if not member.isreg() or member.mode != expected_mode:
                raise SystemExit("binary archive file header differs")
PY
    for path in LICENSE NOTICE THIRD-PARTY.md; do
      tar -xOzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" \
        "$package_name/$path" | cmp -s - "$root/$path" || die "$target archive differs: $path"
    done
    while IFS= read -r path; do
      tar -xOzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" \
        "$package_name/$path" | cmp -s - "$root/$path" || die "$target archive license differs: $path"
    done < <(find "$root/LICENSES" -type f -print | sed "s#^$root/##" | LC_ALL=C sort)
    tar -xOzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" \
      "$package_name/RELEASE-METADATA.json" >"$work/${target}.metadata.json"
    tar -xOzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" \
      "$package_name/SOURCE-REVISION" >"$work/${target}.revision"
    local allowlist_digest epoch_text marker
    allowlist_digest="sha256:$(sha256_file "$out_dir/SOURCE-MANIFEST.json")"
    write_metadata "$work/${target}.expected.metadata.json" "$version" "$revision" "$source_digest" \
      "$allowlist_digest" "$target_profile" "$epoch" "$go_version"
    cmp -s "$work/${target}.metadata.json" "$work/${target}.expected.metadata.json" ||
      die "$target release metadata differs from exact release inputs"
    printf '%s\n' "$revision" >"$work/${target}.expected.revision"
    cmp -s "$work/${target}.revision" "$work/${target}.expected.revision" ||
      die "$target revision file differs from exact release inputs"
    tar -xOzf "$out_dir/prufyx-cli_${version_number}_${target}.tar.gz" \
      "$package_name/prufyx" >"$work/${target}.prufyx"
    chmod 0755 "$work/${target}.prufyx"
    epoch_text=$(build_epoch_rfc3339 "$epoch")
    marker="PRUFYX_BUILD_IDENTITY_V1_BEGIN|${version}|release|${revision}|${source_digest}|${allowlist_digest}|${target_profile}|${epoch_text}|${go_version}|UNPINNED|true|PRUFYX_BUILD_IDENTITY_V1_END"
    BINARY="$work/${target}.prufyx" MARKER="$marker" python3 -B - <<'PY'
import os
import pathlib

data = pathlib.Path(os.environ["BINARY"]).read_bytes()
marker = os.environ["MARKER"].encode("ascii")
if data.count(marker) != 1:
    raise SystemExit("binary does not contain exactly one canonical release identity marker")
PY
    go version -m "$work/${target}.prufyx" >"$work/${target}.buildinfo"
    head -n 1 "$work/${target}.buildinfo" | grep -E ': go1\.26\.8$' >/dev/null || die "$target binary build info has wrong Go version"
    grep -F $'\tbuild\tCGO_ENABLED=0' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info omits CGO_ENABLED=0"
    grep -F $'\tbuild\tGOOS=linux' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info has wrong GOOS"
    if [ "$target" = linux_amd64 ]; then
      grep -F $'\tbuild\tGOARCH=amd64' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info has wrong GOARCH"
      grep -F $'\tbuild\tGOAMD64=v1' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info has wrong GOAMD64"
    else
      grep -F $'\tbuild\tGOARCH=arm64' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info has wrong GOARCH"
      grep -F $'\tbuild\tGOARM64=v8.0' "$work/${target}.buildinfo" >/dev/null || die "$target binary build info has wrong GOARM64"
    fi
    if grep -F $'\tbuild\tGOEXPERIMENT=' "$work/${target}.buildinfo" >/dev/null ||
      grep -F $'\tbuild\t-race=true' "$work/${target}.buildinfo" >/dev/null; then
      die "$target binary build info selects an unreviewed experiment or race runtime"
    fi
  done
}

usage() {
  cat >&2 <<'EOF'
usage:
  community-release.sh test
  community-release.sh binary VERSION linux-amd64|linux-arm64 OUTPUT_DIR
  community-release.sh smoke VERSION linux-amd64|linux-arm64 OUTPUT_DIR
  community-release.sh source VERSION OUTPUT_DIR
  community-release.sh finalize VERSION OUTPUT_DIR
  community-release.sh verify VERSION OUTPUT_DIR
EOF
  exit 2
}

command_name=${1:-}
case "$command_name" in
  test)
    [ "$#" -eq 1 ] || usage
    run_full_tests
    ;;
  binary)
    [ "$#" -eq 4 ] || usage
    build_binary_archive "$2" "$3" "$4"
    ;;
  smoke)
    [ "$#" -eq 4 ] || usage
    smoke_binary_archive "$2" "$3" "$4"
    ;;
  source)
    [ "$#" -eq 3 ] || usage
    build_source_archive "$2" "$3"
    ;;
  finalize)
    [ "$#" -eq 3 ] || usage
    finalize_release "$2" "$3"
    ;;
  verify)
    [ "$#" -eq 3 ] || usage
    verify_release "$2" "$3"
    ;;
  *) usage ;;
esac
