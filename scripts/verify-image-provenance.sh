#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 IMAGE_REF SOURCE_REVISION DOCKERFILE_DIGEST DEPENDENCY_LOCK_DIGEST SUMMARY_FILE" >&2
  exit 2
fi

image_ref="$1"
source_revision="$2"
dockerfile_digest="$3"
dependency_lock_digest="$4"
summary_file="$5"
verify_signatures="${VERIFY_SIGNATURES:-false}"

[[ "${source_revision}" =~ ^[0-9a-f]{40}$ ]]
[[ "${dockerfile_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "${dependency_lock_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
docker buildx imagetools inspect "${image_ref}" --raw >"${tmp}/index.json"
docker buildx imagetools inspect "${image_ref}" --format '{{json .Provenance}}' >"${tmp}/provenance.json"
docker buildx imagetools inspect "${image_ref}" --format '{{json .SBOM}}' >"${tmp}/sbom.json"

jq -e '.mediaType == "application/vnd.oci.image.index.v1+json"' "${tmp}/index.json" >/dev/null
platforms=()
for platform in linux/amd64 linux/arm64; do
  arch="${platform#linux/}"
  digest="$(jq -r --arg arch "${arch}" '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest' "${tmp}/index.json")"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
  [[ "$(jq --arg digest "${digest}" '[.manifests[] | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest" and .annotations["vnd.docker.reference.digest"] == $digest)] | length' "${tmp}/index.json")" -eq 1 ]]
  jq -e \
    --arg platform "${platform}" \
    --arg arch "${arch}" \
    --arg revision "${source_revision}" \
    --arg dockerfile "${dockerfile_digest}" \
    --arg lock "${dependency_lock_digest}" \
    '.[$platform].SLSA.buildDefinition.externalParameters as $definition |
      $definition.configSource.request.args["vcs:revision"] == $revision and
      $definition.request.args["label:org.opencontainers.image.revision"] == $revision and
      $definition.request.args["label:dev.sandboxwich.build.runner-architecture"] == $arch and
      $definition.request.args["label:dev.sandboxwich.build.dockerfile-digest"] == $dockerfile and
      $definition.request.args["label:dev.sandboxwich.build.dependency-lock-digest"] == $lock' \
    "${tmp}/provenance.json" >/dev/null
  jq -e --arg platform "${platform}" '.[$platform].SPDX.packages | length > 0' "${tmp}/sbom.json" >/dev/null
  if [[ "${verify_signatures}" == true ]]; then
    cosign verify \
      --certificate-identity-regexp='https://github.com/evalops/sandboxwich/.github/workflows/containers.yml@refs/heads/main' \
      --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
      "${image_ref%@*}@${digest}" >/dev/null
  fi
  platforms+=("$(jq -cn --arg platform "${platform}" --arg digest "${digest}" '{platform:$platform,digest:$digest,sbom:true,provenance:true}')")
done

if [[ "${verify_signatures}" == true ]]; then
  cosign verify \
    --certificate-identity-regexp='https://github.com/evalops/sandboxwich/.github/workflows/containers.yml@refs/heads/main' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    "${image_ref}" >/dev/null
fi

printf '%s\n' "${platforms[@]}" | jq -s \
  --arg image "${image_ref}" \
  --arg source_revision "${source_revision}" \
  --arg dockerfile_digest "${dockerfile_digest}" \
  --arg dependency_lock_digest "${dependency_lock_digest}" \
  --argjson signatures_verified "$( [[ "${verify_signatures}" == true ]] && echo true || echo false )" \
  '{schema_version:"sandboxwich.image-provenance.v1",image:$image,source_revision:$source_revision,dockerfile_digest:$dockerfile_digest,dependency_lock_digest:$dependency_lock_digest,signatures_verified:$signatures_verified,platforms:.}' \
  >"${summary_file}"
