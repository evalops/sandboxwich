# Base images are pinned by digest (not just tag) so a build is reproducible
# and can't silently pick up a new upstream image between builds. Refresh the
# digest with:
#   docker buildx imagetools inspect rust:1-bookworm
#   docker buildx imagetools inspect debian:bookworm-slim
# and update both the tag comment and the digest below together. Pulled via
# the Docker Hub mirror (mirror.gcr.io) -- which serves identical content by
# digest -- to avoid docker.io's anonymous-pull rate limit on shared
# self-hosted runners; the imagetools inspect commands above still target
# docker.io directly since that's the upstream source of truth for new tags.
FROM mirror.gcr.io/library/rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder

ARG BIN
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p "${BIN}" \
    && cp "target/release/${BIN}" /usr/local/bin/sandboxwich

# Shared multi-binary builder used ONLY by the kind conformance workflow
# (.github/workflows/kubernetes-conformance.yml), which builds the api and
# worker images back-to-back on a single runner. That workflow builds this
# stage's two sibling runtime images (see `runtime-shared` below) via a
# single `docker buildx bake` invocation; because this stage's instructions
# never vary with BIN, BuildKit resolves it once per bake invocation and
# shares the result between both images instead of compiling the workspace
# twice. containers.yml does NOT use this stage -- each service image there
# is still an independent native per-arch job built from `builder`/`runtime`
# above, unchanged.
FROM mirror.gcr.io/library/rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder-shared

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p sandboxwich-api -p sandboxwich-worker

# debian:bookworm-slim, see digest-refresh instructions above.
FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime-base

ARG KUBECTL_VERSION=v1.34.7
ARG TARGETARCH
# Which crate binary was built into this image (sandboxwich-api or
# sandboxwich-worker); carried into the runtime image as an ENV (ARGs aren't
# visible at container runtime) so HEALTHCHECK below can tell whether it's
# looking at the HTTP-serving api or the loop-only worker.
ARG BIN
ENV SANDBOXWICH_BIN=${BIN}

LABEL org.opencontainers.image.source="https://github.com/evalops/sandboxwich"
LABEL org.opencontainers.image.description="Sandboxwich Rust service image"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "${TARGETARCH}" in \
         amd64|arm64) kubectl_arch="${TARGETARCH}" ;; \
         *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${kubectl_arch}/kubectl" \
    && curl -fsSLo /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${kubectl_arch}/kubectl.sha256" \
    && echo "$(cat /tmp/kubectl.sha256)  /tmp/kubectl" | sha256sum --check --strict \
    && mv /tmp/kubectl /usr/local/bin/kubectl \
    && chmod 0755 /usr/local/bin/kubectl \
    && rm -f /tmp/kubectl.sha256 \
    && rm -rf /var/lib/apt/lists/*
# NOTE: curl is intentionally kept (not purged) in the final image -- HEALTHCHECK
# below needs it to probe the api's /healthz. This is a deliberate trade-off
# (slightly larger image / one more binary in the runtime image) for a working
# container-level health signal; the sandbox guest image is the one that
# should stay minimal, not this control-plane image.

# `runtime-shared`: same runtime-base image, but its binary comes from the
# shared multi-binary `builder-shared` stage above (kind workflow only; see
# comment there). Selecting the file by ARG BIN out of the already-compiled
# target/release/ directory is a plain COPY source substitution.
FROM runtime-base AS runtime-shared

# ARG scope is per-stage: without this redeclaration, whether ${BIN} expands
# in the COPY below is BuildKit-frontend-version-dependent (some versions
# expand it, others leave it empty -- which silently copies the ENTIRE
# target/release tree to /usr/local/bin/sandboxwich as a directory and
# breaks the entrypoint). Verified empirically across builders; never
# remove this line.
ARG BIN

COPY --from=builder-shared /src/target/release/${BIN} /usr/local/bin/sandboxwich

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "[ \"$SANDBOXWICH_BIN\" != sandboxwich-api ] || curl -fsS http://127.0.0.1:3217/healthz"]

ENTRYPOINT ["/usr/local/bin/sandboxwich"]

# `runtime`: containers.yml's image, byte-for-byte the same as before this
# refactor -- it must stay the LAST stage in this file so build invocations
# that omit --target (containers.yml's docker/build-push-action steps) keep
# resolving to it by BuildKit's implicit default-last-stage behavior.
FROM runtime-base AS runtime

COPY --from=builder /usr/local/bin/sandboxwich /usr/local/bin/sandboxwich

USER 65532:65532

# Only meaningful for the sandboxwich-api image: it's the only one of the two
# binaries built from this Dockerfile that serves HTTP (see /healthz in
# crates/sandboxwich-api/src/main.rs). For the worker image (a claim/execute
# loop with no listener), short-circuit to a no-op success so `docker ps`
# doesn't report a spuriously "unhealthy" container; Kubernetes doesn't use
# Docker's own HEALTHCHECK status anyway (the worker Deployment has no
# liveness/readiness probe, and the api Deployment's probes hit /healthz and
# /readyz directly).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "[ \"$SANDBOXWICH_BIN\" != sandboxwich-api ] || curl -fsS http://127.0.0.1:3217/healthz"]

ENTRYPOINT ["/usr/local/bin/sandboxwich"]
