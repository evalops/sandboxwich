# Base images are pinned by digest (not just tag) so a build is reproducible
# and can't silently pick up a new upstream image between builds. Refresh the
# digest with:
#   docker buildx imagetools inspect rust:1-bookworm
#   docker buildx imagetools inspect debian:bookworm-slim
# and update both the tag comment and the digest below together.
FROM rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder

ARG BIN
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p "${BIN}" \
    && cp "target/release/${BIN}" /usr/local/bin/sandboxwich

# debian:bookworm-slim, see digest-refresh instructions above.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

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
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${kubectl_arch}/kubectl" \
    && chmod 0755 /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/*
# NOTE: curl is intentionally kept (not purged) in the final image -- HEALTHCHECK
# below needs it to probe the api's /healthz. This is a deliberate trade-off
# (slightly larger image / one more binary in the runtime image) for a working
# container-level health signal; the sandbox guest image is the one that
# should stay minimal, not this control-plane image.

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
