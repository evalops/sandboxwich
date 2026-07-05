FROM rust:1-bookworm AS builder

ARG BIN
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p "${BIN}" \
    && cp "target/release/${BIN}" /usr/local/bin/sandboxwich

FROM debian:bookworm-slim AS runtime

ARG KUBECTL_VERSION=v1.34.7
ARG TARGETARCH

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
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/sandboxwich /usr/local/bin/sandboxwich

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sandboxwich"]
