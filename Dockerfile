FROM rust:1-bookworm AS builder

ARG BIN
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p "${BIN}" \
    && cp "target/release/${BIN}" /usr/local/bin/sandboxwich

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/evalops/sandboxwich"
LABEL org.opencontainers.image.description="Sandboxwich Rust service image"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/sandboxwich /usr/local/bin/sandboxwich

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sandboxwich"]
