# ubuntu:24.04 multi-architecture index, refreshed 2026-07-09.
# Pulled via the Docker Hub mirror (mirror.gcr.io) to avoid docker.io's
# anonymous-pull rate limit on shared self-hosted runners.
# This org-local mirror carries Orb's executor and agent toolchain for the
# exact control-plane protocol revision. Sandboxwich layers its guest daemon
# and desktop entrypoint on top of those binaries below.
ARG ORB_EXECUTOR_IMAGE=ghcr.io/evalops/sandboxwich-orb-executor@sha256:42326731c8ea005923b7dd22c460231e44ee0cedc8c49f02069e82f1f92d9ce3
FROM mirror.gcr.io/library/rust:1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS agent-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p sandboxwich-agent

FROM ${ORB_EXECUTOR_IMAGE} AS orb-executor

FROM mirror.gcr.io/library/ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG SANDBOX_USER=sandbox
ARG SANDBOX_UID=10001
ARG SANDBOX_GID=10001
ARG TARGETARCH
ARG SCCACHE_VERSION=v0.16.0
ARG SCCACHE_SHA256_AMD64=aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588
ARG SCCACHE_SHA256_ARM64=f73a5c39f96bb6ebb89cc7915cf182260d4cbf30765322c5e793d0fe8bd80784

LABEL org.opencontainers.image.title="sandboxwich ubuntu development runtime"
LABEL org.opencontainers.image.description="SSH and browser-desktop guest runtime for disposable development sandboxes"
LABEL dev.sandboxwich.workspace="/workspace"
LABEL dev.sandboxwich.ports.ssh="2222"
LABEL dev.sandboxwich.ports.desktop="6080"

ENV DEBIAN_FRONTEND=noninteractive
ENV SANDBOXWICH_WORKSPACE=/workspace
ENV SANDBOXWICH_AUTHORIZED_KEYS_FILE=/run/sandboxwich/ssh/authorized_keys
ENV SANDBOXWICH_SSH_PORT=2222
ENV HOME=/home/sandbox
ENV CODEX_HOME=/home/sandbox/.codex
ENV ORB_AGENT_ADAPTERS_FILE=/opt/orb/agent-adapters.json
ENV RUSTC_WRAPPER=/usr/local/bin/sccache
ENV CARGO_INCREMENTAL=0
ENV SCCACHE_DIR=/workspace/.cache/sccache
ENV SCCACHE_BASEDIRS=/workspace
ENV SCCACHE_CACHE_SIZE=48M
ENV SCCACHE_IGNORE_SERVER_IO_ERROR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        cargo \
        curl \
        dbus-x11 \
        docker.io \
        fluxbox \
        fonts-liberation \
        fonts-noto-color-emoji \
        fonts-noto-core \
        gh \
        git \
        imagemagick \
        iproute2 \
        jq \
        netcat-openbsd \
        nodejs \
        npm \
        novnc \
        openssh-server \
        procps \
        python3 \
        python3-pip \
        rustc \
        scrot \
        sudo \
        tini \
        tmux \
        unzip \
        vim-tiny \
        websockify \
        x11-utils \
        x11vnc \
        xdotool \
        xvfb \
        xz-utils \
        zsh \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) sccache_arch=x86_64; sccache_sha256="${SCCACHE_SHA256_AMD64}" ;; \
        arm64) sccache_arch=aarch64; sccache_sha256="${SCCACHE_SHA256_ARM64}" ;; \
        *) echo "unsupported sccache architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && archive="sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl.tar.gz" \
    && curl -fsSL "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/${archive}" \
        -o "/tmp/${archive}" \
    && printf '%s  %s\n' "${sccache_sha256}" "/tmp/${archive}" | sha256sum -c - \
    && tar -xzf "/tmp/${archive}" -C /tmp \
    && install -m 0755 "/tmp/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl/sccache" \
        /usr/local/bin/sccache \
    && sccache --version | grep -Fx "sccache 0.16.0" \
    && rm -rf "/tmp/${archive}" "/tmp/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl"

# Firefox: Ubuntu 24.04's own `firefox` apt package is a transitional stub
# that shells out to snapd, which this container never runs (no systemd,
# and sandboxwich deliberately keeps the runtime capability set minimal --
# see the GH-75 sudoers note below). Mozilla publishes a real, non-snap
# .deb build for both amd64 and arm64 from its own apt repo; pin the
# signing key by digest (matching the FROM pin above) and give the repo
# apt priority 1000 so `apt-get install firefox` can never silently
# resolve back to the Ubuntu archive's snap stub.
RUN install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg \
        -o /etc/apt/keyrings/packages.mozilla.org.asc \
    && echo "3ecc63922b7795eb23fdc449ff9396f9114cb3cf186d6f5b53ad4cc3ebfbb11f  /etc/apt/keyrings/packages.mozilla.org.asc" \
        | sha256sum -c - \
    && echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" \
        > /etc/apt/sources.list.d/mozilla.list \
    && printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' \
        > /etc/apt/preferences.d/mozilla \
    && apt-get update \
    && apt-get install -y --no-install-recommends firefox \
    && rm -rf /var/lib/apt/lists/*

# Default $BROWSER for anything (xdotool-driven automation, CLI tools) that
# checks it. Firefox needs no --no-sandbox flag and no extra seccomp/
# capability grant to run as this non-root user, unlike chromium.
ENV BROWSER=firefox

RUN groupadd --gid "${SANDBOX_GID}" "${SANDBOX_USER}" \
    && useradd --create-home --shell /bin/bash \
        --uid "${SANDBOX_UID}" \
        --gid "${SANDBOX_GID}" \
        "${SANDBOX_USER}" \
    && mkdir -p /run/sshd /run/sandboxwich/ssh /workspace "/home/${SANDBOX_USER}/.codex" /opt/orb \
    && chown -R "${SANDBOX_USER}:${SANDBOX_USER}" /run/sandboxwich /workspace "/home/${SANDBOX_USER}" /opt/orb
# NOTE (GH-75): intentionally no passwordless (or any) sudoers grant for
# ${SANDBOX_USER}. The previous `ALL=(ALL) NOPASSWD:ALL` entry meant any
# code execution as this user was one `sudo` away from root, defeating
# runAsNonRoot/capability-drop/seccomp at the pod securityContext layer.

COPY --from=agent-builder /src/target/release/sandboxwich-agent /usr/local/bin/sandboxwich-agent
COPY --from=orb-executor /usr/local/bin/orb-executor /usr/local/bin/orb-executor
COPY --from=orb-executor /usr/local/bin/codex /usr/local/bin/codex
COPY --from=orb-executor /usr/local/bin/orb-deterministic-agent /usr/local/bin/orb-deterministic-agent
COPY --from=orb-executor /opt/orb/agent-adapters.json /opt/orb/agent-adapters.json
COPY deploy/runtime/ubuntu-dev/sandboxwich-entrypoint.sh /usr/local/bin/sandboxwich-entrypoint
RUN chmod 0755 \
        /usr/local/bin/codex \
        /usr/local/bin/orb-deterministic-agent \
        /usr/local/bin/orb-executor \
        /usr/local/bin/sandboxwich-agent \
        /usr/local/bin/sandboxwich-entrypoint

EXPOSE 2222 6080
VOLUME ["/workspace"]
USER ${SANDBOX_USER}

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandboxwich-entrypoint"]
