FROM ubuntu:24.04

ARG SANDBOX_USER=sandbox

LABEL org.opencontainers.image.title="sandboxwich ubuntu development runtime"
LABEL org.opencontainers.image.description="SSH and browser-desktop guest runtime for disposable development sandboxes"
LABEL dev.sandboxwich.workspace="/workspace"
LABEL dev.sandboxwich.ports.ssh="22"
LABEL dev.sandboxwich.ports.desktop="6080"

ENV DEBIAN_FRONTEND=noninteractive
ENV SANDBOXWICH_WORKSPACE=/workspace
ENV SANDBOXWICH_AUTHORIZED_KEYS_FILE=/run/sandboxwich/ssh/authorized_keys

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        cargo \
        curl \
        docker.io \
        fluxbox \
        gh \
        git \
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
        sudo \
        tini \
        tmux \
        unzip \
        vim-tiny \
        websockify \
        x11vnc \
        xvfb \
        xz-utils \
        zsh \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash "${SANDBOX_USER}" \
    && printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${SANDBOX_USER}" > /etc/sudoers.d/sandboxwich \
    && chmod 0440 /etc/sudoers.d/sandboxwich \
    && mkdir -p /run/sshd /run/sandboxwich/ssh /workspace \
    && chown -R "${SANDBOX_USER}:${SANDBOX_USER}" /run/sandboxwich /workspace

COPY sandboxwich-entrypoint.sh /usr/local/bin/sandboxwich-entrypoint
RUN chmod 0755 /usr/local/bin/sandboxwich-entrypoint

EXPOSE 22 6080
VOLUME ["/workspace"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandboxwich-entrypoint"]
