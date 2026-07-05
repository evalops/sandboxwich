FROM ubuntu:24.04

ARG SANDBOX_USER=sandbox
ARG SANDBOX_UID=10001
ARG SANDBOX_GID=10001

LABEL org.opencontainers.image.title="sandboxwich ubuntu development runtime"
LABEL org.opencontainers.image.description="SSH and browser-desktop guest runtime for disposable development sandboxes"
LABEL dev.sandboxwich.workspace="/workspace"
LABEL dev.sandboxwich.ports.ssh="2222"
LABEL dev.sandboxwich.ports.desktop="6080"

ENV DEBIAN_FRONTEND=noninteractive
ENV SANDBOXWICH_WORKSPACE=/workspace
ENV SANDBOXWICH_AUTHORIZED_KEYS_FILE=/run/sandboxwich/ssh/authorized_keys
ENV SANDBOXWICH_SSH_PORT=2222

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

RUN groupadd --gid "${SANDBOX_GID}" "${SANDBOX_USER}" \
    && useradd --create-home --shell /bin/bash \
        --uid "${SANDBOX_UID}" \
        --gid "${SANDBOX_GID}" \
        "${SANDBOX_USER}" \
    && printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${SANDBOX_USER}" > /etc/sudoers.d/sandboxwich \
    && chmod 0440 /etc/sudoers.d/sandboxwich \
    && mkdir -p /run/sshd /run/sandboxwich/ssh /workspace \
    && chown -R "${SANDBOX_USER}:${SANDBOX_USER}" /run/sandboxwich /workspace "/home/${SANDBOX_USER}"

COPY sandboxwich-entrypoint.sh /usr/local/bin/sandboxwich-entrypoint
RUN chmod 0755 /usr/local/bin/sandboxwich-entrypoint

EXPOSE 2222 6080
VOLUME ["/workspace"]
USER ${SANDBOX_USER}

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandboxwich-entrypoint"]
