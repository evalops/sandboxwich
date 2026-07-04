#!/usr/bin/env bash
set -euo pipefail

SANDBOX_USER="${SANDBOXWICH_USER:-sandbox}"
WORKSPACE="${SANDBOXWICH_WORKSPACE:-/workspace}"
AUTHORIZED_KEYS_FILE="${SANDBOXWICH_AUTHORIZED_KEYS_FILE:-/run/sandboxwich/ssh/authorized_keys}"
DISPLAY_NUMBER="${SANDBOXWICH_DISPLAY:-:1}"

install_authorized_keys() {
  if [[ ! -s "${AUTHORIZED_KEYS_FILE}" ]]; then
    return
  fi

  install -d -m 0700 -o "${SANDBOX_USER}" -g "${SANDBOX_USER}" "/home/${SANDBOX_USER}/.ssh"
  install -m 0600 -o "${SANDBOX_USER}" -g "${SANDBOX_USER}" \
    "${AUTHORIZED_KEYS_FILE}" "/home/${SANDBOX_USER}/.ssh/authorized_keys"
}

start_desktop() {
  if [[ "${SANDBOXWICH_DESKTOP:-1}" != "1" ]]; then
    return
  fi

  export DISPLAY="${DISPLAY_NUMBER}"
  Xvfb "${DISPLAY_NUMBER}" -screen 0 "${SANDBOXWICH_DESKTOP_SIZE:-1920x1080x24}" -nolisten tcp &
  fluxbox >/tmp/sandboxwich-fluxbox.log 2>&1 &
  x11vnc -display "${DISPLAY_NUMBER}" -forever -shared -nopw -rfbport 5900 \
    >/tmp/sandboxwich-x11vnc.log 2>&1 &
  websockify --web=/usr/share/novnc/ 6080 localhost:5900 \
    >/tmp/sandboxwich-websockify.log 2>&1 &
}

start_docker() {
  if [[ "${SANDBOXWICH_DOCKERD:-0}" != "1" ]]; then
    return
  fi

  dockerd >/tmp/sandboxwich-dockerd.log 2>&1 &
}

mkdir -p /run/sshd "${WORKSPACE}"
chown -R "${SANDBOX_USER}:${SANDBOX_USER}" "${WORKSPACE}"
install_authorized_keys
start_docker
start_desktop

exec /usr/sbin/sshd -D -e
