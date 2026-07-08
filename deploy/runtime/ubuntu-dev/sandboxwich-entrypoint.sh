#!/usr/bin/env bash
set -euo pipefail

SANDBOX_USER="${SANDBOXWICH_USER:-sandbox}"
WORKSPACE="${SANDBOXWICH_WORKSPACE:-/workspace}"
AUTHORIZED_KEYS_FILE="${SANDBOXWICH_AUTHORIZED_KEYS_FILE:-/run/sandboxwich/ssh/authorized_keys}"
DISPLAY_NUMBER="${SANDBOXWICH_DISPLAY:-:1}"
SSH_PORT="${SANDBOXWICH_SSH_PORT:-2222}"
SSH_DIR="/home/${SANDBOX_USER}/.ssh"

install_authorized_keys() {
  if [[ ! -s "${AUTHORIZED_KEYS_FILE}" ]]; then
    return
  fi

  if [[ "${EUID}" == "0" ]]; then
    install -d -m 0700 -o "${SANDBOX_USER}" -g "${SANDBOX_USER}" "${SSH_DIR}"
    install -m 0600 -o "${SANDBOX_USER}" -g "${SANDBOX_USER}" \
      "${AUTHORIZED_KEYS_FILE}" "${SSH_DIR}/authorized_keys"
  else
    install -d -m 0700 "${SSH_DIR}"
    install -m 0600 "${AUTHORIZED_KEYS_FILE}" "${SSH_DIR}/authorized_keys"
  fi
}

# GH-67: x11vnc previously listened on 0.0.0.0:5900 with -nopw, so any pod
# on the cluster network (including other tenants' sandboxes) could open an
# unauthenticated VNC session directly against port 5900, bypassing
# websockify/noVNC entirely. We now (a) bind x11vnc to the loopback
# interface only via `-listen localhost`, so port 5900 is unreachable from
# any other pod regardless of password, and (b) still require a VNC
# password (removing -nopw) for defense in depth. The password comes from
# SANDBOXWICH_VNC_PASSWORD when set (wire it from a per-sandbox Secret via
# the worker's --vnc-password-secret flag, mirroring
# --ssh-authorized-keys-secret); otherwise a random one-time password is
# generated per container start and written only to a 0600 file readable
# by this user. Note the noVNC web client will now prompt for this
# password on connect.
start_desktop() {
  if [[ "${SANDBOXWICH_DESKTOP:-1}" != "1" ]]; then
    return
  fi

  export DISPLAY="${DISPLAY_NUMBER}"
  Xvfb "${DISPLAY_NUMBER}" -screen 0 "${SANDBOXWICH_DESKTOP_SIZE:-1920x1080x24}" -nolisten tcp &
  fluxbox >/tmp/sandboxwich-fluxbox.log 2>&1 &

  local vnc_password_file="/tmp/sandboxwich-vnc.passwd"
  local vnc_password="${SANDBOXWICH_VNC_PASSWORD:-}"
  if [[ -z "${vnc_password}" ]]; then
    vnc_password="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
  fi
  ( umask 077 && x11vnc -storepasswd "${vnc_password}" "${vnc_password_file}" >/dev/null )

  x11vnc -display "${DISPLAY_NUMBER}" -forever -shared -listen localhost \
    -rfbauth "${vnc_password_file}" -rfbport 5900 \
    >/tmp/sandboxwich-x11vnc.log 2>&1 &
  websockify --web=/usr/share/novnc/ 6080 localhost:5900 \
    >/tmp/sandboxwich-websockify.log 2>&1 &
}

start_docker() {
  if [[ "${SANDBOXWICH_DOCKERD:-0}" != "1" ]]; then
    return
  fi
  if [[ "${EUID}" != "0" ]]; then
    echo "SANDBOXWICH_DOCKERD=1 ignored because runtime is non-root" >&2
    return
  fi

  dockerd >/tmp/sandboxwich-dockerd.log 2>&1 &
}

write_rootless_sshd_config() {
  install -d -m 0700 "${SSH_DIR}"
  if [[ ! -s "${SSH_DIR}/ssh_host_ed25519_key" ]]; then
    ssh-keygen -q -t ed25519 -N "" -f "${SSH_DIR}/ssh_host_ed25519_key"
  fi
  cat > /tmp/sandboxwich-sshd_config <<EOF
Port ${SSH_PORT}
HostKey ${SSH_DIR}/ssh_host_ed25519_key
AuthorizedKeysFile ${SSH_DIR}/authorized_keys
PasswordAuthentication no
PermitRootLogin no
PidFile /tmp/sandboxwich-sshd.pid
UsePAM no
AllowTcpForwarding yes
X11Forwarding no
Subsystem sftp internal-sftp
EOF
}

if [[ "${EUID}" == "0" ]]; then
  mkdir -p /run/sshd "${WORKSPACE}"
  chown -R "${SANDBOX_USER}:${SANDBOX_USER}" "${WORKSPACE}"
else
  mkdir -p "${WORKSPACE}"
fi
install_authorized_keys
start_docker
start_desktop

if [[ "${EUID}" == "0" ]]; then
  exec /usr/sbin/sshd -D -e -p "${SSH_PORT}"
fi

write_rootless_sshd_config
exec /usr/sbin/sshd -D -e -f /tmp/sandboxwich-sshd_config
