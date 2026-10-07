#!/usr/bin/env bash
set -euo pipefail

if [[ "${APLANE_SDK_INTEGRATION:-}" != "1" ]]; then
  echo "SDK integration tests require APLANE_SDK_INTEGRATION=1." >&2
  exit 1
fi

# The client's enrolled SSH key is its only credential. An SSH host means the
# tests tunnel to it with that key, and nothing else is needed: the signer URL
# and the APlane fixture are only for the other mode, where the URL names a
# caller-owned tunnel (a signer's loopback REST port answers only /health).
if [[ -n "${APLANE_SDK_SSH_HOST:-}" ]]; then
  for name in APLANE_SDK_SSH_PORT APLANE_SDK_SSH_KEY_PATH APLANE_SDK_KNOWN_HOSTS_PATH; do
    if [[ -z "${!name:-}" ]]; then
      echo "$name must be set when APLANE_SDK_SSH_HOST is set." >&2
      exit 1
    fi
  done
  if [[ ! "$APLANE_SDK_SSH_PORT" =~ ^[0-9]+$ ]] || (( APLANE_SDK_SSH_PORT < 1 || APLANE_SDK_SSH_PORT > 65535 )); then
    echo "APLANE_SDK_SSH_PORT must be a TCP port, got: $APLANE_SDK_SSH_PORT" >&2
    exit 1
  fi
  if [[ ! -r "$APLANE_SDK_SSH_KEY_PATH" ]]; then
    echo "APLANE_SDK_SSH_KEY_PATH is not readable: $APLANE_SDK_SSH_KEY_PATH" >&2
    echo "The key must be enrolled at the signer (apshell request-enrollment)." >&2
    exit 1
  fi
  if [[ ! -r "$APLANE_SDK_KNOWN_HOSTS_PATH" ]]; then
    echo "APLANE_SDK_KNOWN_HOSTS_PATH is not readable: $APLANE_SDK_KNOWN_HOSTS_PATH" >&2
    echo "It must hold the signer's host key (apshell connect saves it)." >&2
    exit 1
  fi
  # The SSH listener is the only thing the tests reach; a TCP connect is the
  # reachability check, since the SSH port has no HTTP health endpoint.
  if ! timeout 5 bash -c "exec 3<>/dev/tcp/$APLANE_SDK_SSH_HOST/$APLANE_SDK_SSH_PORT" 2>/dev/null; then
    cat >&2 <<EOF
SDK integration tests could not reach the signer's SSH listener at:
  $APLANE_SDK_SSH_HOST:$APLANE_SDK_SSH_PORT

Run them from the APlane harness:
  cd ~/aplane
  APLANE_SDKS_REPO=~/aplanesdk make integration-test

Or start apsigner yourself with the same fixture/env before running:
  cd ~/aplanesdk
  make integration-test
EOF
    exit 1
  fi
  echo "SDK integration preflight ok: ssh://$APLANE_SDK_SSH_HOST:$APLANE_SDK_SSH_PORT"
  exit 0
fi

signer_url="${APLANE_SDK_SIGNER_URL:-}"
if [[ -z "$signer_url" ]]; then
  if [[ -z "${APSIGNER_DATA:-}" ]]; then
    cat >&2 <<'EOF'
SDK integration tests require a live apsigner.

Run them from the APlane harness:
  cd ~/aplane
  APLANE_SDKS_REPO=~/aplanesdk make integration-test

Or start apsigner yourself and set either:
  APLANE_SDK_SSH_HOST, APLANE_SDK_SSH_PORT, APLANE_SDK_SSH_KEY_PATH,
  APLANE_SDK_KNOWN_HOSTS_PATH (the enrolled client key and host trust), or
  APLANE_SDK_SIGNER_URL=http://127.0.0.1:<port> for a caller-owned tunnel
EOF
    exit 1
  fi

  config="$APSIGNER_DATA/config.yaml"
  if [[ ! -f "$config" ]]; then
    echo "APSIGNER_DATA is set, but $config does not exist." >&2
    echo "Regenerate the APlane fixture or set APLANE_SDK_SIGNER_URL explicitly." >&2
    exit 1
  fi

  port="$(python3 - "$config" <<'PY'
import sys
from pathlib import Path

config = Path(sys.argv[1])
in_endpoint = False
for raw in config.read_text().splitlines():
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        continue
    indent = len(raw) - len(raw.lstrip(" "))
    if indent == 0:
        in_endpoint = stripped == "endpoint:"
        continue
    if in_endpoint and indent == 2 and stripped.startswith("signer_port:"):
        value = stripped.split(":", 1)[1].split("#", 1)[0].strip()
        if not value.isdigit():
            raise SystemExit(1)
        print(value)
        break
else:
    raise SystemExit(1)
PY
)" || {
    echo "Could not read endpoint.signer_port from $config." >&2
    echo "Set APLANE_SDK_SIGNER_URL explicitly." >&2
    exit 1
  }

  signer_url="http://127.0.0.1:$port"
fi

if ! curl -fsS "$signer_url/health" >/dev/null 2>&1; then
  cat >&2 <<EOF
SDK integration tests could not reach a healthy apsigner at:
  $signer_url

Run them from the APlane harness:
  cd ~/aplane
  APLANE_SDKS_REPO=~/aplanesdk make integration-test

Or start apsigner yourself with the same fixture/env before running:
  cd ~/aplanesdk
  make integration-test
EOF
  exit 1
fi

echo "SDK integration preflight ok: $signer_url"
