#!/usr/bin/env bash
set -euo pipefail

if [[ "${APLANE_SDK_INTEGRATION:-}" != "1" ]]; then
  echo "SDK integration tests require APLANE_SDK_INTEGRATION=1." >&2
  exit 1
fi

signer_url="${APLANE_SDK_SIGNER_URL:-}"
if [[ -z "$signer_url" ]]; then
  if [[ -z "${APSIGNER_DATA:-}" ]]; then
    cat >&2 <<'EOF'
SDK integration tests require a live apsigner.

Run them from the APlane harness:
  cd ~/aplane
  APLANE_SDKS_REPO=~/aplanesdk make integration-test

Or start apsigner yourself and set:
  APLANE_SDK_SIGNER_URL=http://127.0.0.1:<port>
  APLANE_SDK_TOKEN or APLANE_SDK_TOKEN_FILE
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
import re
import sys
from pathlib import Path

match = re.search(r"(?m)^signer_port:\s*(\d+)\s*$", Path(sys.argv[1]).read_text())
if not match:
    raise SystemExit(1)
print(match.group(1))
PY
)" || {
    echo "Could not read signer_port from $config." >&2
    echo "Set APLANE_SDK_SIGNER_URL explicitly." >&2
    exit 1
  }

  signer_url="http://127.0.0.1:$port"
fi

token_source="${APLANE_SDK_TOKEN:-}"
if [[ -z "$token_source" ]]; then
  token_file="${APLANE_SDK_TOKEN_FILE:-}"
  if [[ -z "$token_file" && -n "${APCLIENT_DATA:-}" ]]; then
    token_file="$APCLIENT_DATA/aplane.token"
  fi
  if [[ -z "$token_file" && -n "${APSIGNER_DATA:-}" ]]; then
    token_file="$APSIGNER_DATA/identities/default/aplane.token"
  fi
  if [[ -z "$token_file" || ! -s "$token_file" ]]; then
    cat >&2 <<EOF
SDK integration tests need an apsigner token.

Set one of:
  APLANE_SDK_TOKEN=<token>
  APLANE_SDK_TOKEN_FILE=/path/to/aplane.token

When using the APlane harness, APCLIENT_DATA/aplane.token is provided automatically.
EOF
    exit 1
  fi
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
