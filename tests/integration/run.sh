#!/usr/bin/env bash
# Full deploy test against a throwaway Ubuntu 24.04 container that behaves like a VPS:
#   1. `bibvpn deploy` provisions it from scratch;
#   2. a second deploy must change nothing (idempotency);
#   3. a real Xray client connects through both transports (Vision and XHTTP);
#   4. an unauthenticated TLS probe sees the impersonated site's certificate;
#   5. a disabled user loses access after the next deploy.
#
# Needs: docker (privileged containers), ssh, the project venv (make dev), and an
# `xray` binary on PATH for the client side.
# Optional: REBUILD=1 rebuilds the node image; EXTRA_CA=/path/ca.crt is trusted inside the node (for TLS-intercepting proxies).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
NODE=bibvpn-it-node
SNI=${SNI:-www.samsung.com}
BIBVPN="$ROOT/.venv/bin/bibvpn --state $WORK/state.yml --build-dir $WORK/build"
export ANSIBLE_SSH_ARGS="-C -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$WORK/known_hosts -o StrictHostKeyChecking=accept-new"
CLIENT_PIDS=()

cleanup() {
  for pid in "${CLIENT_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  docker rm -f "$NODE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fetch() { # fetch <socks port>: HTTP status of a request through the tunnel ("000" on failure)
  env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
    curl -s -m 15 --socks5-hostname "127.0.0.1:$1" -o /dev/null -w "%{http_code}" https://github.com || true
}

ssh-keygen -q -t ed25519 -N "" -f "$WORK/id"
if [[ -n "${REBUILD:-}" ]] || ! docker image inspect bibvpn-testnode >/dev/null 2>&1; then
  docker build -q -t bibvpn-testnode "$ROOT/tests/integration" >/dev/null
fi
docker run -d --name "$NODE" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw bibvpn-testnode >/dev/null
docker cp "$WORK/id.pub" "$NODE:/root/.ssh/authorized_keys"
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE")
until docker exec "$NODE" systemctl is-active -q ssh; do sleep 1; done
if [[ -n "${EXTRA_CA:-}" ]]; then
  docker cp "$EXTRA_CA" "$NODE:/usr/local/share/ca-certificates/extra.crt"
  docker exec "$NODE" update-ca-certificates >/dev/null
fi

$BIBVPN init
$BIBVPN node add node1 "$IP" --sni "$SNI"
$BIBVPN user add alice

echo "== 1. first deploy"
$BIBVPN deploy --private-key "$WORK/id" | tee "$WORK/deploy1.log" | tail -3

echo "== 2. second deploy is a no-op"
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy2.log"
grep -q "changed=0 .*failed=0" "$WORK/deploy2.log" || { tail -20 "$WORK/deploy2.log"; echo "FAIL: not idempotent"; exit 1; }

echo "== 3. client connects through both transports"
"$ROOT/.venv/bin/python" - "$WORK" <<'PY'
import json, sys
from pathlib import Path
from bibvpn import state as st
from bibvpn.links import client_xray_config
work = Path(sys.argv[1])
s = st.load(work / "state.yml")
node, user = s.node("node1"), s.user("alice")
for transport, port in (("vision", 31080), ("xhttp", 31081)):
    (work / f"client-{transport}.json").write_text(json.dumps(client_xray_config(node, user, transport, port)))
PY
for t in vision xhttp; do
  xray run -c "$WORK/client-$t.json" > "$WORK/client-$t.log" 2>&1 &
  CLIENT_PIDS+=($!)
done
sleep 2
for port in 31080 31081; do
  code=$(fetch $port)
  echo "  socks :$port -> $code"
  [[ "$code" == 200 ]] || { echo "FAIL: tunnel on :$port"; exit 1; }
done

echo "== 4. probes see $SNI"
openssl s_client -connect "$IP:443" -servername "$SNI" </dev/null 2>/dev/null | grep -q "subject=.*${SNI#www.}" \
  || { echo "FAIL: probe did not see $SNI certificate"; exit 1; }

echo "== 5. disabled user is cut off"
$BIBVPN user disable alice
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy3.log"
sleep 2
for port in 31080 31081; do
  code=$(fetch $port)
  [[ "$code" == 000 ]] || { echo "FAIL: disabled user still has access on :$port ($code)"; exit 1; }
done

echo "PASS"
