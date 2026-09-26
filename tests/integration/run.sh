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

tcurl() { # curl through the tunnel; proxy env vars (incl. no_proxy) must not bypass it
  env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u no_proxy -u NO_PROXY \
    curl -s -m 10 --socks5-hostname "127.0.0.1:$1" "${@:2}" || true
}
fetch() { # fetch <socks port>: HTTP status through the tunnel ("000" on failure)
  tcurl "$1" -o /dev/null -w "%{http_code}" https://github.com
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

# Like many cloud images: a drop-in that enables password login.
docker exec "$NODE" bash -c 'echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/50-cloud-init.conf'

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

echo "== 5. security"
sshd_cfg=$(docker exec "$NODE" sshd -T)
grep -qx "passwordauthentication no" <<<"$sshd_cfg" || { echo "FAIL: SSH password login still enabled"; exit 1; }
grep -qx "kbdinteractiveauthentication no" <<<"$sshd_cfg" || { echo "FAIL: keyboard-interactive still enabled"; exit 1; }
open_ports=$(docker exec "$NODE" ufw status | awk '/ALLOW/ && !/v6/ {print $1}' | sort | tr '\n' ' ')
[[ "$open_ports" == "22/tcp 443/tcp " ]] || { echo "FAIL: unexpected open ports: $open_ports"; exit 1; }
docker exec "$NODE" ufw status verbose | grep -q "deny (incoming)" || { echo "FAIL: firewall not default-deny"; exit 1; }
docker exec "$NODE" fail2ban-client status sshd >/dev/null || { echo "FAIL: fail2ban sshd jail not running"; exit 1; }
[[ $(docker exec "$NODE" ps -o user= -C xray) == xray ]] || { echo "FAIL: xray not running as its own user"; exit 1; }
score=$(docker exec "$NODE" systemd-analyze security xray --no-pager | grep 'Overall exposure level' | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "  systemd exposure score: $score (lower is better)"
awk -v s="$score" 'BEGIN { exit !(s < 3.0) }' || { echo "FAIL: xray sandbox too weak ($score)"; exit 1; }
for target in 127.0.0.1:22 localhost:22 "$IP:22" "[::1]:22"; do
  banner=$(tcurl 31080 --http0.9 "http://$target/" | head -c 7)
  [[ "$banner" != SSH-2.0 ]] || { echo "FAIL: server SSH reachable through the tunnel at $target"; exit 1; }
done
[[ $(tcurl 31080 --http2-prior-knowledge -o /dev/null -w "%{http_code}" http://127.0.0.1:10085/) == 000 ]] \
  || { echo "FAIL: Xray API reachable through the tunnel"; exit 1; }
[[ $(fetch 31080) == 200 ]] || { echo "FAIL: tunnel broke during security checks"; exit 1; }
echo "  ok"

echo "== 6. disabled user is cut off"
$BIBVPN user disable alice
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy3.log"
sleep 2
for port in 31080 31081; do
  code=$(fetch $port)
  [[ "$code" == 000 ]] || { echo "FAIL: disabled user still has access on :$port ($code)"; exit 1; }
done

echo "PASS"
