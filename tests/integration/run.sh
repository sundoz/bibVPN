#!/usr/bin/env bash
# Full deploy test against throwaway Ubuntu 24.04 containers that behave like VPSes
# (one exit node, one hub):
#   1. `bibvpn deploy` provisions both from scratch;
#   2. a second deploy must change nothing (idempotency);
#   3. a real Xray client connects through both transports (Vision and XHTTP);
#   4. an unauthenticated TLS probe sees the impersonated site's certificate;
#   5. security: password SSH is off (even with a cloud-init drop-in saying otherwise),
#      only the expected ports are open, the Xray sandbox scores well, and tunnel
#      users cannot reach the node's own services (SSH, Xray API) through the proxy;
#   6. subscriptions: the hub serves a user's links over HTTPS, unknown tokens get 404;
#   7. monitoring: `bibvpn status` is green; when the node goes down the hub marks it
#      in subscriptions and sends a Telegram alert (to a fake Telegram API), and
#      another when it comes back;
#   0. `deploy --check --diff` works on fresh servers and never prints secrets;
#   8. ... nor when the config changes (Reality private key, UUIDs, tokens);
#   9. a disabled user is cut off and their subscription disappears;
#  10. a disabled node is really stopped: Xray off, config with keys deleted, port closed.
#
# Needs: docker (privileged containers), ssh, the project venv (make dev), and an
# `xray` binary on PATH for the client side.
# Optional: KEEP=1 keeps containers and logs; REBUILD=1 rebuilds the image; EXTRA_CA=/path/ca.crt is trusted inside the
# containers (for TLS-intercepting proxies).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
NODE=bibvpn-it-node
HUB=bibvpn-it-hub
HUB_DOMAIN=hub.bibvpn.test
SNI=${SNI:-www.samsung.com}
BIBVPN="$ROOT/.venv/bin/bibvpn --state $WORK/state.yml --build-dir $WORK/build"
SSH_OPTS=(-o "UserKnownHostsFile=$WORK/known_hosts" -o StrictHostKeyChecking=accept-new)
export ANSIBLE_SSH_ARGS="-C -o ControlMaster=auto -o ControlPersist=60s ${SSH_OPTS[*]}"
CLIENT_PIDS=()

cleanup() {
  for pid in "${CLIENT_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [[ -n "${KEEP:-}" ]]; then  # KEEP=1: leave containers and logs for debugging
    echo "kept: logs in $WORK, containers $NODE $HUB"
    return
  fi
  docker rm -f "$NODE" "$HUB" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

nocurl() { # curl without any proxy settings from the environment
  env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u no_proxy -u NO_PROXY curl "$@"
}
tcurl() { # curl through the tunnel on local SOCKS port $1
  nocurl -s -m 10 --socks5-hostname "127.0.0.1:$1" "${@:2}" || true
}
fetch() { # HTTP status through the tunnel ("000" on failure)
  tcurl "$1" -o /dev/null -w "%{http_code}" https://github.com
}
subcurl() { # request to the hub's HTTPS subscription endpoint
  nocurl -sk -m 10 --resolve "$HUB_DOMAIN:443:$HUB_IP" "$@" || true
}

start_vm() { # start_vm <name>: boot a container, install our key (and CA), print its IP
  docker run -d --name "$1" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw bibvpn-testnode >/dev/null
  docker cp "$WORK/id.pub" "$1:/root/.ssh/authorized_keys"
  # docker cp keeps the caller's uid (non-root on CI runners); sshd ignores an
  # authorized_keys file that root does not own.
  docker exec "$1" chown root:root /root/.ssh/authorized_keys
  docker exec "$1" chmod 600 /root/.ssh/authorized_keys
  until docker exec "$1" systemctl is-active -q ssh; do sleep 1; done
  if [[ -n "${EXTRA_CA:-}" ]]; then
    docker cp "$EXTRA_CA" "$1:/usr/local/share/ca-certificates/extra.crt"
    docker exec "$1" update-ca-certificates >/dev/null
  fi
  # Like many cloud images: a drop-in that enables password login.
  docker exec "$1" bash -c 'echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/50-cloud-init.conf'
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

monitor_round() { docker exec "$HUB" systemctl start bibvpn-monitor.service; }
tg_messages() { docker exec "$HUB" cat /tmp/tg.log 2>/dev/null || true; }

ssh-keygen -q -t ed25519 -N "" -f "$WORK/id"
if [[ -n "${REBUILD:-}" ]] || ! docker image inspect bibvpn-testnode >/dev/null 2>&1; then
  docker build -q -t bibvpn-testnode "$ROOT/tests/integration" >/dev/null
fi
IP=$(start_vm "$NODE")
HUB_IP=$(start_vm "$HUB")

# Fake Telegram Bot API on the hub: records every message it receives.
docker exec -d "$HUB" python3 -c '
import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        with open("/tmp/tg.log", "a") as f:
            f.write(body["chat_id"][0] + " " + body["text"][0].replace("\n", " | ") + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"{\"ok\":true}")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()'

TG_TOKEN="123456:TESTTOKENtesttokenTESTTOKENtesttoken"
$BIBVPN init
$BIBVPN node add node1 "$IP" --sni "$SNI"
$BIBVPN user add alice
$BIBVPN hub set "$HUB_IP" --domain "$HUB_DOMAIN" --tls internal
$BIBVPN monitor set --threshold 2 --interval 60 \
  --small-url https://github.com \
  --large-url https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip \
  --telegram-token "$TG_TOKEN" --telegram-chat-id 42 --telegram-api http://127.0.0.1:8099

secrets_leaked() { # secrets_leaked <file>: any Reality private key or user/monitor UUID in it?
  "$ROOT/.venv/bin/python" - "$WORK/state.yml" "$1" <<'PY'
import sys
from pathlib import Path
from bibvpn import state as st
s = st.load(Path(sys.argv[1]))
text = Path(sys.argv[2]).read_text()
secrets = [n.reality.private_key for n in s.nodes] + [u.uuid for u in s.users] + [s.monitor.uuid]
secrets += [u.sub_token for u in s.users] + ([s.monitor.telegram_token] if s.monitor.telegram_token else [])
found = [x[:6] + "..." for x in secrets if x in text]
print(" ".join(found))
sys.exit(0 if found else 1)
PY
}

echo "== 0. dry run (--check --diff) on fresh servers"
$BIBVPN deploy --check --private-key "$WORK/id" > "$WORK/check0.log" 2>&1 || { tail -40 "$WORK/check0.log"; fail "deploy --check on fresh servers"; }
leak=$(secrets_leaked "$WORK/check0.log") && fail "deploy --check printed secrets: $leak"
echo "  ok, no secrets in output"

echo "== 1. first deploy"
$BIBVPN deploy --private-key "$WORK/id" | tee "$WORK/deploy1.log" | tail -4
grep -q "unreachable=0 .*failed=0" "$WORK/deploy1.log" || fail "first deploy"

echo "== 2. second deploy is a no-op"
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy2.log"
[[ $(grep -c "changed=0 .*failed=0" "$WORK/deploy2.log") == 2 ]] || { tail -30 "$WORK/deploy2.log"; fail "not idempotent"; }

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
  [[ "$code" == 200 ]] || fail "tunnel on :$port"
done

echo "== 4. probes see $SNI"
openssl s_client -connect "$IP:443" -servername "$SNI" </dev/null 2>/dev/null | grep -q "subject=.*${SNI#www.}" \
  || fail "probe did not see $SNI certificate"

echo "== 5. security"
for vm in "$NODE" "$HUB"; do
  sshd_cfg=$(docker exec "$vm" sshd -T)
  grep -qx "passwordauthentication no" <<<"$sshd_cfg" || fail "$vm: SSH password login still enabled"
  grep -qx "kbdinteractiveauthentication no" <<<"$sshd_cfg" || fail "$vm: keyboard-interactive still enabled"
  docker exec "$vm" ufw status verbose | grep -q "deny (incoming)" || fail "$vm: firewall not default-deny"
  docker exec "$vm" fail2ban-client status sshd >/dev/null || fail "$vm: fail2ban sshd jail not running"
done
open_ports=$(docker exec "$NODE" ufw status | awk '/ALLOW/ && !/v6/ {print $1}' | sort | tr '\n' ' ')
[[ "$open_ports" == "22/tcp 443/tcp " ]] || fail "node: unexpected open ports: $open_ports"
open_ports=$(docker exec "$HUB" ufw status | awk '/ALLOW/ && !/v6/ {print $1}' | sort | tr '\n' ' ')
[[ "$open_ports" == "22/tcp 443/tcp 80/tcp " ]] || fail "hub: unexpected open ports: $open_ports"
[[ $(docker exec "$NODE" ps -o user= -C xray) == xray ]] || fail "xray not running as its own user"
for unit in "$NODE xray" "$HUB bibvpn-probe" "$HUB bibvpn-monitor"; do
  read -r vm svc <<<"$unit"
  score=$(docker exec "$vm" systemd-analyze security "$svc" --no-pager | grep 'Overall exposure level' | grep -oE '[0-9]+\.[0-9]+' | head -1)
  echo "  $svc systemd exposure: $score (lower is better)"
  awk -v s="$score" 'BEGIN { exit !(s < 3.0) }' || fail "$svc sandbox too weak ($score)"
done
for target in 127.0.0.1:22 localhost:22 "$IP:22" "[::1]:22"; do
  banner=$(tcurl 31080 --http0.9 "http://$target/" | head -c 7)
  [[ "$banner" != SSH-2.0 ]] || fail "node SSH reachable through the tunnel at $target"
done
[[ $(tcurl 31080 --http2-prior-knowledge -o /dev/null -w "%{http_code}" http://127.0.0.1:10085/) == 000 ]] \
  || fail "Xray API reachable through the tunnel"
[[ $(fetch 31080) == 200 ]] || fail "tunnel broke during security checks"
echo "  ok"

echo "== 6. subscriptions"
SUB_URL=$($BIBVPN sub alice)
SUB_PATH=${SUB_URL#https://$HUB_DOMAIN}
headers=$(subcurl -D - -o "$WORK/sub.b64" "https://$HUB_DOMAIN$SUB_PATH")
grep -qi "^profile-update-interval: 3" <<<"$headers" || fail "no Profile-Update-Interval header"
decoded=$(base64 -d "$WORK/sub.b64")
ALICE_UUID=$("$ROOT/.venv/bin/python" -c "from bibvpn import state as st; from pathlib import Path; print(st.load(Path('$WORK/state.yml')).user('alice').uuid)")
[[ $(grep -c "^vless://$ALICE_UUID@$IP:443" <<<"$decoded") == 2 ]] || { echo "$decoded"; fail "subscription content"; }
[[ $(subcurl -o /dev/null -w "%{http_code}" "https://$HUB_DOMAIN/s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 404 ]] || fail "unknown token not 404"
[[ $(subcurl -o /dev/null -w "%{http_code}" "https://$HUB_DOMAIN/") == 404 ]] || fail "root not 404"
[[ $(subcurl -o /dev/null -w "%{http_code}" "https://$HUB_DOMAIN/s/") == 404 ]] || fail "directory listing"
echo "  ok: $SUB_URL"

echo "== 7. monitoring"
$BIBVPN status -i "$WORK/id" "${SSH_OPTS[@]}" || fail "status not green after deploy"
docker exec "$NODE" systemctl stop xray
monitor_round; monitor_round   # threshold 2
$BIBVPN status -i "$WORK/id" "${SSH_OPTS[@]}" && fail "status still green with the node down"
tg_messages | grep -q "^42 bibVPN | 🔴 node1/vision" || { tg_messages; fail "no down alert"; }
base64 -d <<<"$(subcurl "https://$HUB_DOMAIN$SUB_PATH")" | grep -q "%E2%9A%A0" || fail "down node not marked in subscription"
docker exec "$NODE" systemctl start xray
sleep 2
monitor_round
tg_messages | grep -q "🟢 node1/vision" || { tg_messages; fail "no recovery alert"; }
$BIBVPN status -i "$WORK/id" "${SSH_OPTS[@]}" || fail "status not green after recovery"
[[ $(tg_messages | wc -l) == 2 ]] || { tg_messages; fail "expected exactly 2 alerts"; }
echo "  ok"

echo "== 8. --check after a config change prints no secrets"
$BIBVPN user add bob
$BIBVPN deploy --check --private-key "$WORK/id" > "$WORK/check1.log" 2>&1 || { tail -40 "$WORK/check1.log"; fail "deploy --check"; }
grep -q "Stage config" "$WORK/check1.log" || fail "check run did not reach the config"
leak=$(secrets_leaked "$WORK/check1.log") && fail "deploy --check printed secrets: $leak"
grep -q "changed: \[node1\]" "$WORK/check1.log" || fail "--check did not report the pending config change"
$BIBVPN user rm bob
echo "  ok"

echo "== 9. disabled user is cut off"
$BIBVPN user disable alice
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy3.log"
sleep 2
for port in 31080 31081; do
  code=$(fetch $port)
  [[ "$code" == 000 ]] || fail "disabled user still has access on :$port ($code)"
done
[[ $(subcurl -o /dev/null -w "%{http_code}" "https://$HUB_DOMAIN$SUB_PATH") == 404 ]] || fail "disabled user's subscription still served"

echo "== 10. disabled node is really stopped"
$BIBVPN node rm node1 && fail "node rm accepted a running node"
$BIBVPN user enable alice
$BIBVPN node set node1 --disable
$BIBVPN deploy --private-key "$WORK/id" > "$WORK/deploy4.log" || { tail -30 "$WORK/deploy4.log"; fail "deploy with disabled node"; }
docker exec "$NODE" systemctl is-active -q xray && fail "xray still running on disabled node"
docker exec "$NODE" systemctl is-enabled -q xray && fail "xray still enabled on disabled node"
docker exec "$NODE" test -e /usr/local/etc/xray/config.json && fail "config with keys left on disabled node"
docker exec "$NODE" ufw status | grep -q "^443/tcp" && fail "port 443 still open on disabled node"
timeout 5 bash -c "echo > /dev/tcp/$IP/443" 2>/dev/null && fail "port 443 still answers"
[[ $(fetch 31080) == 000 ]] || fail "old link still works on disabled node"
$BIBVPN node rm node1 || fail "node rm after disable"
echo "  ok"

echo "PASS"
