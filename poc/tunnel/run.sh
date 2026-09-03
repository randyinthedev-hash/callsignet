#!/usr/bin/env bash
# csa 둘이 터널을 세우고 터널 IP로 통신하는지 확인한다.
#
# 네임스페이스 둘을 만들어 브리지로 잇고, 각 네임스페이스에서 csa를 띄운 뒤
# 한쪽 터널 IP에서 다른 쪽 터널 IP로 ping을 보낸다.
set -euo pipefail

NS_A=cs-a
NS_B=cs-b
BR=cs-br0
IP_A=10.90.0.10
IP_B=10.90.0.30
WG_A=10.91.0.1
WG_B=10.91.0.2
CIDR=10.91.0.0/24
PORT=51820

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CSA="${CSA:-$REPO/csa}"
WORK="$HERE/_work"

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi
if [ ! -x "$CSA" ]; then echo "csa를 먼저 만드십시오: make build" >&2; exit 1; fi

cleanup() {
  [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null || true
  [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null || true
  sleep 0.3
  ip netns delete "$NS_A" 2>/dev/null || true
  ip netns delete "$NS_B" 2>/dev/null || true
  ip link delete "$BR" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
rm -rf "$WORK"; mkdir -p "$WORK/a" "$WORK/b"

echo "== 언더레이"
ip link add "$BR" type bridge && ip link set "$BR" up
attach() { # ns addr
  ip netns add "$1"
  ip link add "v-$1" type veth peer name eth0 netns "$1"
  ip link set "v-$1" master "$BR" up
  ip netns exec "$1" ip link set lo up
  ip netns exec "$1" ip link set eth0 up
  ip netns exec "$1" ip addr add "$2/24" dev eth0
}
attach "$NS_A" "$IP_A"
attach "$NS_B" "$IP_B"

echo "== 키와 설정"
PUB_A=$("$CSA" genkey -o "$WORK/a/private.key" | sed -n 's/^공개키: //p')
PUB_B=$("$CSA" genkey -o "$WORK/b/private.key" | sed -n 's/^공개키: //p')

peers_toml() {
  cat <<TOML
[[peer]]
peer-id    = "srv-a"
public-key = "$PUB_A"
tunnel-ip  = "$WG_A"
endpoints  = ["$IP_A:$PORT"]
services   = [{ app = "test", port = 9 }]

[[peer]]
peer-id    = "srv-b"
public-key = "$PUB_B"
tunnel-ip  = "$WG_B"
endpoints  = ["$IP_B:$PORT"]
services   = [{ app = "test", port = 9 }]
TOML
}
side() { # dir peer-id 상대
  peers_toml > "$WORK/$1/peers.toml"
  cat > "$WORK/$1/csa.toml" <<TOML
peer-id     = "$2"
private-key = "$WORK/$1/private.key"
domain      = "cs.test.internal"
tunnel-cidr = "$CIDR"
listen-port = $PORT

[tun]
name = "cs0"
mtu  = 1420

[dns]
listen = "127.0.0.54:53"
TOML
  cat > "$WORK/$1/policy.toml" <<TOML
outbound = ["$3/test"]

[[inbound]]
app   = "test"
allow = ["$3"]
TOML
}
side a srv-a srv-b
side b srv-b srv-a

echo "== 설정 검사"
"$CSA" check -c "$WORK/a"
"$CSA" check -c "$WORK/b"

echo "== csa 기동"
ip netns exec "$NS_A" "$CSA" run -c "$WORK/a" > "$WORK/a/csa.log" 2>&1 & PID_A=$!
ip netns exec "$NS_B" "$CSA" run -c "$WORK/b" > "$WORK/b/csa.log" 2>&1 & PID_B=$!
for _ in $(seq 30); do
  if ip netns exec "$NS_A" ip link show cs0 >/dev/null 2>&1 &&
     ip netns exec "$NS_B" ip link show cs0 >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo "== 인터페이스"
ip netns exec "$NS_A" ip -brief addr show cs0 || true
ip netns exec "$NS_B" ip -brief addr show cs0 || true

echo
echo "== $WG_A 에서 $WG_B 로 ping"
if ip netns exec "$NS_A" ping -c 3 -W 2 -I "$WG_A" "$WG_B"; then
  echo
  echo "확인됨. csa 둘이 터널을 세우고 터널 IP로 통신한다."
else
  echo
  echo "실패했습니다. 로그를 보십시오."
  echo "--- a ---"; cat "$WORK/a/csa.log"
  echo "--- b ---"; cat "$WORK/b/csa.log"
  exit 1
fi
