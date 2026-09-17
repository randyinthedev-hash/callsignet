#!/usr/bin/env bash
# 앱이 상대의 실제 IP와 포트로 불러도 csa 둘이 터널로 나르는지 확인한다.
#
# 설계는 이렇게 주장한다. 보내는 쪽 머신의 NAT 표가 상대의 실제 IP와 서비스
# 포트로 가는 패킷의 목적지를 상대의 터널 IP로 바꾸고 출발지를 자기 터널 IP로
# 바꾼다. 그러면 그 패킷은 TUN 인터페이스로 들어가 지금과 같은 안쪽 패킷이 된다.
# 받는 쪽 머신의 NAT 표가 터널로 온 패킷의 목적지를 자기 실제 IP로 바꾸고
# 출발지를 상대의 실제 IP로 바꾼다. 그러면 앱은 상대를 실제 IP로 본다. 커널의
# 연결 추적이 되돌아가는 패킷의 주소를 되돌린다.
#
# csa는 아직 이 규칙을 만들지 않는다. 이 스크립트가 nftables NAT 표를 손으로
# 걸고 그 주장을 관측한다. 스크립트가 네임스페이스 둘을 만들어 브리지로 잇고,
# 각 네임스페이스에서 지금의 csa를 띄운 뒤, 앱이 상대의 실제 IP로 부른다.
set -euo pipefail

# csa는 개인키가 놓인 자리와 그 위의 모든 디렉터리를 다른 사용자가 고칠 수 없어야
# 받아들인다. 리포 체크아웃이 0775인 머신이 있으므로 작업 자리는 리포 밖에 두고
# umask를 못박는다. /var/tmp는 끈적임 비트가 서 있어 거절되지 않는다.
umask 022

NS_A=st-a
NS_B=st-b
BR=st-br0
IP_A=10.90.1.10
IP_B=10.90.1.30
# srv-c가 있다고 적어 두는 자리다. 아무도 없다. 정책에 없는 상대를 실제 IP로
# 부를 때 앱이 무엇을 받는지 보는 데 쓴다.
IP_C=10.90.1.50
WG_A=10.91.1.1
WG_B=10.91.1.2
WG_C=10.91.1.3
CIDR=10.91.1.0/24
PORT=51820
WG_IF=cs0
NAT=callsignet-nat
# srv-b의 서비스다. report는 TCP로, beacon은 UDP로 잰다.
PORT_REPORT=8080
PORT_BEACON=9090

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK=/var/tmp/csn-steer-work
RESULTS="$REPO/results"
. "$HERE/../lib.sh"

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi
for c in nft python3; do
  command -v "$c" >/dev/null 2>&1 || { echo "$c가 필요합니다." >&2; exit 1; }
done
if [ -n "${CSA:-}" ]; then
  echo "csa를 새로 만들지 않고 준 것을 씁니다: $CSA"
  [ -x "$CSA" ] || { echo "그 자리에 csa가 없습니다: $CSA" >&2; exit 1; }
else
  CSA="$REPO/csa"
  build_csa "$REPO" "$CSA"
fi

cleanup() {
  for pid in "${PID_A:-}" "${PID_B:-}" "${SRV:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  # 앞선 실행이 남긴 것도 거둔다. csa와 앱 노릇 프로그램은 모두 작업 자리를
  # 인자로 받으므로 그 자리로 찾는다.
  pkill -f "$WORK/" 2>/dev/null || true
  sleep 0.3
  ip netns delete "$NS_A" 2>/dev/null || true
  ip netns delete "$NS_B" 2>/dev/null || true
  ip link delete "$BR" 2>/dev/null || true
  rm -rf "/etc/netns/$NS_A" "/etc/netns/$NS_B"
}
trap cleanup EXIT
cleanup
rm -rf "$WORK"; mkdir -p "$WORK/a" "$WORK/b"

# 결과를 모은다. 검사 이름은 한다체다. TESTING.md의 검사 목록과 같은 문장이다.
CHECKS=()
FAIL=0
ok()  { printf '  ok    %s\n' "$1"; CHECKS+=("| $1 | ok |"); }
bad() { printf '  틀림  %s\n' "$1"; CHECKS+=("| $1 | 틀림 |"); FAIL=1; }
nsa() { ip netns exec "$NS_A" "$@"; }
nsb() { ip netns exec "$NS_B" "$@"; }

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
# 지금의 csa는 리졸버 자리를 차지하려고 /etc/resolv.conf를 고친다. 네임스페이스에
# 자기 파일을 주어 호스트의 파일을 건드리지 않게 한다.
for ns in "$NS_A" "$NS_B"; do
  mkdir -p "/etc/netns/$ns"
  echo "nameserver 10.90.1.253" > "/etc/netns/$ns/resolv.conf"
done
if ! nsa ping -c 2 -W 2 "$IP_B" >/dev/null 2>&1; then
  echo "언더레이가 통하지 않습니다. 터널 이전의 문제입니다." >&2
  echo "브리지로 오가는 패킷이 방화벽에 막히는지 보십시오: sysctl net.bridge.bridge-nf-call-iptables" >&2
  exit 1
fi
echo "언더레이를 확인했습니다."

echo "== 키와 설정"
PUB_A=$("$CSA" genkey -o "$WORK/a/private.key" | sed -n 's/^공개키: //p')
PUB_B=$("$CSA" genkey -o "$WORK/b/private.key" | sed -n 's/^공개키: //p')
PUB_C=$("$CSA" genkey -o "$WORK/c-unused.key" | sed -n 's/^공개키: //p')

peers_toml() {
  cat <<TOML
[[peer]]
peer-id    = "srv-a"
public-key = "$PUB_A"
tunnel-ip  = "$WG_A"
endpoints  = ["$IP_A:$PORT"]
services   = [{ app = "billing", port = 8080 }]

[[peer]]
peer-id    = "srv-b"
public-key = "$PUB_B"
tunnel-ip  = "$WG_B"
endpoints  = ["$IP_B:$PORT"]
services   = [{ app = "report", port = $PORT_REPORT }, { app = "beacon", port = $PORT_BEACON }]

[[peer]]
peer-id    = "srv-c"
public-key = "$PUB_C"
tunnel-ip  = "$WG_C"
endpoints  = ["$IP_C:$PORT"]
services   = [{ app = "idle", port = 8080 }]
TOML
}
side() { # dir peer-id
  peers_toml > "$WORK/$1/peers.toml"
  cat > "$WORK/$1/csa.toml" <<TOML
peer-id     = "$2"
private-key = "$WORK/$1/private.key"
domain      = "cs.test.internal"
tunnel-cidr = "$CIDR"
listen-port = $PORT

[tun]
name = "$WG_IF"
mtu  = 1420

[dns]
listen = "127.0.53.1:53"
TOML
}
side a srv-a
side b srv-b
# srv-a는 srv-b의 두 서비스에 나가도 된다. srv-c는 정책에 없다.
cat > "$WORK/a/policy.toml" <<TOML
outbound = ["srv-b/report", "srv-b/beacon"]

[[inbound]]
app   = "billing"
allow = ["srv-b"]
TOML
cat > "$WORK/b/policy.toml" <<TOML
outbound = ["srv-a/billing"]

[[inbound]]
app   = "report"
allow = ["srv-a"]

[[inbound]]
app   = "beacon"
allow = ["srv-a"]
TOML

# 앱 노릇을 하는 작은 프로그램들이다.
cat > "$WORK/dial.py" <<'PY'
# TCP로 붙어 본다. 결과 한 줄을 찍는다: 결과 받은것 걸린초.
# 결과는 connected, timeout, 또는 errno 이름이다.
import errno, socket, sys, time
ip, port = sys.argv[1], int(sys.argv[2])
payload = sys.argv[3] if len(sys.argv) > 3 else ""
wait = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0
s = socket.socket()
s.settimeout(wait)
t = time.monotonic()
try:
    s.connect((ip, port))
    got = ""
    if payload:
        s.sendall(payload.encode() + b"\n")
        got = s.recv(64).decode().strip()
    print("connected", got or "-", "%.2f" % (time.monotonic() - t))
except socket.timeout:
    print("timeout", "-", "%.2f" % (time.monotonic() - t))
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)), "-", "%.2f" % (time.monotonic() - t))
finally:
    s.close()
PY
cat > "$WORK/serve.py" <<'PY'
# TCP 연결 하나를 받아 pong:을 붙여 되돌려 주고, 상대의 주소를 찍는다.
import socket, sys
bind, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((bind, port))
s.listen(4)
while True:
    c, peer = s.accept()
    try:
        data = c.recv(64)
        c.sendall(b"pong:" + data)
    except OSError:
        pass
    print(peer[0], flush=True)
    c.close()
PY
cat > "$WORK/udp-serve.py" <<'PY'
# UDP 데이터그램을 받아 pong:을 붙여 되돌려 주고, 상대의 주소를 찍는다.
import socket, sys
bind, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((bind, port))
while True:
    data, peer = s.recvfrom(64)
    s.sendto(b"pong:" + data, peer)
    print(peer[0], flush=True)
PY
cat > "$WORK/udp-dial.py" <<'PY'
# UDP 데이터그램을 보내고 답을 기다린다. 결과 한 줄을 찍는다: 결과 받은것 답의출발지.
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b"ping", (ip, port))
    data, peer = s.recvfrom(64)
    print("reply", data.decode().strip(), peer[0])
except socket.timeout:
    print("timeout", "-", "-")
except OSError as e:
    print(type(e).__name__, "-", "-")
PY

echo "== 설정 검사"
"$CSA" check -c "$WORK/a"
"$CSA" check -c "$WORK/b"

echo "== csa 기동"
# CSA_DEBUG를 켜야 wg가 출발지 검사에서 버린 패킷을 적는다. 아래 검사 하나가 그
# 기록을 본다.
#
# 배경에 띄울 때는 함수를 거치지 않는다. 함수를 배경에 띄우면 $!가 서브셸의 PID가
# 되어 kill이 csa에 닿지 않고 csa가 고아로 남는다.
ip netns exec "$NS_A" env CSA_DEBUG=1 "$CSA" run -c "$WORK/a" > "$WORK/a/csa.log" 2>&1 & PID_A=$!
ip netns exec "$NS_B" env CSA_DEBUG=1 "$CSA" run -c "$WORK/b" > "$WORK/b/csa.log" 2>&1 & PID_B=$!
for _ in $(seq 30); do
  if nsa ip link show "$WG_IF" >/dev/null 2>&1 && nsb ip link show "$WG_IF" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
nsa ip -brief addr show "$WG_IF" || { tail -20 "$WORK/a/csa.log"; exit 1; }
nsb ip -brief addr show "$WG_IF" || { tail -20 "$WORK/b/csa.log"; exit 1; }

echo "== 세션"
# 두 csa가 같은 순간에 뜨면 첫 handshake가 어긋나 몇 초 뒤에 다시 선다.
OK=0
for i in $(seq 45); do
  if nsa ping -c 1 -W 1 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then
    echo "세션이 섰습니다. ${i}초 걸렸습니다."; OK=1; break
  fi
done
if [ "$OK" = 0 ]; then
  echo "세션이 서지 않습니다."
  echo "--- a의 로그 ---"; tail -30 "$WORK/a/csa.log"
  echo "--- b의 로그 ---"; tail -30 "$WORK/b/csa.log"
  exit 1
fi

# 되돌아가는 패킷의 출발지가 실제 IP로 바뀌는 자리가 라우팅 뒤인지 보려면
# 역경로 검사를 엄격하게 두어야 한다. 앞이면 이 검사가 그 패킷을 버린다.
for ns in "$NS_A" "$NS_B"; do
  ip netns exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=1 \
    net.ipv4.conf.eth0.rp_filter=1 "net.ipv4.conf.$WG_IF.rp_filter=1"
done

echo
echo "== NAT 표"
# 자기 표를 만들고 지우는 배치로 시작해 어느 경우에도 같은 자리에서 시작한다.
apply_nat() { # ns 규칙글
  printf 'add table ip %s\ndelete table ip %s\n%s\n' "$NAT" "$NAT" "$2" | ip netns exec "$1" nft -f -
}
# 보내는 쪽 규칙. 상대마다, 서비스 포트마다, tcp와 udp를 적는다. srv-c는 정책에
# 없지만 peers.toml에 있으므로 여기에도 있다. 정책은 csa가 본다.
nat_a() { # snat여부(1이면 넣는다)
  local snat=""
  if [ "$1" = 1 ]; then
    snat="	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname \"$WG_IF\" ip saddr != $CIDR counter snat to $WG_A
	}"
  fi
  cat <<RULES
table ip $NAT {
	chain output {
		type nat hook output priority dstnat; policy accept;
		ip daddr $IP_B tcp dport $PORT_REPORT counter dnat to $WG_B
		ip daddr $IP_B udp dport $PORT_REPORT counter dnat to $WG_B
		ip daddr $IP_B tcp dport $PORT_BEACON counter dnat to $WG_B
		ip daddr $IP_B udp dport $PORT_BEACON counter dnat to $WG_B
		ip daddr $IP_C tcp dport 8080 counter dnat to $WG_C
		ip daddr $IP_C udp dport 8080 counter dnat to $WG_C
	}
$snat
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "$WG_IF" ip daddr $WG_A counter dnat to $IP_A
	}
	chain input {
		type nat hook input priority srcnat; policy accept;
		iifname "$WG_IF" ip saddr $WG_B counter snat to $IP_B
		iifname "$WG_IF" ip saddr $WG_C counter snat to $IP_C
	}
}
RULES
}
nat_b() {
  cat <<RULES
table ip $NAT {
	chain output {
		type nat hook output priority dstnat; policy accept;
		ip daddr $IP_A tcp dport 8080 counter dnat to $WG_A
		ip daddr $IP_A udp dport 8080 counter dnat to $WG_A
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "$WG_IF" ip saddr != $CIDR counter snat to $WG_B
	}
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "$WG_IF" ip daddr $WG_B counter dnat to $IP_B
	}
	chain input {
		type nat hook input priority srcnat; policy accept;
		iifname "$WG_IF" ip saddr $WG_A counter snat to $IP_A
	}
}
RULES
}
apply_nat "$NS_B" "$(nat_b)"
echo "b에 표를 걸었습니다."

serve() { # ns bind port → 배경에서 띄우고 SRV에 pid를 둔다. 찍는 것은 SRV_OUT에 남는다
  SRV_OUT="$WORK/serve-$3.out"
  ip netns exec "$1" python3 "$WORK/serve.py" "$2" "$3" > "$SRV_OUT" 2>&1 & SRV=$!
  sleep 0.7
}
stop_serve() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; SRV=""; sleep 0.2; }

echo
echo "== 출발지를 바꾸지 않으면"
# 목적지만 터널 IP로 바꾸고 출발지를 그대로 두면, 안쪽 패킷의 출발지가 실제 IP라
# 받는 쪽 wg가 허용 IP 검사에서 버려야 한다. 이것이 출발지도 바꾸는 까닭이다.
apply_nat "$NS_A" "$(nat_a 0)"
serve "$NS_B" 0.0.0.0 "$PORT_REPORT"
read -r why _ took < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" ping 3)
if [ "$why" != connected ]; then
  ok "출발지를 바꾸지 않으면 서지 않는다 ($why, ${took}초)"
else
  bad "출발지를 바꾸지 않았는데 섰다"
fi
sleep 0.3
if grep -q "disallowed source address" "$WORK/b/csa.log"; then
  ok "받는 쪽 wg가 허용 IP 검사에서 버렸다고 적는다"
else
  bad "받는 쪽 wg의 기록에 허용 IP 검사가 없다"
fi
stop_serve

echo
echo "== 실제 IP로 부른 TCP"
apply_nat "$NS_A" "$(nat_a 1)"
echo "a에 표를 걸었습니다."
serve "$NS_B" 0.0.0.0 "$PORT_REPORT"
read -r why got took < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" ping 5)
if [ "$why" = connected ] && [ "$got" = "pong:ping" ]; then
  ok "앱이 상대의 실제 IP와 포트로 TCP를 맺고 양쪽으로 자료가 오간다"
else
  bad "실제 IP로 TCP가 서지 않는다 ($why, 받은 것 $got)"
fi
sleep 0.3
if grep -q "들어온 연결을 받았습니다.*상대 srv-a" "$WORK/b/csa.log"; then
  ok "받는 쪽 csa의 기록에 peer-id가 남는다. 터널로 왔다"
else
  bad "받는 쪽 csa의 기록에 그 연결이 없다"
fi
stop_serve

echo
echo "== 실제 IP 하나에만 바인딩한 서버"
serve "$NS_B" "$IP_B" "$PORT_REPORT"
read -r why got _ < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" ping 5)
if [ "$why" = connected ] && [ "$got" = "pong:ping" ]; then
  ok "실제 IP 하나에만 바인딩한 서버가 받는다"
else
  bad "실제 IP에 바인딩한 서버가 받지 못한다 ($why)"
fi
sleep 0.3
peer=$(head -1 "$SRV_OUT" 2>/dev/null || true)
if [ "$peer" = "$IP_A" ]; then
  ok "서버가 보는 상대 주소가 보낸 쪽의 실제 IP다 ($peer)"
else
  bad "서버가 보는 상대 주소가 다르다: ${peer:-없음} (기대 $IP_A)"
fi
stop_serve

echo
echo "== 거절"
# 정책에 없는 상대다. 보내는 쪽 csa가 막고 ICMP로 알린다. 연결 추적이 그 ICMP의
# 주소를 원래대로 되돌려야 앱의 소켓에 닿는다.
read -r why _ took < <(nsa python3 "$WORK/dial.py" "$IP_C" 8080 "" 5)
if [ "$why" = EHOSTUNREACH ]; then
  ok "정책에 없는 상대의 실제 IP로 붙으면 곧바로 EHOSTUNREACH를 받는다 (${took}초)"
else
  bad "정책에 없는 상대에 붙었을 때 받은 것이 다르다: $why (${took}초)"
fi
# 허가된 곳인데 듣는 앱이 없다. 상대 커널의 거절이 되돌아와야 한다.
read -r why _ took < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" "" 5)
if [ "$why" = ECONNREFUSED ]; then
  ok "듣는 앱이 없는 포트로 붙으면 ECONNREFUSED를 받는다 (${took}초)"
else
  bad "듣는 앱이 없는 포트에 붙었을 때 받은 것이 다르다: $why (${took}초)"
fi

echo
echo "== 실제 IP로 부른 UDP"
ip netns exec "$NS_B" python3 "$WORK/udp-serve.py" "$IP_B" "$PORT_BEACON" > "$WORK/udp-serve.out" 2>&1 & SRV=$!
sleep 0.7
read -r why got from < <(nsa python3 "$WORK/udp-dial.py" "$IP_B" "$PORT_BEACON")
if [ "$why" = reply ] && [ "$got" = "pong:ping" ] && [ "$from" = "$IP_B" ]; then
  ok "UDP도 실제 IP로 오가고 답의 출발지가 상대의 실제 IP다"
else
  bad "UDP가 오가지 않는다 ($why, 받은 것 $got, 출발지 $from)"
fi
stop_serve

# 받는 쪽 표의 계수기는 상대 csa를 멈추기 전에 읽는다. 받는 쪽 규칙이 실제로
# 걸렸는지는 이 계수기만 말해 준다. 되돌아가는 패킷은 규칙이 아니라 연결 추적이
# 되돌리므로 보내는 쪽의 받는 방향 계수기는 0이 맞다.
RULES_B=$(nsb nft list table ip "$NAT" 2>&1 || true)

echo
echo "== 상대 csa가 죽었을 때"
# 지금은 상대 csa가 멈추면 그쪽 nftables 표가 사라져 직통 연결이 인증 없이 통한다.
# 보내는 쪽에 이 표가 있으면 그 연결이 터널로 들어가 서지 않아야 한다.
kill "$PID_B"; wait "$PID_B" 2>/dev/null || true
for _ in $(seq 25); do
  kill -0 "$PID_B" 2>/dev/null || break
  sleep 0.2
done
if kill -0 "$PID_B" 2>/dev/null; then
  bad "상대 csa가 멈추지 않는다"
else
  ok "상대 csa가 멈췄다"
fi
PID_B=""
for _ in $(seq 25); do
  nsb nft list table inet callsignet >/dev/null 2>&1 || break
  sleep 0.2
done
if nsb nft list table inet callsignet >/dev/null 2>&1; then
  bad "상대 csa가 멈췄는데 직통 경로 표가 남아 있다"
else
  ok "상대 csa가 멈추면서 직통 경로 표를 지웠다. 서비스 포트가 밖으로 열렸다"
fi
serve "$NS_B" 0.0.0.0 "$PORT_REPORT"
read -r why _ took < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" ping 3)
if [ "$why" != connected ]; then
  ok "상대 csa가 죽어 있으면 실제 IP로 불러도 서지 않는다 ($why)"
else
  bad "상대 csa가 죽어 있는데 실제 IP로 붙었다. 인증 없이 통했다"
fi
# 계수기는 표를 지우기 전에 읽는다.
RULES_A=$(nsa nft list table ip "$NAT" 2>&1 || true)
# 대조. 보내는 쪽 표를 지우면 그 연결이 직통으로 통한다. 표가 그 길을 막고 있었다.
nsa nft delete table ip "$NAT"
read -r why got _ < <(nsa python3 "$WORK/dial.py" "$IP_B" "$PORT_REPORT" ping 3)
if [ "$why" = connected ] && [ "$got" = "pong:ping" ]; then
  ok "보내는 쪽 표를 지우면 같은 연결이 직통으로 인증 없이 통한다. 표가 막고 있었다"
else
  bad "보내는 쪽 표를 지웠는데도 직통으로 붙지 못한다 ($why)"
fi
stop_serve

echo
echo "== 보내는 쪽 표와 계수기"
echo "$RULES_A" | sed 's/^/    /'
echo
echo "== 받는 쪽 표와 계수기"
echo "$RULES_B" | sed 's/^/    /'

mkdir -p "$RESULTS"; own "$RESULTS"
TS=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$RESULTS/steer-$TS.md"
{
  echo "# 실제 IP로 부른 연결을 터널로 돌리기 ($TS)"
  echo
  echo "커밋 $(git -C "$REPO" rev-parse --short HEAD). csa는 이 규칙을 만들지 않는다. 시험 스크립트가 nftables NAT 표를 손으로 걸었다. 역경로 검사는 엄격(rp_filter=1)이다."
  echo
  echo "| 검사 | 결과 |"
  echo "|---|---|"
  printf '%s\n' "${CHECKS[@]}"
  echo
  if [ "$FAIL" = 0 ]; then
    echo "확인됨. 보내는 쪽 NAT 표가 목적지를 상대의 터널 IP로 바꾸고 출발지를 자기 터널 IP로 바꾸면, 앱이 실제 IP로 부른 연결이 터널로 간다. 받는 쪽 NAT 표가 목적지를 자기 실제 IP로 바꾸고 출발지를 상대의 실제 IP로 바꾸면, 실제 IP에 바인딩한 서버가 그 연결을 받고 상대를 실제 IP로 본다. 커널의 연결 추적이 되돌아가는 패킷과 거절 응답의 주소를 되돌린다."
  else
    echo "예상과 다른 것이 있다. 표의 「틀림」을 본다."
  fi
  echo
  echo "보내는 쪽(srv-a)의 표와 계수기. 받는 방향 체인이 0인 것은 되돌아가는 패킷을 규칙이 아니라 연결 추적이 되돌리기 때문이다:"
  echo
  echo '```'
  echo "$RULES_A"
  echo '```'
  echo
  echo "받는 쪽(srv-b)의 표와 계수기. 상대 csa를 멈추기 전에 읽었다:"
  echo
  echo '```'
  echo "$RULES_B"
  echo '```'
} > "$REPORT"
own "$REPORT"

echo
echo "기록: ${REPORT#$REPO/}"
[ "$FAIL" = 0 ] || { echo "--- a의 로그 ---"; tail -20 "$WORK/a/csa.log"; echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }
echo "확인했습니다. 앱이 상대의 실제 IP로 불러도 csa 둘이 터널로 나릅니다."
