#!/usr/bin/env bash
# csa 둘이 터널을 세우고, 앱이 상대의 실제 IP로 불러도 터널로 나르는지 확인한다.
#
# 네임스페이스 둘을 만들어 브리지로 잇고, 각 네임스페이스에서 csa를 띄운 뒤
# 한쪽 터널 IP에서 다른 쪽 터널 IP로 ping을 보낸다. 그다음 앱이 상대의 실제 IP와
# 포트로 붙는다. srv-b는 앱에 실제 IP를 보이는 머신이고 srv-a는 터널 IP를 그대로
# 보이는 머신이다. 두 모드가 한 자리에서 함께 확인된다.
set -euo pipefail

# csa는 개인키와 사전 공유키가 놓인 자리와 그 위의 모든 디렉터리를 다른 사용자가
# 고칠 수 없어야 받아들인다. 리포 체크아웃이 0775인 머신이 있으므로 작업 자리는
# 리포 밖에 두고 umask를 못박는다. /var/tmp는 끈적임 비트가 서 있어 거절되지 않는다.
umask 022

NS_A=cs-a
NS_B=cs-b
# csa를 돌리지 않는 머신이다. peers.toml에도 정책에도 없다. 직통 경로를 재는 데 쓴다.
NS_C=cs-c
BR=cs-br0
IP_A=10.90.0.10
IP_B=10.90.0.30
IP_C=10.90.0.50
# srv-a가 옮겨 갈 자리다. peers.toml에는 적지 않는다.
IP_A2=10.90.0.11
WG_A=10.91.0.1
WG_B=10.91.0.2
CIDR=10.91.0.0/24
PORT=51820
WG_IF=cs0

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK=/var/tmp/csn-tunnel-work
. "$HERE/../lib.sh"

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi
# 만들어 둔 것을 그냥 쓰면 낡은 바이너리로 시험이 돈다. 부르는 사람이 CSA로
# 자리를 주었을 때만 그것을 쓴다.
if [ -n "${CSA:-}" ]; then
  echo "csa를 새로 만들지 않고 준 것을 씁니다: $CSA"
  [ -x "$CSA" ] || { echo "그 자리에 csa가 없습니다: $CSA" >&2; exit 1; }
else
  CSA="$REPO/csa"
  build_csa "$REPO" "$CSA"
fi

cleanup() {
  [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null || true
  [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null || true
  [ -n "${PID_B2:-}" ] && kill "$PID_B2" 2>/dev/null || true
  [ -n "${RV_SRV:-}" ] && kill "$RV_SRV" 2>/dev/null || true
  for pid in "${PID_A3:-}" "${PID_B3:-}" "${PID_A4:-}" "${PID_B4:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  sleep 0.3
  ip netns delete "$NS_A" 2>/dev/null || true
  ip netns delete "$NS_B" 2>/dev/null || true
  ip netns delete "$NS_C" 2>/dev/null || true
  ip link delete "$BR" 2>/dev/null || true
  rm -rf "/etc/netns/$NS_A" "/etc/netns/$NS_B" "/etc/netns/$NS_C"
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
attach "$NS_C" "$IP_C"

# 회사 리졸버만 적어 둔다. csa는 이 파일을 건드리지 않아야 한다. 0.1.x는 여기에
# 자기를 첫 줄에 넣었다. ip netns exec는 /etc/netns/<이름>/resolv.conf가 있으면
# 그것을 /etc/resolv.conf 자리에 붙여 준다.
UPSTREAM=10.90.0.253
for ns in "$NS_A" "$NS_B"; do
  mkdir -p "/etc/netns/$ns"
  echo "nameserver $UPSTREAM" > "/etc/netns/$ns/resolv.conf"
done

# 언더레이가 먼저 통해야 한다. 여기서 막히면 터널 문제가 아니다.
if ! ip netns exec "$NS_A" ping -c 2 -W 2 "$IP_B" >/dev/null 2>&1; then
  echo "언더레이가 통하지 않습니다. 터널 이전의 문제입니다." >&2
  echo "브리지로 오가는 패킷이 방화벽에 막히는지 보십시오:" >&2
  echo "  sysctl net.bridge.bridge-nf-call-iptables" >&2
  echo "  iptables -L FORWARD -n | head -3" >&2
  exit 1
fi
echo "언더레이를 확인했습니다."

echo "== 키와 설정"
PUB_A=$("$CSA" genkey -o "$WORK/a/private.key" | sed -n 's/^공개키: //p')
PUB_B=$("$CSA" genkey -o "$WORK/b/private.key" | sed -n 's/^공개키: //p')
PUB_C=$("$CSA" genkey -o "$WORK/c-unused.key" | sed -n 's/^공개키: //p')

# 사전 공유키는 짝마다 하나다. 두 머신에 상대의 peer-id로 이름 붙여 같은 내용을
# 둔다. srv-a에는 psk/srv-b.key가, srv-b에는 psk/srv-a.key가 놓인다.
#
# srv-c의 키도 만든다. 정책에 없는 상대이지만 peers.toml에 있으므로 csa가 wg에
# 건다. mode가 required이면 그런 상대에도 키가 있어야 한다.
mkdir -p "$WORK/a/psk" "$WORK/b/psk"
"$CSA" genpsk -o "$WORK/a/psk/srv-b.key" >/dev/null
cp "$WORK/a/psk/srv-b.key" "$WORK/b/psk/srv-a.key"
"$CSA" genpsk -o "$WORK/a/psk/srv-c.key" >/dev/null
"$CSA" genpsk -o "$WORK/b/psk/srv-c.key" >/dev/null

# 두 머신에 서로 다른 앱을 둔다.
APP_A=billing
APP_B=report
# srv-b에만 있는 앱이다. srv-a는 나가도 되지만 srv-b는 들이지 않는다. 받는 쪽이
# 최종 판단 주체임을 확인하려고 정책을 일부러 어긋나게 둔다.
APP_SECRET=secret
PORT_SECRET=7070
# 설정에는 있으나 정책에 없는 상대다. 실제 IP로 부르면 보내는 쪽 csa가 막아야 한다.
WG_C=10.91.0.3
IP_C_REAL=10.90.0.99

peers_toml() {
  cat <<TOML
[[peer]]
peer-id    = "srv-a"
public-key = "$PUB_A"
tunnel-ip  = "$WG_A"
endpoints  = ["$IP_A:$PORT"]
services   = [{ app = "$APP_A", port = 8080 }]

[[peer]]
peer-id    = "srv-b"
public-key = "$PUB_B"
tunnel-ip  = "$WG_B"
endpoints  = ["$IP_B:$PORT"]
services   = [{ app = "$APP_B", port = 8080 }, { app = "$APP_SECRET", port = $PORT_SECRET }]

[[peer]]
peer-id    = "srv-c"
public-key = "$PUB_C"
tunnel-ip  = "$WG_C"
endpoints  = ["$IP_C_REAL:$PORT"]
services   = [{ app = "idle", port = 8080 }]
TOML
}
side() { # dir peer-id 상대 내앱 상대앱 outbound줄 받는쪽모드
  peers_toml > "$WORK/$1/peers.toml"
  cat > "$WORK/$1/csa.toml" <<TOML
peer-id     = "$2"
private-key = "$WORK/$1/private.key"
tunnel-cidr = "$CIDR"
listen-port = $PORT

[tun]
name = "cs0"
mtu  = 1420

[nat]
incoming = "$7"

[psk]
dir  = "$WORK/$1/psk"
mode = "required"
TOML
  cat > "$WORK/$1/policy.toml" <<TOML
$6

[[inbound]]
app   = "$4"
allow = ["$3"]
TOML
}
# srv-a는 srv-b의 report와 secret에 나가도 된다. 그런데 srv-b는 report만 들인다.
# srv-a는 앱에 터널 IP를 그대로 보이고, srv-b는 실제 IP로 보인다.
side a srv-a srv-b "$APP_A" "$APP_B" "outbound = [\"srv-b/$APP_B\", \"srv-b/$APP_SECRET\"]" tunnel-ip
side b srv-b srv-a "$APP_B" "$APP_A" "outbound = [\"srv-a/$APP_A\"]" real-ip

echo "== 설정 검사"
"$CSA" check -c "$WORK/a"
"$CSA" check -c "$WORK/b"

echo "== csa 기동"
export CSA_DEBUG="${CSA_DEBUG:-1}"
ip netns exec "$NS_A" env CSA_DEBUG="$CSA_DEBUG" "$CSA" run -c "$WORK/a" > "$WORK/a/csa.log" 2>&1 & PID_A=$!
ip netns exec "$NS_B" env CSA_DEBUG="$CSA_DEBUG" "$CSA" run -c "$WORK/b" > "$WORK/b/csa.log" 2>&1 & PID_B=$!
for _ in $(seq 30); do
  if ip netns exec "$NS_A" ip link show cs0 >/dev/null 2>&1 &&
     ip netns exec "$NS_B" ip link show cs0 >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo "== 인터페이스"
ip netns exec "$NS_A" ip -brief addr show cs0 || true
ip netns exec "$NS_B" ip -brief addr show cs0 || true

echo
echo "== 터널 IP로 ping ($WG_A -> $WG_B)"
# 두 csa가 같은 순간에 뜨면 둘 다 handshake를 건다. 그러면 각자 상대의 응답을
# 받을 자리를 이미 응답 상태로 덮어써서 첫 시도가 어긋난다. wg가 몇 초 뒤에
# 다시 걸어 세션이 서므로 45초까지 기다린다. 17초가 걸린 적이 있다.
OK=0
for i in $(seq 45); do
  if ip netns exec "$NS_A" ping -c 1 -W 1 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then
    echo "세션이 섰습니다. ${i}초 걸렸습니다."
    OK=1; break
  fi
done
if [ "$OK" = 1 ] && ip netns exec "$NS_A" ping -c 3 -W 2 -I "$WG_A" "$WG_B"; then
  echo
  echo "== 주소 바꾸기 표"
  NT_OK=1
  RULES_A=$(ip netns exec "$NS_A" nft list table ip callsignet-nat 2>/dev/null || true)
  RULES_B=$(ip netns exec "$NS_B" nft list table ip callsignet-nat 2>/dev/null || true)
  if [ -n "$RULES_A" ] && [ -n "$RULES_B" ]; then
    printf '  ok    %s\n' "csa가 주소 바꾸기 표를 만들었다"
  else
    printf '  틀림  %s\n' "주소 바꾸기 표가 없다"; NT_OK=0
  fi
  if printf '%s' "$RULES_A" | grep -q "chain output" && ! printf '%s' "$RULES_A" | grep -q "chain prerouting"; then
    printf '  ok    %s\n' "터널 IP를 그대로 보이는 머신은 보내는 쪽 체인만 만든다"
  else
    printf '  틀림  %s\n' "srv-a의 표가 다르다"; NT_OK=0
  fi
  if printf '%s' "$RULES_B" | grep -q "ip daddr $WG_B .*dnat to $IP_B" &&
     printf '%s' "$RULES_B" | grep -q "ip daddr $IP_A tcp dport 8080 .*dnat to $WG_A"; then
    printf '  ok    %s\n' "실제 IP로 보이는 머신은 두 방향 체인을 모두 만든다"
  else
    printf '  틀림  %s\n' "srv-b의 표가 다르다"; NT_OK=0
  fi
  if [ "$(cat "/etc/netns/$NS_A/resolv.conf")" = "nameserver $UPSTREAM" ]; then
    printf '  ok    %s\n' "csa가 /etc/resolv.conf를 건드리지 않는다"
  else
    printf '  틀림  %s\n' "csa가 /etc/resolv.conf를 고쳤다"; cat "/etc/netns/$NS_A/resolv.conf"; NT_OK=0
  fi
  [ "$NT_OK" = 1 ] || { echo "--- a의 표 ---"; echo "$RULES_A"; echo "--- b의 표 ---"; echo "$RULES_B"; exit 1; }

  echo
  echo "== 실제 IP로 부른 연결"
  # 앱은 상대를 지금 쓰는 실제 IP로 부른다. 보내는 쪽 csa의 표가 그 연결을 터널로
  # 돌린다. 받는 쪽 서버는 실제 IP 하나에만 듣는다. 레거시 서버가 그렇다. 받는 쪽
  # csa의 표가 목적지를 실제 IP로 바꾸지 않으면 이 서버는 받지 못한다.
  TCP_OK=1
  serve_tcp() { # ns bind 출력파일
    ip netns exec "$1" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$2', 8080))
s.listen(1)
c, peer = s.accept()
c.sendall(b'pong:' + c.recv(64))
print(peer[0], flush=True)
c.close()
" > "$3" 2>&1 &
    sleep 1
  }
  dial_tcp() { # ns 주소
    ip netns exec "$1" timeout 5 bash -c \
      "exec 3<>/dev/tcp/$2/8080; printf 'ping\n' >&3; head -1 <&3" 2>/dev/null || true
  }
  serve_tcp "$NS_B" "$IP_B" "$WORK/b/serve.out"; LISTEN_PID=$!
  got=$(dial_tcp "$NS_A" "$IP_B")
  sleep 0.3
  kill "$LISTEN_PID" 2>/dev/null || true
  if [ "$got" = "pong:ping" ]; then
    printf '  ok    %s\n' "앱이 상대의 실제 IP와 포트로 TCP를 맺고 양쪽으로 자료가 오간다"
  else
    printf '  틀림  %s\n' "실제 IP로 TCP가 서지 않는다. 받은 것: ${got:-없음}"; TCP_OK=0
  fi
  if grep -q "들어온 연결을 받았습니다.*상대 srv-a.*:8080" "$WORK/b/csa.log"; then
    printf '  ok    %s\n' "받는 쪽 csa의 기록에 peer-id가 남는다. 터널로 왔다"
  else
    printf '  틀림  %s\n' "받는 쪽 csa의 기록에 그 연결이 없다"; TCP_OK=0
  fi
  peer=$(head -1 "$WORK/b/serve.out" 2>/dev/null || true)
  if [ "$peer" = "$IP_A" ]; then
    printf '  ok    %s\n' "실제 IP 하나에만 바인딩한 서버가 받고 상대를 보낸 쪽의 실제 IP로 본다 ($peer)"
  else
    printf '  틀림  %s\n' "서버가 보는 상대 주소가 다르다: ${peer:-없음} (기대 $IP_A)"; TCP_OK=0
  fi
  # ping은 ICMP라서 peer 단위로만 판단한다. TCP는 다르다. 서버가 돌려주는 패킷의
  # 목적지는 부른 쪽 앱의 임시 포트인데, 그 포트는 어느 정책에도 적혀 있지 않다.
  # csa가 들인 연결을 기억하지 않으면 손잡기부터 서지 않는다.
  if grep -q "나가는 연결을 막았습니다" "$WORK/b/csa.log"; then
    printf '  틀림  %s\n' "받는 쪽이 자기 답을 막았다"
    grep "나가는 연결을 막았습니다" "$WORK/b/csa.log" | tail -3 | sed 's/^/        /'; TCP_OK=0
  else
    printf '  ok    %s\n' "받는 쪽이 자기 답을 막지 않는다"
  fi

  # UDP도 같은 길이다. 서버는 실제 IP에 듣고 답의 출발지도 실제 IP여야 한다.
  ip netns exec "$NS_B" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$IP_B', 8080))
data, peer = s.recvfrom(64)
s.sendto(b'pong:' + data, peer)
" > /dev/null 2>&1 & UDP_PID=$!
  sleep 1
  got=$(ip netns exec "$NS_A" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b'ping', ('$IP_B', 8080))
    data, peer = s.recvfrom(64)
    print(data.decode(), peer[0])
except OSError as e:
    print('실패', type(e).__name__)
" 2>/dev/null || true)
  kill "$UDP_PID" 2>/dev/null || true
  if [ "$got" = "pong:ping $IP_B" ]; then
    printf '  ok    %s\n' "UDP도 실제 IP로 오가고 답의 출발지가 상대의 실제 IP다"
  else
    printf '  틀림  %s\n' "UDP가 오가지 않는다: ${got:-없음}"; TCP_OK=0
  fi

  # 반대 방향. srv-a는 터널 IP를 그대로 보이는 머신이다. 서버는 0.0.0.0에 듣고
  # 상대를 보낸 쪽의 터널 IP로 본다. 두 모드가 한 자리에서 서로 통한다.
  serve_tcp "$NS_A" 0.0.0.0 "$WORK/a/serve.out"; LISTEN_PID=$!
  got=$(dial_tcp "$NS_B" "$IP_A")
  sleep 0.3
  kill "$LISTEN_PID" 2>/dev/null || true
  peer=$(head -1 "$WORK/a/serve.out" 2>/dev/null || true)
  if [ "$got" = "pong:ping" ] && [ "$peer" = "$WG_B" ]; then
    printf '  ok    %s\n' "터널 IP를 그대로 보이는 머신의 앱은 상대를 터널 IP로 본다 ($peer)"
  else
    printf '  틀림  %s\n' "반대 방향이 다르다. 받은 것 ${got:-없음}, 상대 주소 ${peer:-없음} (기대 $WG_B)"; TCP_OK=0
  fi
  [ "$TCP_OK" = 1 ] || { echo "--- a의 로그 ---"; tail -20 "$WORK/a/csa.log"; echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }

  if [ "$TCP_OK" = 1 ]; then
    echo
    echo "확인했습니다. 앱이 실제 IP로 부르고 csa 둘이 터널로 나릅니다."

    echo
    echo "== 직통 경로"
    # csa를 돌리지 않는 머신 하나가 srv-b의 실제 IP로 붙어 본다. peers.toml에도
    # 없고 정책에도 없는 머신이다. csa가 닫지 않으면 그대로 통한다.
    DP_OK=1
    # 앱은 0.0.0.0에 듣는다. 앱을 고치지 않고도 막히는지 보려는 것이다.
    ip netns exec "$NS_B" python3 -c "
import socket, threading

def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(8)
    while True:
        c, _ = s.accept()
        c.sendall(b'here\n')
        c.close()

threading.Thread(target=serve, args=(8080,), daemon=True).start()
serve(9999)
" & OPEN_PID=$!
    sleep 1

    knock_c() { # 주소 포트
      ip netns exec "$NS_C" timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2; head -1 <&3" 2>/dev/null || true
    }
    if [ -z "$(knock_c "$IP_B" 8080)" ]; then
      printf '  ok    %s\n' "csa 없는 머신이 실제 IP로 서비스 포트에 붙지 못한다"
    else
      printf '  틀림  %s\n' "실제 IP로 서비스 포트에 붙었다"; DP_OK=0
    fi
    if [ "$(knock_c "$IP_B" 9999)" = "here" ]; then
      printf '  ok    %s\n' "peers.toml에 없는 포트는 막지 않는다"
    else
      printf '  틀림  %s\n' "적지 않은 포트까지 막았다"; DP_OK=0
    fi
    if [ "$(ip netns exec "$NS_A" timeout 3 bash -c \
        "exec 3<>/dev/tcp/$IP_B/8080; head -1 <&3" 2>/dev/null || true)" = "here" ]; then
      printf '  ok    %s\n' "csa 있는 머신이 실제 IP로 부른 연결은 터널로 돌아 지난다"
    else
      printf '  틀림  %s\n' "터널로 오는 연결까지 막았다"; DP_OK=0
    fi
    if ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1; then
      printf '  ok    %s\n' "csa가 자기 nftables 표를 만들었다"
    else
      printf '  틀림  %s\n' "csa의 nftables 표가 없다"; DP_OK=0
    fi
    n=$("$CSA" status -c "$WORK/b" -json 2>/dev/null | sed -n 's/.*"guard-blocked":\([0-9]*\).*/\1/p')
    if [ "${n:-0}" -gt 0 ]; then
      printf '  ok    %s\n' "csa status가 막은 패킷을 센다 (${n}개)"
    else
      printf '  틀림  %s\n' "막은 패킷을 세지 않는다 (${n:-없음})"; DP_OK=0
    fi
    kill "$OPEN_PID" 2>/dev/null || true

    [ "$DP_OK" = 1 ] || {
      echo "--- b의 규칙 ---"; ip netns exec "$NS_B" nft list ruleset 2>&1 | sed 's/^/        /'
      echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }


    echo
    echo "== 거절 응답"
    # csa가 나가는 연결을 막을 때 앱에 ICMP로 알린다. 앱이 연결 시간을 다
    # 기다리지 않고 곧바로 실패를 보아야 한다. 조용히 버리면 그것을 확인할 수 없다.
    if ! ip netns exec "$NS_A" python3 - "$WG_B" "$WG_C" "$IP_B" "$IP_C_REAL" <<'PYREJECT'
import errno
import socket
import sys
import time

wg_b, wg_c, ip_b, ip_c = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ok = True


def check(cond, good, bad):
    global ok
    if cond:
        print("  ok    " + good)
    else:
        print("  틀림  " + bad)
        ok = False


def dial(addr, port):
    s = socket.socket()
    s.settimeout(5)
    t = time.monotonic()
    try:
        s.connect((addr, port))
        return "연결됨", time.monotonic() - t
    except TimeoutError:
        return "시간초과", time.monotonic() - t
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno)), time.monotonic() - t
    finally:
        s.close()


# 정책에 없는 상대다. csa가 막고 거절을 돌려준다.
why, took = dial(wg_c, 8080)
check(why == "EHOSTUNREACH",
      "정책에 없는 상대에 붙으면 곧바로 실패한다",
      "거절이 앱에 닿지 않았다: %s" % why)
check(took < 1.0,
      "기다리지 않고 실패한다 (%.2f초)" % took,
      "연결 시간을 다 기다렸다 (%.2f초)" % took)

# 같은 상대인데 정책에 없는 포트다.
why, took = dial(wg_b, 9090)
check(why == "EHOSTUNREACH",
      "정책에 없는 포트에 붙으면 곧바로 실패한다",
      "거절이 앱에 닿지 않았다: %s" % why)

# 허가된 곳이다. 듣는 앱이 없으므로 상대 커널이 거절한다. csa의 거절과 달라야
# 한다. 같으면 무엇 때문에 실패했는지 앱이 가릴 수 없다.
why, took = dial(wg_b, 8080)
check(why in ("ECONNREFUSED", "연결됨"),
      "허가된 곳은 상대가 답한다 (%s)" % why,
      "허가된 곳인데 csa가 막았다: %s" % why)

# 실제 IP로 불러도 같다. 보내는 쪽 표가 터널로 돌린 뒤 csa가 거절하면, 연결
# 추적이 그 거절의 주소를 원래대로 되돌려 앱의 소켓에 닿아야 한다.
why, took = dial(ip_c, 8080)
check(why == "EHOSTUNREACH" and took < 1.0,
      "정책에 없는 상대의 실제 IP로 붙으면 곧바로 EHOSTUNREACH를 받는다 (%.2f초)" % took,
      "실제 IP로 붙었을 때 받은 것이 다르다: %s (%.2f초)" % (why, took))
why, took = dial(ip_b, 8080)
check(why == "ECONNREFUSED",
      "듣는 앱이 없는 실제 IP의 포트로 붙으면 ECONNREFUSED를 받는다",
      "실제 IP의 빈 포트에 붙었을 때 받은 것이 다르다: %s" % why)

sys.exit(0 if ok else 1)
PYREJECT
    then
      echo "--- a의 로그 ---"; grep "막았습니다" "$WORK/a/csa.log" | tail -5 | sed 's/^/        /'
      exit 1
    fi
    echo
    echo "== 정책 집행"
    POL_OK=1
    try_tcp() { ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$1/$2" >/dev/null 2>&1 || true; }
    saw() { # 파일 문구 설명
      if grep -q "$2" "$1"; then printf '  ok    %s\n' "$3"
      else printf '  틀림  %s\n' "$3"; POL_OK=0; fi
    }

    # 나가는 쪽. 정책에 없는 포트다.
    try_tcp "$WG_B" 9999
    # 나가는 쪽. 정책에 없는 상대다. ICMP에는 포트가 없다.
    ip netns exec "$NS_A" ping -c 1 -W 1 "$WG_C" >/dev/null 2>&1 || true
    # 받는 쪽. srv-a는 나가도 되지만 srv-b가 들이지 않는다.
    try_tcp "$WG_B" "$PORT_SECRET"
    sleep 0.5

    saw "$WORK/a/csa.log" "나가는 연결을 막았습니다" "나가는 쪽이 정책에 없는 곳을 막는다"
    saw "$WORK/a/csa.log" "모르는 상대다\|서비스가 없는 상대다" "나가는 쪽이 정책에 없는 상대를 막는다"
    saw "$WORK/b/csa.log" "들어온 연결을 막았습니다" "받는 쪽이 정책에 없는 연결을 막는다"
    if grep -q "들어온 연결을 막았습니다" "$WORK/a/csa.log"; then
      printf '  틀림  %s\n' "허가된 연결을 받는 쪽이 막았다"; POL_OK=0
    else
      printf '  ok    %s\n' "허가된 연결은 그대로 지난다"
    fi
    saw "$WORK/b/csa.log" "들어온 연결을 받았습니다.*상대 srv-a.*관측한 출발지 $IP_A" \
        "기록에 peer-id와 관측한 출발지가 함께 남는다"
    n=$(grep -c "들어온 연결을 받았습니다" "$WORK/b/csa.log" || true)
    if [ "$n" -le 10 ]; then printf '  ok    %s\n' "연결마다 한 번만 적는다 ($n줄)"
    else printf '  틀림  %s\n' "패킷마다 적고 있다 ($n줄)"; POL_OK=0; fi

    [ "$POL_OK" = 1 ] || { echo; echo "--- a의 로그 ---"; grep 막았습니다 "$WORK/a/csa.log" || true
                           echo "--- b의 로그 ---"; grep 막았습니다 "$WORK/b/csa.log" || true; exit 1; }
    echo
    echo "확인했습니다. 받는 쪽이 최종 판단을 합니다."

    echo
    echo "== 상태"
    ST_OK=1
    "$CSA" status -c "$WORK/a" 2>&1 | sed 's/^/    /'
    SJ=$("$CSA" status -c "$WORK/a" -json 2>/dev/null || true)
    if ! python3 - "$SJ" "$IP_B" <<'PYCHECK'
import json, sys

st = json.loads(sys.argv[1])
peers = {p["peer-id"]: p for p in st["peers"]}
ok = True


def check(cond, good, bad):
    global ok
    if cond:
        print("  ok    " + good)
    else:
        print("  틀림  " + bad)
        ok = False


check(sorted(peers) == ["srv-b", "srv-c"],
      "peers.toml의 상대를 모두 보여 준다",
      "상대 목록이 다르다: %s" % sorted(peers))

b = peers.get("srv-b", {})
check(b.get("handshake", "").startswith("20"),
      "세션을 맺은 상대의 handshake 시각을 보여 준다",
      "handshake 시각이 없다: %s" % b.get("handshake"))
check(b.get("endpoint", "").startswith(sys.argv[2] + ":"),
      "관측한 출발지를 보여 준다",
      "출발지가 다르다: %s" % b.get("endpoint"))
check(b.get("rx-bytes", 0) > 0 and b.get("tx-bytes", 0) > 0,
      "주고받은 바이트를 보여 준다",
      "바이트 수가 0이다. 받음 %s, 보냄 %s" % (b.get("rx-bytes"), b.get("tx-bytes")))
check(b.get("psk") is True,
      "사전 공유키를 쓰는 상대를 보여 준다",
      "사전 공유키를 쓰는데 그렇게 보이지 않는다")

c = peers.get("srv-c", {})
check(c.get("handshake", "").startswith("0001"),
      "세션을 맺지 않은 상대는 시각이 비어 있다",
      "시각이 있다: %s" % c.get("handshake"))
check(not c.get("endpoint"),
      "세션을 맺지 않은 상대는 출발지가 비어 있다",
      "관측하지 않은 주소를 보여 준다: %s" % c.get("endpoint"))

check(st.get("nat-steered", 0) > 0,
      "터널로 돌린 연결을 센다 (%d개)" % st.get("nat-steered", 0),
      "실제 IP로 부른 연결을 돌렸는데 세지 않는다: %s" % st.get("nat-steered"))
check(st.get("nat-incoming") == "터널 IP",
      "앱에 보이는 주소의 모드를 보여 준다 (%s)" % st.get("nat-incoming"),
      "모드가 다르다: %s" % st.get("nat-incoming"))

sys.exit(0 if ok else 1)
PYCHECK
    then ST_OK=0; fi
    [ "$ST_OK" = 1 ] || { echo "$SJ"; exit 1; }

    echo
    echo "== 설정 다시 읽기"
    RL_OK=1
    rl() { # 설명 기대문구 [파일]
      out=$("$CSA" reload -c "$WORK/b" 2>&1 || true)
      if printf '%s' "$out" | grep -q "$2"; then
        printf '  ok    %s\n' "$1"
      else
        printf '  틀림  %s\n' "$1"; printf '%s\n' "$out" | sed 's/^/        /'; RL_OK=0
      fi
    }

    rl "바뀐 것이 없으면 그렇게 알린다" "바뀐 것이 없습니다"

    # 어긋난 설정은 걸지 않는다. csa는 앞서 읽은 설정 그대로 계속 돈다.
    cp "$WORK/b/policy.toml" "$WORK/b/policy.toml.bak"
    printf '\n[[inbound]]\napp   = "없는앱"\nallow = ["srv-a"]\n' >> "$WORK/b/policy.toml"
    rl "어긋난 설정은 걸지 않는다" "아무것도 바꾸지 않았다"
    mv "$WORK/b/policy.toml.bak" "$WORK/b/policy.toml"

    # csa.toml은 도는 중에 바꿀 수 없다.
    cp "$WORK/b/csa.toml" "$WORK/b/csa.toml.bak"
    sed -i 's/^mtu  = 1420/mtu  = 1280/' "$WORK/b/csa.toml"
    rl "csa.toml이 바뀌면 다시 띄우라고 한다" "다시 띄우라"
    mv "$WORK/b/csa.toml.bak" "$WORK/b/csa.toml"

    # 정책을 바꾸고 다시 읽으면 집행이 달라진다. 앞에서 srv-b가 막았던 앱이다.
    printf '\n[[inbound]]\napp   = "%s"\nallow = ["srv-a"]\n' "$APP_SECRET" >> "$WORK/b/policy.toml"
    rl "정책을 바꾸면 바꾸었다고 알린다" "정책을 바꾸었습니다"
    ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$WG_B/$PORT_SECRET" >/dev/null 2>&1 || true
    sleep 0.5
    if grep -q "들어온 연결을 받았습니다.*:$PORT_SECRET" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "바뀐 정책대로 들인다"
    else
      printf '  틀림  %s\n' "정책을 바꿨는데 받는 쪽이 여전히 막는다"; RL_OK=0
    fi

    # 상대를 더하면 주소 바꾸기 표도 함께 바뀐다.
    PUB_D=$("$CSA" genkey -o "$WORK/d-unused.key" | sed -n 's/^공개키: //p')
    "$CSA" genpsk -o "$WORK/a/psk/srv-d.key" >/dev/null
    printf '\n[[peer]]\npeer-id    = "srv-d"\npublic-key = "%s"\ntunnel-ip  = "10.91.0.4"\nendpoints  = ["10.90.0.98:%s"]\nservices   = [{ app = "ledger", port = 8080 }]\n' \
      "$PUB_D" "$PORT" >> "$WORK/a/peers.toml"
    out=$("$CSA" reload -c "$WORK/a" 2>&1 || true)
    if printf '%s' "$out" | grep -q "더한 상대: srv-d"; then
      printf '  ok    %s\n' "상대를 더하면 더했다고 알린다"
    else
      printf '  틀림  %s\n' "더한 상대를 알리지 않는다"; printf '%s\n' "$out" | sed 's/^/        /'; RL_OK=0
    fi
    if ip netns exec "$NS_A" nft list table ip callsignet-nat 2>/dev/null | grep -q "ip daddr 10.90.0.98 tcp dport 8080 .*dnat to 10.91.0.4"; then
      printf '  ok    %s\n' "더한 상대의 실제 IP가 바로 표에 실린다"
    else
      printf '  틀림  %s\n' "더한 상대가 표에 없다"
      ip netns exec "$NS_A" nft list table ip callsignet-nat 2>&1 | sed 's/^/        /'; RL_OK=0
    fi

    [ "$RL_OK" = 1 ] || exit 1

    echo
    echo "== 철회"
    # 오가는 중인 연결에서 정책을 거두면 그 연결로 더 오가지 못해야 한다.
    #
    # 재는 것은 서버가 미는 방향이다. 앱이 부르는 방향은 고치기 전에도 막혔다.
    # 살아남던 것은 받는 쪽이 되돌려 보내는 방향이다. csa가 들여 둔 연결을
    # 기억해 그 방향을 정책 없이 통과시키기 때문이다.
    RV_OK=1
    ip netns exec "$NS_B" python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$IP_B', 8080))
s.listen(1)
c, _ = s.accept()
c.sendall(b'echo:' + c.recv(64))
time.sleep(6)          # 이 사이에 시험 스크립트가 정책을 거둔다
c.sendall(b'push\n')   # 거둔 뒤에 서버가 먼저 민다
time.sleep(5)
" > "$WORK/b/revoke-srv.out" 2>&1 & RV_SRV=$!
    sleep 1
    ip netns exec "$NS_A" python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
s.connect(('$IP_B', 8080))
s.sendall(b'first\n')
print('첫째', s.recv(64).decode().strip(), flush=True)
s.settimeout(10)
try:
    got = s.recv(64)
    print('밀어 준 것', got.decode().strip() if got else '연결이 닫혔다')
except OSError as e:
    print('밀어 준 것 막힘', type(e).__name__)
" > "$WORK/revoke.out" 2>&1 & RV_CLI=$!
    sleep 3

    # srv-b가 srv-a를 더 들이지 않게 한다.
    cat > "$WORK/b/policy.toml" <<TOML
outbound = ["srv-a/$APP_A"]

[[inbound]]
app   = "$APP_B"
allow = []
TOML
    "$CSA" reload -c "$WORK/b" >/dev/null
    wait "$RV_CLI" 2>/dev/null || true
    kill "$RV_SRV" 2>/dev/null || true

    if grep -q "^첫째 echo:first" "$WORK/revoke.out"; then
      printf '  ok    %s\n' "철회하기 전에는 오간다"
    else
      printf '  틀림  %s\n' "철회하기 전부터 오가지 못한다"; sed 's/^/        /' "$WORK/revoke.out"; RV_OK=0
    fi
    if grep -q "^밀어 준 것 막힘\|^밀어 준 것 연결이 닫혔다" "$WORK/revoke.out"; then
      printf '  ok    %s\n' "철회한 뒤에는 받는 쪽이 미는 것도 막힌다"
    else
      printf '  틀림  %s\n' "철회했는데 받는 쪽이 미는 것이 앱에 닿는다"; sed 's/^/        /' "$WORK/revoke.out"; RV_OK=0
    fi
    if grep -q "정책이 바뀌어 들여 둔 연결" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "잊은 연결이 몇 개인지 적는다"
    else
      printf '  틀림  %s\n' "잊은 연결의 수를 적지 않는다"; RV_OK=0
    fi
    [ "$RV_OK" = 1 ] || exit 1

    echo
    echo "== IP 대역 정책"
    BD_OK=1
    # srv-b의 정책을 통째로 다시 쓴다. secret 앱에 대역 조건을 건다.
    policy_b() { # 허용 대역
      cat > "$WORK/b/policy.toml" <<TOML
outbound = ["srv-a/$APP_A"]

[[inbound]]
app   = "$APP_B"
allow = ["srv-a"]

[[inbound]]
app        = "$APP_SECRET"
allow      = ["srv-a"]
allow-cidr = ["$1"]
expires    = "2099-01-01"
TOML
      "$CSA" reload -c "$WORK/b" >/dev/null
    }
    count_b() { grep -c "$1" "$WORK/b/csa.log" 2>/dev/null || true; }
    knock() {
      ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$WG_B/$PORT_SECRET" >/dev/null 2>&1 || true
      sleep 0.5
    }

    # srv-a는 10.90.0.10에서 온다. 그 대역을 허용하면 들어온다.
    policy_b "10.90.0.0/24"
    before=$(count_b "들어온 연결을 받았습니다.*:$PORT_SECRET")
    knock
    if [ "$(count_b "들어온 연결을 받았습니다.*:$PORT_SECRET")" -gt "$before" ]; then
      printf '  ok    %s\n' "허용 대역에서 오면 들인다"
    else
      printf '  틀림  %s\n' "허용 대역에서 왔는데 막는다"; BD_OK=0
    fi

    # 같은 상대라도 대역이 다르면 막는다. peer-id와 대역을 모두 만족해야 한다.
    policy_b "192.0.2.0/24"
    before=$(count_b "들어온 연결을 받았습니다.*:$PORT_SECRET")
    beforeban=$(count_b "허용 대역 밖에서 왔다")
    knock
    if [ "$(count_b "허용 대역 밖에서 왔다")" -gt "$beforeban" ]; then
      printf '  ok    %s\n' "허용 대역 밖에서 오면 막는다"
    else
      printf '  틀림  %s\n' "대역 밖인데 막지 않는다"; BD_OK=0
    fi
    if [ "$(count_b "들어온 연결을 받았습니다.*:$PORT_SECRET")" -eq "$before" ]; then
      printf '  ok    %s\n' "막힌 연결은 앱에 가지 않는다"
    else
      printf '  틀림  %s\n' "막았다면서 앱에 넘겼다"; BD_OK=0
    fi
    if grep -q "허용 대역 밖에서 왔다.*관측한 출발지 $IP_A" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "막은 까닭에 관측한 출발지가 남는다"
    else
      printf '  틀림  %s\n' "관측한 출발지를 적지 않는다"
      grep "허용 대역" "$WORK/b/csa.log" | tail -3 | sed 's/^/        /'; BD_OK=0
    fi

    # 대역을 보는 규칙이 없는 앱은 그대로 지난다.
    before=$(count_b "들어온 연결을 받았습니다.*:8080")
    ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$WG_B/8080" >/dev/null 2>&1 || true
    sleep 0.5
    if [ "$(count_b "들어온 연결을 받았습니다.*:8080")" -gt "$before" ]; then
      printf '  ok    %s\n' "대역을 조건으로 두지 않은 앱은 그대로 지난다"
    else
      printf '  틀림  %s\n' "대역을 조건으로 두지 않은 앱까지 막는다"; BD_OK=0
    fi

    [ "$BD_OK" = 1 ] || { echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }

    echo
    echo "== MTU와 MSS"
    MT_OK=1
    # TUN 인터페이스의 MTU는 1420이다. IP 헤더 20과 ICMP 헤더 8을 빼면 1392가
    # 조각내지 않고 보낼 수 있는 가장 큰 자료다. 그 경계를 양쪽에서 본다.
    if ip netns exec "$NS_A" ping -c 1 -W 2 -M do -s 1392 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then
      printf '  ok    %s\n' "터널 MTU에 꼭 맞는 패킷이 지난다 (1392바이트)"
    else
      printf '  틀림  %s\n' "MTU 안인데 지나지 못한다 (1392바이트)"; MT_OK=0
    fi
    if ip netns exec "$NS_A" ping -c 1 -W 2 -M do -s 1393 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then
      printf '  틀림  %s\n' "MTU를 넘는데 지났다 (1393바이트)"; MT_OK=0
    else
      printf '  ok    %s\n' "터널 MTU를 넘는 패킷은 커널이 막는다 (1393바이트)"
    fi
    if grep -q "터널 MTU를 확인했습니다.*wg가 덧붙이는 크기 60바이트" "$WORK/a/csa.log"; then
      printf '  ok    %s\n' "csa가 바깥 인터페이스 MTU와 견준다"
    else
      printf '  틀림  %s\n' "바깥 MTU와 견주지 않는다"
      grep -i "MTU" "$WORK/a/csa.log" | sed 's/^/        /'; MT_OK=0
    fi

    # 경로에 advmss를 걸어 커널이 크게 알리게 만든다. 앱이 스스로 크기를 정하거나
    # 운영자가 경로에 값을 박아 둔 경우가 이렇다. csa가 그것을 깎아야 한다.
    before=$("$CSA" status -c "$WORK/a" -json | sed -n 's/.*"mss-clamped":\([0-9]*\).*/\1/p')
    ip netns exec "$NS_A" ip route change "$CIDR" dev "$WG_IF" advmss 1460
    ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$WG_B/8080" >/dev/null 2>&1 || true
    sleep 0.5
    after=$("$CSA" status -c "$WORK/a" -json | sed -n 's/.*"mss-clamped":\([0-9]*\).*/\1/p')
    if [ "${after:-0}" -gt "${before:-0}" ]; then
      printf '  ok    %s\n' "크게 알리는 MSS를 깎는다 (깎은 횟수 $before -> $after)"
    else
      printf '  틀림  %s\n' "깎지 않았다 (깎은 횟수 $before -> $after)"; MT_OK=0
    fi
    if grep -q "TCP 최대 세그먼트 크기를 깎았습니다.*1380바이트" "$WORK/a/csa.log"; then
      printf '  ok    %s\n' "처음 깎을 때 한 번 적는다"
    else
      printf '  틀림  %s\n' "깎았다고 적지 않는다"; MT_OK=0
    fi

    [ "$MT_OK" = 1 ] || { echo "--- a의 로그 ---"; tail -20 "$WORK/a/csa.log"; exit 1; }

    echo
    echo "== 오래 도는 동안"
    LG_OK=1
    peer_field() { # 설정디렉터리 peer-id 항목
      "$CSA" status -c "$1" -json 2>/dev/null | python3 -c "
import json, sys
st = json.load(sys.stdin)
for p in st['peers']:
    if p['peer-id'] == sys.argv[1]:
        print(p[sys.argv[2]])
        break
" "$2" "$3"
    }

    # 상태를 기억하는 방화벽이 UDP 흐름을 30초에 지우는 경우가 흔하다. wg가
    # 25초마다 keepalive를 보내 그 흐름을 살려 둔다. 실제로 나가는지 본다.
    before=$(peer_field "$WORK/a" srv-b tx-bytes)
    echo "  30초 동안 아무것도 보내지 않고 기다립니다."
    sleep 30
    after=$(peer_field "$WORK/a" srv-b tx-bytes)
    if [ "${after:-0}" -gt "${before:-0}" ]; then
      printf '  ok    %s\n' "쉬는 동안에도 keepalive가 나간다 ($((after-before))바이트)"
    else
      printf '  틀림  %s\n' "keepalive가 나가지 않는다 ($before -> $after)"; LG_OK=0
    fi
    if ip netns exec "$NS_A" ping -c 1 -W 1 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then
      printf '  ok    %s\n' "쉬고 나서도 세션이 그대로다"
    else
      printf '  틀림  %s\n' "쉬고 나서 세션이 끊겼다"; LG_OK=0
    fi

    # srv-a가 다른 자리로 옮겨 간다. peers.toml에 적힌 주소는 그대로 두므로,
    # 받는 쪽 csa는 관측으로만 새 자리를 안다.
    ip netns exec "$NS_A" ip addr del "$IP_A/24" dev eth0
    ip netns exec "$NS_A" ip addr add "$IP_A2/24" dev eth0
    sleep 0.5
    ip netns exec "$NS_A" ping -c 3 -W 2 -I "$WG_A" "$WG_B" >/dev/null 2>&1 || true
    sleep 1.5
    got=$(peer_field "$WORK/b" srv-a endpoint)
    if [ "$got" = "$IP_A2:$PORT" ]; then
      printf '  ok    %s\n' "자리를 옮기면 관측한 출발지가 따라간다 ($IP_A:$PORT -> $got)"
    else
      printf '  틀림  %s\n' "옛 자리를 그대로 들고 있다: ${got:-없음}"; LG_OK=0
    fi
    if grep -q "접속 주소가 바뀌었습니다.*상대 srv-a" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "csa가 자리가 바뀐 것을 적는다"
    else
      printf '  틀림  %s\n' "자리가 바뀐 것을 적지 않는다"; LG_OK=0
    fi
    if grep -q "등록된 접속 주소가 아닌 곳에서 패킷이 왔습니다.*$IP_A2" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "peers.toml에 없는 자리에서 온 것을 알아챈다"
    else
      printf '  틀림  %s\n' "peers.toml에 없는 자리에서 온 것을 알아채지 못한다"; LG_OK=0
    fi

    [ "$LG_OK" = 1 ] || { echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }

    echo
    echo "== 상대 csa가 죽었을 때"
    # srv-b의 csa를 멈추면 그쪽 직통 경로 표가 사라져 서비스 포트가 밖으로 열린다.
    # 그래도 srv-a의 앱이 실제 IP로 부른 연결은 srv-a의 표가 터널로 돌리므로 그
    # 열린 포트에 닿지 않는다. 인증 없이 통하는 대신 닫힌 채 실패한다.
    DD_OK=1
    kill "$PID_B" 2>/dev/null || true
    for _ in $(seq 25); do
      ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1 || break
      sleep 0.2
    done
    if ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1; then
      echo "  틀림  csa가 직통 경로 규칙을 남겼다"
      ip netns exec "$NS_B" nft list ruleset | sed 's/^/        /'; DD_OK=0
    else
      echo "  ok    csa가 멈추면서 직통 경로 규칙을 지웠다"
    fi
    if ip netns exec "$NS_B" nft list table ip callsignet-nat >/dev/null 2>&1; then
      echo "  틀림  csa가 주소 바꾸기 표를 남겼다"; DD_OK=0
    else
      echo "  ok    csa가 멈추면서 주소 바꾸기 표를 지웠다"
    fi
    ip netns exec "$NS_B" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8080))
s.listen(4)
while True:
    c, _ = s.accept()
    c.sendall(b'here\n')
    c.close()
" & DEAD_PID=$!
    sleep 1
    got=$(ip netns exec "$NS_A" timeout 3 bash -c "exec 3<>/dev/tcp/$IP_B/8080; head -1 <&3" 2>/dev/null || true)
    if [ -z "$got" ]; then
      echo "  ok    상대 csa가 죽어 있으면 실제 IP로 불러도 서지 않는다"
    else
      echo "  틀림  상대 csa가 죽어 있는데 실제 IP로 붙었다. 인증 없이 통했다"; DD_OK=0
    fi
    # csa 없는 머신은 그 열린 포트에 그대로 붙는다. 표가 그 길을 막고 있었다.
    if [ "$(knock_c "$IP_B" 8080)" = "here" ]; then
      echo "  ok    csa 없는 머신은 그 열린 포트에 직통으로 붙는다. 지키지 않는 동안에는 지켜지지 않는다"
    else
      echo "  틀림  상대 csa가 죽었는데 csa 없는 머신도 붙지 못한다"; DD_OK=0
    fi
    kill "$DEAD_PID" 2>/dev/null || true
    [ "$DD_OK" = 1 ] || { echo "--- a의 로그 ---"; tail -20 "$WORK/a/csa.log"; exit 1; }

    echo
    echo "== 되돌리기"
    kill "$PID_A" 2>/dev/null || true
    for _ in $(seq 20); do
      grep -q "주소 바꾸기 표를 지웠습니다" "$WORK/a/csa.log" && break
      sleep 0.2
    done
    if [ "$(cat "/etc/netns/$NS_A/resolv.conf")" = "nameserver $UPSTREAM" ]; then
      echo "  ok    csa가 멈춘 뒤에도 /etc/resolv.conf는 그대로다"
    else
      echo "  틀림  csa가 /etc/resolv.conf를 고쳤다"
      cat "/etc/netns/$NS_A/resolv.conf"; exit 1
    fi
    if "$CSA" status -c "$WORK/a" >/dev/null 2>&1; then
      echo "  틀림  멈춘 csa에 붙었다고 한다"; exit 1
    else
      echo "  ok    멈춘 뒤에는 csa status가 붙지 못한다고 알린다"
    fi
    if ip netns exec "$NS_A" nft list table ip callsignet-nat >/dev/null 2>&1; then
      echo "  틀림  csa가 주소 바꾸기 표를 남겼다"; exit 1
    else
      echo "  ok    csa가 멈추면서 주소 바꾸기 표를 지웠다"
    fi

    echo
    echo "== 예외 말고 모두 닫는 모드"
    # 앞 절에서 csa 둘을 멈췄다. srv-b의 csa를 다른 모드로 다시 띄운다.
    # 이 모드는 csa.toml에서 정하므로 csa reload로는 바꿀 수 없다.
    OD_OK=1
    cat >> "$WORK/b/csa.toml" <<TOML

[guard]
mode     = "all"
keep-tcp = [9999]
TOML
    ip netns exec "$NS_B" env CSA_DEBUG="$CSA_DEBUG" "$CSA" run -c "$WORK/b" \
      > "$WORK/b/csa2.log" 2>&1 & PID_B2=$!
    for _ in $(seq 20); do
      grep -q "직통 경로를 닫았습니다" "$WORK/b/csa2.log" && break
      sleep 0.3
    done

    # 세 포트에 모두 듣게 해 둔다. 앱을 고치지 않고도 갈리는지 보려는 것이다.
    ip netns exec "$NS_B" python3 -c "
import socket, threading

def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(8)
    while True:
        c, _ = s.accept()
        c.sendall(b'here\n')
        c.close()

for p in (8080, 7777):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
serve(9999)
" & OD_PID=$!
    sleep 1

    if [ -z "$(knock_c "$IP_B" 8080)" ]; then
      printf '  ok    %s\n' "서비스 포트를 막는다"
    else
      printf '  틀림  %s\n' "서비스 포트가 열려 있다"; OD_OK=0
    fi
    if [ -z "$(knock_c "$IP_B" 7777)" ]; then
      printf '  ok    %s\n' "예외에 없는 포트도 막는다"
    else
      printf '  틀림  %s\n' "예외에 없는 포트가 열려 있다"; OD_OK=0
    fi
    if [ "$(knock_c "$IP_B" 9999)" = "here" ]; then
      printf '  ok    %s\n' "예외로 적은 포트는 연다"
    else
      printf '  틀림  %s\n' "예외로 적은 포트가 막혔다"; OD_OK=0
    fi
    if ip netns exec "$NS_C" ping -c 1 -W 2 "$IP_B" >/dev/null 2>&1; then
      printf '  ok    %s\n' "ICMP는 연다"
    else
      printf '  틀림  %s\n' "ICMP까지 막았다. 경로 MTU 발견이 되지 않는다"; OD_OK=0
    fi
    kill "$OD_PID" 2>/dev/null || true
    kill "$PID_B2" 2>/dev/null || true
    sleep 1
    if ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1; then
      printf '  틀림  %s\n' "멈추면서 nftables 규칙을 남겼다"; OD_OK=0
    else
      printf '  ok    %s\n' "멈추면서 nftables 규칙을 지웠다"
    fi


    [ "$OD_OK" = 1 ] || { echo "--- b의 규칙 ---"; ip netns exec "$NS_B" nft list ruleset 2>&1 | sed 's/^/        /'
                          echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa2.log"; exit 1; }

    echo
    echo "== 사전 공유키가 다를 때"
    # 지금까지의 검사는 모두 사전 공유키를 쓴 채로 돌았다. 여기서는 한쪽 키만
    # 바꾸어 세션이 서지 않는 것을 본다. 키가 실제로 handshake에 섞이지 않으면
    # 달라도 세션이 서므로, 이 검사가 없으면 위의 통과가 아무것도 증명하지 못한다.
    PSK_OK=1
    "$CSA" genpsk -f -o "$WORK/b/psk/srv-a.key" >/dev/null
    ip netns exec "$NS_A" env CSA_DEBUG= "$CSA" run -c "$WORK/a" > "$WORK/a/csa3.log" 2>&1 & PID_A3=$!
    ip netns exec "$NS_B" env CSA_DEBUG= "$CSA" run -c "$WORK/b" > "$WORK/b/csa3.log" 2>&1 & PID_B3=$!
    sleep 3
    OK=0
    for _ in $(seq 15); do
      if ip netns exec "$NS_A" ping -c 1 -W 1 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then OK=1; break; fi
    done
    if [ "$OK" = 0 ]; then
      printf '  ok    %s\n' "키가 다르면 세션이 서지 않는다"
    else
      printf '  틀림  %s\n' "키가 다른데 세션이 섰다. 키가 handshake에 섞이지 않는다"; PSK_OK=0
    fi
    kill "$PID_A3" "$PID_B3" 2>/dev/null || true
    sleep 1

    # 키를 맞추면 다시 선다. 앞의 실패가 키 때문이지 다른 까닭이 아님을 보인다.
    cp "$WORK/a/psk/srv-b.key" "$WORK/b/psk/srv-a.key"
    ip netns exec "$NS_A" env CSA_DEBUG= "$CSA" run -c "$WORK/a" > "$WORK/a/csa4.log" 2>&1 & PID_A4=$!
    ip netns exec "$NS_B" env CSA_DEBUG= "$CSA" run -c "$WORK/b" > "$WORK/b/csa4.log" 2>&1 & PID_B4=$!
    sleep 3
    OK=0
    for _ in $(seq 45); do
      if ip netns exec "$NS_A" ping -c 1 -W 1 -I "$WG_A" "$WG_B" >/dev/null 2>&1; then OK=1; break; fi
    done
    if [ "$OK" = 1 ]; then
      printf '  ok    %s\n' "키를 맞추면 다시 선다"
    else
      printf '  틀림  %s\n' "키를 맞췄는데 서지 않는다"; PSK_OK=0
    fi
    kill "$PID_A4" "$PID_B4" 2>/dev/null || true
    sleep 1

    # 반드시 있어야 한다고 해 놓고 없으면 뜨지 않는다.
    mv "$WORK/b/psk/srv-a.key" "$WORK/b/psk/srv-a.key.away"
    if "$CSA" check -c "$WORK/b" >/dev/null 2>&1; then
      printf '  틀림  %s\n' "required인데 키가 없는 설정을 받아들였다"; PSK_OK=0
    else
      printf '  ok    %s\n' "required인데 키가 없으면 기동하지 않는다"
    fi
    mv "$WORK/b/psk/srv-a.key.away" "$WORK/b/psk/srv-a.key"

    [ "$PSK_OK" = 1 ] || { echo "--- a의 로그 ---"; tail -15 "$WORK/a/csa3.log"; exit 1; }

  else
    echo "실제 IP로는 통하지 않습니다."; exit 1
  fi
else
  echo
  echo "실패했습니다."
  echo "--- a의 경로 ---"; ip netns exec "$NS_A" ip -4 route
  echo "--- b의 경로 ---"; ip netns exec "$NS_B" ip -4 route
  echo "--- a의 로그 ---"; tail -30 "$WORK/a/csa.log"
  echo "--- b의 로그 ---"; tail -30 "$WORK/b/csa.log"
  exit 1
fi
