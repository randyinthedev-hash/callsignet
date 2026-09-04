#!/usr/bin/env bash
# csa 둘이 터널을 세우고 터널 IP로 통신하는지 확인한다.
#
# 네임스페이스 둘을 만들어 브리지로 잇고, 각 네임스페이스에서 csa를 띄운 뒤
# 한쪽 터널 IP에서 다른 쪽 터널 IP로 ping을 보낸다.
set -euo pipefail

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

# 상위 리졸버만 적어 둔다. csa가 이 파일을 가져가 자기를 첫 줄에 넣어야 한다.
# ip netns exec는 /etc/netns/<이름>/resolv.conf가 있으면 그것을 /etc/resolv.conf
# 자리에 붙여 준다. 심볼릭 링크가 아니므로 csa는 파일 갈래로 판별한다.
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
echo "언더레이 확인"

echo "== 키와 설정"
PUB_A=$("$CSA" genkey -o "$WORK/a/private.key" | sed -n 's/^공개키: //p')
PUB_B=$("$CSA" genkey -o "$WORK/b/private.key" | sed -n 's/^공개키: //p')
PUB_C=$("$CSA" genkey -o "$WORK/c-unused.key" | sed -n 's/^공개키: //p')

# 두 머신에 서로 다른 앱을 둔다. 이름 해석이 앱마다 다른 답을 내는지 보려는 것이다.
APP_A=billing
APP_B=report
# srv-b에만 있는 앱이다. srv-a는 나가도 되지만 srv-b는 들이지 않는다. 받는 쪽이
# 최종 판단 주체임을 확인하려고 정책을 일부러 어긋나게 둔다.
APP_SECRET=secret
PORT_SECRET=7070
# 설정에는 있으나 정책에 없는 상대다. 이름은 풀리지만 통신은 막혀야 한다.
WG_C=10.91.0.3

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
endpoints  = ["10.90.0.99:$PORT"]
services   = [{ app = "idle", port = 8080 }]
TOML
}
side() { # dir peer-id 상대 내앱 상대앱
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
$6

[[inbound]]
app   = "$4"
allow = ["$3"]
TOML
}
# srv-a는 srv-b의 report와 secret에 나가도 된다. 그런데 srv-b는 report만 들인다.
side a srv-a srv-b "$APP_A" "$APP_B" "outbound = [\"srv-b/$APP_B\", \"srv-b/$APP_SECRET\"]"
side b srv-b srv-a "$APP_B" "$APP_A" "outbound = [\"srv-a/$APP_A\"]"

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
echo "== $WG_A 에서 $WG_B 로 ping"
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
  echo "== 리졸버 자리 차지하기"
  TAKE_OK=1
  if grep -q "^nameserver 127.0.0.54" "/etc/netns/$NS_A/resolv.conf"; then
    printf '  ok    %s\n' "csa가 자기를 첫 줄에 넣었다"
  else
    printf '  틀림  %s\n' "csa가 파일을 가져가지 않았다"; TAKE_OK=0
  fi
  if grep -q "^nameserver $UPSTREAM" "/etc/netns/$NS_A/resolv.conf"; then
    printf '  ok    %s\n' "원래 리졸버를 남겼다"
  else
    printf '  틀림  %s\n' "원래 리졸버를 잃었다"; TAKE_OK=0
  fi
  if grep -q "이름 해석을 확인했습니다" "$WORK/a/csa.log"; then
    printf '  ok    %s\n' "csa가 스스로 확인했다"
  else
    printf '  틀림  %s\n' "csa가 확인하지 못했다"; TAKE_OK=0
  fi
  [ "$TAKE_OK" = 1 ] || { grep -i "이름 해석" "$WORK/a/csa.log" || true; exit 1; }

  echo
  echo "== 이름 해석"
  NAME_OK=1
  check_dig() { # 질의 기대값 설명
    got=$(ip netns exec "$NS_A" dig @127.0.0.54 +short +time=2 +tries=1 $1 2>/dev/null | head -1)
    if [ "$got" = "$2" ]; then
      printf '  ok    %-46s -> %s\n' "$3" "$got"
    else
      printf '  틀림  %-46s -> %s (기대 %s)\n' "$3" "${got:-없음}" "$2"; NAME_OK=0
    fi
  }
  check_dig "$APP_B.srv-b.cs.test.internal A" "$WG_B"                    "서비스 이름"
  check_dig "srv-b.cs.test.internal A"        "$WG_B"                    "머신 이름"
  check_dig "-x $WG_B"                        "srv-b.cs.test.internal."  "역방향"

  check_dig "$APP_A.srv-a.cs.test.internal A" "$WG_A"                    "자기 서비스 이름"

  rc=$(ip netns exec "$NS_A" dig @127.0.0.54 +time=2 +tries=1 "$APP_A.srv-b.cs.test.internal" A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  if [ "$rc" = NXDOMAIN ]; then printf '  ok    %-46s -> NXDOMAIN\n' "다른 머신의 앱 이름"
  else printf '  틀림  %-46s -> %s\n' "다른 머신의 앱 이름" "${rc:-없음}"; NAME_OK=0; fi

  rc=$(ip netns exec "$NS_A" dig @127.0.0.54 +time=2 +tries=1 srv-z.cs.test.internal A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  if [ "$rc" = NXDOMAIN ]; then printf '  ok    %-46s -> NXDOMAIN\n' "설정에 없는 이름"
  else printf '  틀림  %-46s -> %s\n' "설정에 없는 이름" "${rc:-없음}"; NAME_OK=0; fi

  rc=$(ip netns exec "$NS_A" dig @127.0.0.54 +time=2 +tries=1 www.example.com A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  if [ "$rc" = REFUSED ]; then printf '  ok    %-46s -> REFUSED\n' "우리 도메인이 아닌 이름"
  else printf '  틀림  %-46s -> %s\n' "우리 도메인이 아닌 이름" "${rc:-없음}"; NAME_OK=0; fi

  echo
  echo "== 이름으로 ping"
  if ip netns exec "$NS_A" ping -c 2 -W 2 "$APP_B.srv-b.cs.test.internal"; then
    echo
    echo "확인됨. 앱이 이름으로 부르고 csa 둘이 터널로 나른다."

    echo
    echo "== TCP 연결"
    # ping은 ICMP라서 peer 단위로만 판단한다. TCP는 다르다. 서버가 돌려주는
    # 패킷의 목적지는 부른 쪽 앱의 임시 포트인데, 그 포트는 어느 정책에도 적혀
    # 있지 않다. csa가 들인 연결을 기억하지 않으면 손잡기부터 서지 않는다.
    TCP_OK=1
    ip netns exec "$NS_B" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$WG_B', 8080))
s.listen(1)
c, _ = s.accept()
c.sendall(b'pong:' + c.recv(64))
c.close()
" & LISTEN_PID=$!
    sleep 1
    got=$(ip netns exec "$NS_A" timeout 5 bash -c \
      "exec 3<>/dev/tcp/$APP_B.srv-b.cs.test.internal/8080; printf 'ping\n' >&3; head -1 <&3" 2>/dev/null || true)
    kill "$LISTEN_PID" 2>/dev/null || true
    if [ "$got" = "pong:ping" ]; then
      printf '  ok    %s\n' "이름으로 TCP를 맺고 양쪽으로 자료가 오간다"
    else
      printf '  틀림  %s\n' "TCP가 서지 않는다. 받은 것: ${got:-없음}"; TCP_OK=0
    fi
    if grep -q "나가는 연결을 막았습니다" "$WORK/b/csa.log"; then
      printf '  틀림  %s\n' "받는 쪽이 자기 답을 막았다"
      grep "나가는 연결을 막았습니다" "$WORK/b/csa.log" | tail -3 | sed 's/^/        /'; TCP_OK=0
    else
      printf '  ok    %s\n' "받는 쪽이 자기 답을 막지 않는다"
    fi
    [ "$TCP_OK" = 1 ] || { echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }

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
        "exec 3<>/dev/tcp/$APP_B.srv-b.cs.test.internal/8080; head -1 <&3" 2>/dev/null || true)" = "here" ]; then
      printf '  ok    %s\n' "터널로 오는 연결은 그대로 지난다"
    else
      printf '  틀림  %s\n' "터널로 오는 연결까지 막았다"; DP_OK=0
    fi
    if ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1; then
      printf '  ok    %s\n' "csa가 자기 표를 만들었다"
    else
      printf '  틀림  %s\n' "표가 없다"; DP_OK=0
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
    [ "$NAME_OK" = 1 ] || { echo "다만 이름 해석에 틀린 것이 있습니다."; exit 1; }


    echo
    echo "== 거절 응답"
    # csa가 나가는 연결을 막을 때 앱에게 ICMP로 알린다. 앱이 연결 시간을 다
    # 기다리지 않고 곧바로 실패를 보아야 한다. 조용히 버리면 그것을 확인할 수 없다.
    if ! ip netns exec "$NS_A" python3 - "$WG_B" "$WG_C" <<'PYREJECT'
import errno
import socket
import sys
import time

wg_b, wg_c = sys.argv[1], sys.argv[2]
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
      "거절이 앱에게 닿지 않았다: %s" % why)
check(took < 1.0,
      "기다리지 않고 실패한다 (%.2f초)" % took,
      "연결 시간을 다 기다렸다 (%.2f초)" % took)

# 같은 상대인데 정책에 없는 포트다.
why, took = dial(wg_b, 9090)
check(why == "EHOSTUNREACH",
      "정책에 없는 포트에 붙으면 곧바로 실패한다",
      "거절이 앱에게 닿지 않았다: %s" % why)

# 허가된 곳이다. 듣는 앱이 없으므로 상대 커널이 거절한다. csa의 거절과 달라야
# 한다. 같으면 무엇 때문에 실패했는지 앱이 가릴 수 없다.
why, took = dial(wg_b, 8080)
check(why in ("ECONNREFUSED", "연결됨"),
      "허가된 곳은 상대가 답한다 (%s)" % why,
      "허가된 곳인데 csa가 막았다: %s" % why)

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
    echo "확인됨. 받는 쪽이 최종 판단을 한다."

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

c = peers.get("srv-c", {})
check(c.get("handshake", "").startswith("0001"),
      "세션을 맺지 않은 상대는 시각이 비어 있다",
      "시각이 있다: %s" % c.get("handshake"))
check(not c.get("endpoint"),
      "세션을 맺지 않은 상대는 출발지가 비어 있다",
      "관측하지 않은 주소를 보여 준다: %s" % c.get("endpoint"))

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
      printf '  틀림  %s\n' "여전히 막는다"; RL_OK=0
    fi

    # 상대를 더하면 이름 표도 함께 바뀐다.
    PUB_D=$("$CSA" genkey -o "$WORK/d-unused.key" | sed -n 's/^공개키: //p')
    printf '\n[[peer]]\npeer-id    = "srv-d"\npublic-key = "%s"\ntunnel-ip  = "10.91.0.4"\nendpoints  = ["10.90.0.98:%s"]\nservices   = [{ app = "ledger", port = 8080 }]\n' \
      "$PUB_D" "$PORT" >> "$WORK/a/peers.toml"
    out=$("$CSA" reload -c "$WORK/a" 2>&1 || true)
    if printf '%s' "$out" | grep -q "더한 상대: srv-d"; then
      printf '  ok    %s\n' "상대를 더하면 더했다고 알린다"
    else
      printf '  틀림  %s\n' "더한 상대를 알리지 않는다"; printf '%s\n' "$out" | sed 's/^/        /'; RL_OK=0
    fi
    got=$(ip netns exec "$NS_A" dig @127.0.0.54 +short +time=2 +tries=1 ledger.srv-d.cs.test.internal A 2>/dev/null | head -1)
    if [ "$got" = "10.91.0.4" ]; then
      printf '  ok    %s\n' "더한 상대의 이름이 바로 풀린다"
    else
      printf '  틀림  %s\n' "이름이 풀리지 않는다: ${got:-없음}"; RL_OK=0
    fi

    [ "$RL_OK" = 1 ] || exit 1

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
      printf '  ok    %s\n' "막힌 연결은 앱에게 가지 않는다"
    else
      printf '  틀림  %s\n' "막았다면서 앱에게 넘겼다"; BD_OK=0
    fi
    if grep -q "허용 대역 밖에서 왔다.*관측한 출발지 $IP_A" "$WORK/b/csa.log"; then
      printf '  ok    %s\n' "까닭에 관측한 출발지가 남는다"
    else
      printf '  틀림  %s\n' "관측한 출발지를 적지 않는다"
      grep "허용 대역" "$WORK/b/csa.log" | tail -3 | sed 's/^/        /'; BD_OK=0
    fi

    # 대역을 보는 규칙이 없는 앱은 그대로 지난다.
    before=$(count_b "들어온 연결을 받았습니다.*:8080")
    ip netns exec "$NS_A" timeout 3 bash -c "echo > /dev/tcp/$WG_B/8080" >/dev/null 2>&1 || true
    sleep 0.5
    if [ "$(count_b "들어온 연결을 받았습니다.*:8080")" -gt "$before" ]; then
      printf '  ok    %s\n' "대역을 보지 않는 앱은 그대로 지난다"
    else
      printf '  틀림  %s\n' "대역과 상관없는 앱까지 막는다"; BD_OK=0
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
      printf '  ok    %s\n' "크게 알리는 MSS를 깎는다 ($before -> $after)"
    else
      printf '  틀림  %s\n' "깎지 않았다 ($before -> $after)"; MT_OK=0
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
      printf '  ok    %s\n' "자리를 옮기면 관측한 출발지가 따라간다 ($IP_A -> $got)"
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
      printf '  틀림  %s\n' "낯선 자리를 알아채지 못한다"; LG_OK=0
    fi

    [ "$LG_OK" = 1 ] || { echo "--- b의 로그 ---"; tail -20 "$WORK/b/csa.log"; exit 1; }

    echo
    echo "== 되돌리기"
    kill "$PID_A" 2>/dev/null || true
    for _ in $(seq 20); do
      grep -q "되돌렸습니다" "$WORK/a/csa.log" && break
      sleep 0.2
    done
    if grep -q "^nameserver $UPSTREAM" "/etc/netns/$NS_A/resolv.conf" &&
       ! grep -q "^nameserver 127.0.0.54" "/etc/netns/$NS_A/resolv.conf"; then
      echo "  ok    csa가 멈추면서 원래 파일로 되돌렸다"
    else
      echo "  틀림  되돌리지 않았다"
      cat "/etc/netns/$NS_A/resolv.conf"; exit 1
    fi
    if "$CSA" status -c "$WORK/a" >/dev/null 2>&1; then
      echo "  틀림  멈춘 csa에 붙었다고 한다"; exit 1
    else
      echo "  ok    멈춘 뒤에는 csa status가 붙지 못한다고 알린다"
    fi
    kill "$PID_B" 2>/dev/null || true
    sleep 1
    if ip netns exec "$NS_B" nft list table inet callsignet >/dev/null 2>&1; then
      echo "  틀림  csa가 직통 경로 규칙을 남겼다"
      ip netns exec "$NS_B" nft list ruleset | sed 's/^/        /'; exit 1
    else
      echo "  ok    csa가 멈추면서 직통 경로 규칙을 지웠다"
    fi
  else
    echo "이름으로는 통하지 않습니다."; exit 1
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
