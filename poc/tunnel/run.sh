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
  rm -rf "/etc/netns/$NS_A" "/etc/netns/$NS_B"
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
    [ "$NAME_OK" = 1 ] || { echo "다만 이름 해석에 틀린 것이 있습니다."; exit 1; }

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
    if [ "$n" -le 3 ]; then printf '  ok    %s\n' "연결마다 한 번만 적는다 ($n줄)"
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
