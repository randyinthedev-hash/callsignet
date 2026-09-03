#!/usr/bin/env bash
# 네임스페이스 둘을 만들고 wg로 잇는다.
#
# 받는 쪽은 보내는 쪽 항목에 허용 IP를 10.91.0.1 하나만 적는다. 보내는 쪽이 그 밖의
# 주소를 출발지로 쓰면 받는 쪽이 복호화한 뒤에 버린다. 그것을 재는 구성이다.
source "$(dirname "$0")/common.sh"
need_root "$@"

"$HERE/teardown.sh" >/dev/null 2>&1 || true
mkdir -p "$WORK"; chmod 700 "$WORK"

echo "== 키 생성"
for who in cli srv; do
  if [ ! -f "$WORK/$who.key" ]; then
    (umask 077; wg genkey > "$WORK/$who.key")
    wg pubkey < "$WORK/$who.key" > "$WORK/$who.pub"
  fi
done
CLI_PUB=$(cat "$WORK/cli.pub"); SRV_PUB=$(cat "$WORK/srv.pub")

echo "== 언더레이"
ip link add "$BR" type bridge
ip link set "$BR" up
attach() { # ns addr
  local ns=$1 addr=$2 host="v-$1"
  ip netns add "$ns"
  ip link add "$host" type veth peer name eth0 netns "$ns"
  ip link set "$host" master "$BR" up
  nsx "$ns" ip link set lo up
  nsx "$ns" ip link set eth0 up
  nsx "$ns" ip addr add "$addr/$PREFIX" dev eth0
}
attach "$NS_CLI" "$IP_CLI"
attach "$NS_SRV" "$IP_SRV"

echo "== wg"
nsx "$NS_SRV" ip link add wg0 type wireguard
nsx "$NS_SRV" wg set wg0 listen-port "$WG_PORT" private-key "$WORK/srv.key"
nsx "$NS_SRV" wg set wg0 peer "$CLI_PUB" allowed-ips "$WG_CLI/32"
nsx "$NS_SRV" ip addr add "$WG_SRV/$WG_PREFIX" dev wg0
nsx "$NS_SRV" ip link set wg0 up

nsx "$NS_CLI" ip link add wg0 type wireguard
nsx "$NS_CLI" wg set wg0 private-key "$WORK/cli.key"
nsx "$NS_CLI" wg set wg0 peer "$SRV_PUB" endpoint "$IP_SRV:$WG_PORT" allowed-ips "$WG_SRV/32"
nsx "$NS_CLI" ip addr add "$WG_CLI/$WG_PREFIX" dev wg0
nsx "$NS_CLI" ip link set wg0 up

echo
echo "구성 완료. 다음: sudo $HERE/check.sh"
