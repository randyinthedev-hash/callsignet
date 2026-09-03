#!/usr/bin/env bash
# 허용 목록에 없는 출발지 IP로 보낸 패킷을 받는 쪽이 버리는지 확인한다.
#
# 커널 wg는 복호화한 패킷의 출발지 IP가 그 상대의 AllowedIPs 안에 없으면 버리면서
# rx_errors와 rx_dropped를 올린다. rx_packets는 올라가지 않는다. 이 차이가 「받는 쪽
# 데이터플레인이 상대를 확정한다」의 근거가 된다.
source "$(dirname "$0")/common.sh"
need_root "$@"

ip netns list | grep -q "$NS_CLI" || { echo "먼저 setup.sh 를 돌리세요." >&2; exit 1; }
mkdir -p "$RESULTS"
TS=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$RESULTS/cryptokey-$TS.md"

stat() { nsx "$NS_SRV" cat "/sys/class/net/wg0/statistics/$1"; }

P0=$(stat rx_packets); E0=$(stat rx_errors); D0=$(stat rx_dropped)

echo "== 1. 허용된 출발지 $WG_CLI 로 보낸다"
nsx "$NS_CLI" ping -c 3 -W 1 -I "$WG_CLI" "$WG_SRV" >/dev/null 2>&1 && OK1=성공 || OK1=실패
P1=$(stat rx_packets); E1=$(stat rx_errors); D1=$(stat rx_dropped)

echo "== 2. 허용 목록에 없는 출발지 $WG_SPOOF 로 보낸다"
nsx "$NS_CLI" ip addr add "$WG_SPOOF/32" dev wg0
nsx "$NS_CLI" ping -c 3 -W 1 -I "$WG_SPOOF" "$WG_SRV" >/dev/null 2>&1 && OK2=성공 || OK2=실패
P2=$(stat rx_packets); E2=$(stat rx_errors); D2=$(stat rx_dropped)
nsx "$NS_CLI" ip addr del "$WG_SPOOF/32" dev wg0

PASS=0
[ "$OK1" = 성공 ] && [ "$OK2" = 실패 ] && [ "$((P2-P1))" -eq 0 ] && [ "$((E2-E1))" -gt 0 ] && PASS=1

{
  echo "# cryptokey routing 확인 ($TS)"
  echo
  echo "| 출발지 | ping | rx_packets | rx_errors | rx_dropped |"
  echo "|---|---|---|---|---|"
  printf '| %s (허용) | %s | +%d | +%d | +%d |\n' "$WG_CLI" "$OK1" "$((P1-P0))" "$((E1-E0))" "$((D1-D0))"
  printf '| %s (허용 밖) | %s | +%d | +%d | +%d |\n' "$WG_SPOOF" "$OK2" "$((P2-P1))" "$((E2-E1))" "$((D2-D1))"
  echo
  if [ $PASS -eq 1 ]; then
    echo "확인됨. 허용 목록 밖의 출발지로 온 패킷을 받는 쪽이 복호화한 뒤에 버린다."
    echo "상대의 정적 공개키로 인증된 세션이라도 배정된 터널 IP만 출발지로 쓸 수 있다."
  else
    echo "예상과 다르다. wg 설정을 확인한다."
  fi
} > "$REPORT"

echo
cat "$REPORT"
echo
echo "기록: ${REPORT#$REPO/}"
