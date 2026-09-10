# 공통 정의. 각 스크립트에서 source 한다.
set -euo pipefail

NS_CLI=cs-cli
NS_SRV=cs-srv
ALL_NS="$NS_CLI $NS_SRV"
BR=cs-br0

# 언더레이. 두 네임스페이스가 같은 브리지에 붙는다.
NET=10.90.0
IP_CLI=$NET.10
IP_SRV=$NET.30
PREFIX=24

# 터널. 받는 쪽은 보내는 쪽에 10.91.0.1만 허용한다.
WG_PORT=51820
WG_CLI=10.91.0.1
WG_SRV=10.91.0.2
WG_PREFIX=24

# 허용 목록에 없는 출발지. 이 주소로 보낸 패킷을 받는 쪽이 버리는지 본다.
WG_SPOOF=10.91.0.9

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$HERE/_work"
RESULTS="$REPO/results"

# own은 root로 만든 파일을 부른 사람에게 넘긴다. 실험은 root로 도는데 기록은
# 리포에 남으므로, 그대로 두면 부른 사람이 그 파일을 지우지도 고치지도 못한다.
# git이 그 파일을 덮어쓰지 못해 pull이 막히는 일도 생긴다.
own() { # 파일이나 디렉터리
  [ -n "${SUDO_UID:-}" ] || return 0
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null || true
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "이 스크립트는 root가 필요합니다: sudo $0 $*" >&2
    exit 1
  fi
}

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
