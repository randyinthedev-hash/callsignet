#!/usr/bin/env bash
# 준비물을 점검한다. root 권한은 필요 없다.
source "$(dirname "$0")/common.sh"
ok=0
chk() { if "$@" >/dev/null 2>&1; then printf '  ok    %s\n' "$*"; else printf '  없음  %s\n' "$*"; ok=1; fi; }
echo "명령"; chk command -v ip; chk command -v wg; chk command -v ping
echo "커널"
if modinfo wireguard >/dev/null 2>&1 || [ -d /sys/module/wireguard ]; then echo "  ok    wireguard 모듈"; else echo "  없음  wireguard 모듈"; ok=1; fi
echo "권한"
if [ "$(id -u)" -eq 0 ]; then echo "  ok    root"; else echo "  참고  setup·check·teardown 은 sudo 로 실행해야 합니다"; fi
if [ $ok -ne 0 ]; then
  echo; echo "빠진 것이 있습니다. Ubuntu라면:"; echo "  sudo apt update && sudo apt install -y wireguard-tools iproute2 iputils-ping"
  exit 1
fi
echo; echo "준비 완료."
