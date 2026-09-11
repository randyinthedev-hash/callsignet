#!/usr/bin/env bash
# csa를 설치하고, 올리고, 되돌린다.
#
# 이 스크립트는 설치 묶음 안에 들어 있다. 묶음을 푼 자리에서 부른다. 묶음에는
# csa 실행 파일과 csa.service와 이 스크립트와 라이선스가 있다.
#
# 판마다 자기 디렉터리에 두고 심볼릭 링크 하나로 어느 판이 도는지 정한다.
#
#   /opt/callsignet/versions/<판>/   묶음을 푼 그대로
#   /opt/callsignet/current          지금 도는 판을 가리키는 링크
#   /opt/callsignet/previous         바로 앞 판을 가리키는 링크. 되돌릴 때 쓴다
#   /usr/local/bin/csa               current/csa를 가리키는 링크
#   /etc/systemd/system/csa.service  current/csa.service의 사본
#   /etc/callsignet/                 설정. 이 스크립트는 만들기만 하고 채우지 않는다
#
# 올릴 때는 새 판의 csa로 지금 설정을 먼저 검사한다. 지나면 링크를 옮기고 다시
# 띄운 뒤 csa가 답하는지 본다. 답하지 않으면 스스로 앞 판으로 되돌린다.
set -euo pipefail

ROOT=/opt/callsignet
VERSIONS=$ROOT/versions
CURRENT=$ROOT/current
PREVIOUS=$ROOT/previous
BIN=/usr/local/bin/csa
UNIT=/etc/systemd/system/csa.service
CONF=/etc/callsignet
SERVICE=csa

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
사용법: $0 <명령>

  install    처음 설치한다. 설정은 만들지 않는다
  upgrade    이 묶음의 판으로 올린다. 먼저 검사하고, 다시 띄운 뒤 답하지 않으면 되돌린다
  rollback   바로 앞 판으로 되돌린다
  status     어느 판이 돌고 어느 판으로 되돌릴 수 있는지 보여 준다
EOF
}

die() { echo "오류: $*" >&2; exit 1; }
say() { echo "$*"; }

need_root() { [ "$(id -u)" -eq 0 ] || die "root가 필요합니다: sudo $0 $*"; }

# 이 묶음의 판이다. 실행 파일이 말하는 값을 쓴다. 파일 이름이나 디렉터리 이름을
# 믿지 않는다.
bundle_version() {
  [ -x "$HERE/csa" ] || die "이 자리에 csa가 없습니다: $HERE"
  "$HERE/csa" version
}

# 링크가 가리키는 판이다. 링크가 없으면 빈 값이다.
linked_version() { # 링크
  [ -L "$1" ] || { echo ""; return; }
  basename "$(readlink -f "$1")"
}

active() { systemctl is-active --quiet "$SERVICE"; }

# 판 디렉터리를 만든다. 묶음을 푼 그대로 옮긴다.
place() { # 판
  local dir="$VERSIONS/$1"
  if [ -e "$dir" ]; then
    die "그 판이 이미 있습니다: $dir. 다른 판을 올리거나 그 디렉터리를 치우십시오"
  fi
  install -d -m 755 "$VERSIONS"
  mkdir -p "$dir.tmp"
  cp -a "$HERE/." "$dir.tmp/"
  chmod 0755 "$dir.tmp/csa"
  mv "$dir.tmp" "$dir"
  say "판을 두었습니다: $dir"
}

# 링크를 바꾼다. 옆에 만들어 한 번에 옮기므로 링크가 없는 순간이 없다.
point() { # 링크 대상
  ln -sfn "$2" "$1.tmp"
  mv -T "$1.tmp" "$1"
}

# 서비스 파일을 지금 판의 것으로 맞춘다.
place_unit() {
  install -m 644 "$CURRENT/csa.service" "$UNIT"
  systemctl daemon-reload
}

# 다시 띄운 csa가 답하는지 본다. csa status는 도는 csa의 소켓에 붙는다.
# 15초 안에 답하지 않으면 실패로 본다.
answers() {
  local i
  for i in $(seq 1 15); do
    if "$CURRENT/csa" status -c "$CONF" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

do_install() {
  need_root install
  [ -L "$CURRENT" ] && die "이미 설치되어 있습니다. 올리려면 $0 upgrade"
  local ver
  ver=$(bundle_version)
  place "$ver"
  point "$CURRENT" "$VERSIONS/$ver"
  install -d -m 755 "$(dirname "$BIN")"
  point "$BIN" "$CURRENT/csa"
  install -d -m 750 "$CONF"
  place_unit
  systemctl enable "$SERVICE" >/dev/null
  say "설치했습니다. 판 $ver"
  say "다음 할 일:"
  say "  1. $CONF 에 csa.toml과 peers.toml과 policy.toml을 둔다. 자세한 것은 INSTALL.md"
  say "  2. csa check -c $CONF 로 검사한다"
  say "  3. systemctl start $SERVICE"
}

do_upgrade() {
  need_root upgrade
  [ -L "$CURRENT" ] || die "설치되어 있지 않습니다. 처음이면 $0 install"
  local new old
  new=$(bundle_version)
  old=$(linked_version "$CURRENT")
  [ "$new" != "$old" ] || die "지금 도는 판과 같습니다: $old"
  place "$new"

  # 새 판의 csa로 지금 설정을 먼저 본다. 설정 파일의 모양이 판마다 달라질 수
  # 있다. 여기서 걸리면 아무것도 바꾸지 않는다.
  if [ -f "$CONF/csa.toml" ]; then
    if ! "$VERSIONS/$new/csa" check -c "$CONF"; then
      die "새 판 $new 이(가) 지금 설정을 받지 않습니다. 아무것도 바꾸지 않았습니다. 설정을 고치거나 판을 다시 고르십시오"
    fi
    say "새 판 $new 이(가) 지금 설정을 받습니다."
  else
    say "설정이 아직 없어 검사를 건너뜁니다."
  fi

  point "$PREVIOUS" "$VERSIONS/$old"
  point "$CURRENT" "$VERSIONS/$new"
  place_unit
  say "링크를 옮겼습니다. $old → $new"

  if ! active; then
    say "서비스가 돌고 있지 않아 다시 띄우지 않습니다. 올렸습니다. 판 $new"
    return
  fi
  systemctl restart "$SERVICE"
  if answers; then
    say "다시 띄웠고 csa가 답합니다. 올렸습니다. 판 $new"
    return
  fi
  # 답하지 않으면 스스로 되돌린다. 올리다 멈춘 채로 두는 것보다 앞 판으로
  # 도는 편이 낫다. 무엇이 잘못됐는지는 journalctl -u csa 에 남아 있다.
  say "다시 띄운 csa가 답하지 않습니다. 앞 판 $old 으로 되돌립니다." >&2
  point "$CURRENT" "$VERSIONS/$old"
  point "$PREVIOUS" "$VERSIONS/$new"
  place_unit
  systemctl restart "$SERVICE" || true
  if answers; then
    die "되돌렸고 앞 판 $old 이(가) 답합니다. 새 판 $new 은(는) 뜨지 못했습니다. journalctl -u $SERVICE 를 보십시오"
  fi
  die "되돌렸는데 앞 판 $old 도 답하지 않습니다. journalctl -u $SERVICE 를 보십시오"
}

do_rollback() {
  need_root rollback
  [ -L "$CURRENT" ] || die "설치되어 있지 않습니다"
  [ -L "$PREVIOUS" ] || die "되돌릴 앞 판이 없습니다"
  local cur prev
  cur=$(linked_version "$CURRENT")
  prev=$(linked_version "$PREVIOUS")
  point "$CURRENT" "$VERSIONS/$prev"
  point "$PREVIOUS" "$VERSIONS/$cur"
  place_unit
  say "링크를 옮겼습니다. $cur → $prev"
  if ! active; then
    say "서비스가 돌고 있지 않아 다시 띄우지 않습니다. 되돌렸습니다. 판 $prev"
    return
  fi
  systemctl restart "$SERVICE"
  if answers; then
    say "다시 띄웠고 csa가 답합니다. 되돌렸습니다. 판 $prev"
    return
  fi
  die "되돌린 판 $prev 이(가) 답하지 않습니다. journalctl -u $SERVICE 를 보십시오"
}

do_status() {
  local cur prev
  cur=$(linked_version "$CURRENT")
  prev=$(linked_version "$PREVIOUS")
  say "지금 판:      ${cur:-없음}"
  say "앞 판:        ${prev:-없음}"
  if [ -d "$VERSIONS" ]; then
    say "둔 판:        $(ls "$VERSIONS" | tr '\n' ' ')"
  fi
  if systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1; then
    say "서비스:       $(systemctl is-active "$SERVICE" 2>/dev/null || true) ($(systemctl is-enabled "$SERVICE" 2>/dev/null || true))"
  fi
}

case "${1:-}" in
  install)  do_install ;;
  upgrade)  do_upgrade ;;
  rollback) do_rollback ;;
  status)   do_status ;;
  *) usage; exit 2 ;;
esac
