#!/usr/bin/env bash
# csa를 설치하고, 올리고, 되돌린다.
#
# 이 스크립트는 설치 묶음 안에 들어 있다. 묶음을 푼 자리에서 부른다. 묶음에는
# bin/csa와 csa.service와 이 스크립트와 라이선스가 있다.
#
# 판마다 자기 디렉터리에 두고 심볼릭 링크 하나로 어느 판이 도는지 정한다.
#
#   /opt/callsignet/versions/<판>/   묶음을 푼 그대로. 실행 파일은 bin/csa
#   /opt/callsignet/current          지금 도는 판을 가리키는 링크
#   /opt/callsignet/previous         바로 앞 판을 가리키는 링크. 되돌릴 때 쓴다
#   /usr/local/bin/csa               current/bin/csa를 가리키는 링크
#   /etc/systemd/system/csa.service  current/csa.service의 사본
#   /etc/callsignet/                 설정. 이 스크립트는 만들기만 하고 채우지 않는다
#
# 올릴 때도 되돌릴 때도 같은 길을 밟는다. 옮겨 갈 판의 csa로 지금 설정을 먼저
# 검사하고, 지나면 링크를 옮기고 다시 띄운 뒤, csa가 답하는지 본다. 답하지
# 않으면 방금까지 돌던 판으로 스스로 돌아온다.
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
  upgrade    이 묶음의 판으로 옮긴다. 먼저 검사하고, 다시 띄운 뒤 답하지 않으면 돌아온다
  rollback   바로 앞 판으로 옮긴다. 먼저 검사하고, 다시 띄운 뒤 답하지 않으면 돌아온다
  status     어느 판이 돌고 어느 판으로 되돌릴 수 있는지 보여 준다
EOF
}

die() { echo "오류: $*" >&2; exit 1; }
say() { echo "$*"; }

need_root() { [ "$(id -u)" -eq 0 ] || die "root가 필요합니다: sudo $0 $*"; }

# 이 묶음의 판이다. 실행 파일이 말하는 값을 쓴다. 파일 이름이나 디렉터리 이름을
# 믿지 않는다.
bundle_version() {
  [ -x "$HERE/bin/csa" ] || die "이 자리에 bin/csa가 없습니다: $HERE"
  "$HERE/bin/csa" version
}

# 링크가 가리키는 판이다. 링크가 없으면 빈 값이다.
linked_version() { # 링크
  [ -L "$1" ] || { echo ""; return; }
  basename "$(readlink -f "$1")"
}

active() { systemctl is-active --quiet "$SERVICE"; }

# 판 디렉터리를 만든다. 묶음을 푼 그대로 옮긴다.
#
# 임자와 권한을 root의 것으로 못박는다. 묶음을 푼 사람이 일반 사용자면 푼
# 파일의 임자가 그 사용자다. 그것을 그대로 옮기면 root로 도는 실행 파일을 그
# 사용자가 고칠 수 있다. 다른 사용자가 쓸 수 없게 하는 것도 같은 까닭이다.
#
# 같은 판의 디렉터리가 이미 있으면 치우고 다시 둔다. 앞서 사전 검사에 걸려
# 멈춘 시도가 남긴 것이거나 앞 판이다. 지금 도는 판만은 건드리지 않는다.
place() { # 판
  local dir="$VERSIONS/$1"
  if [ -e "$dir" ]; then
    if [ "$(readlink -f "$CURRENT" 2>/dev/null || true)" = "$dir" ]; then
      die "지금 도는 판입니다: $dir"
    fi
    rm -rf "$dir"
  fi
  install -d -m 755 "$ROOT" "$VERSIONS"
  rm -rf "$dir.tmp"
  mkdir -p "$dir.tmp"
  cp -a "$HERE/." "$dir.tmp/"
  chown -R root:root "$dir.tmp"
  chmod -R go-w "$dir.tmp"
  chmod 0755 "$dir.tmp/bin/csa"
  mv -T "$dir.tmp" "$dir"
  # SELinux가 있으면 문맥을 이 자리의 기본값으로 되돌린다. cp -a가 묶음을 푼
  # 자리의 문맥을 그대로 가져오는데, 홈 디렉터리에서 풀었으면 그 문맥으로는
  # systemd가 실행 파일을 띄우지 못한다. /opt/*/bin/ 아래는 기본 정책이 bin_t를
  # 붙이므로 되돌리기만 하면 된다. SELinux가 없는 머신에는 이 명령이 없다.
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$dir"
  fi
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
    if "$CURRENT/bin/csa" status -c "$CONF" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# 옮겨 갈 판의 csa로 지금 설정을 본다. 설정 파일의 모양이 판마다 달라질 수 있다.
# 설정이 아직 없으면 볼 것이 없다.
accepts_config() { # 판
  [ -f "$CONF/csa.toml" ] || { say "설정이 아직 없어 검사를 건너뜁니다."; return 0; }
  "$VERSIONS/$1/bin/csa" check -c "$CONF"
}

# 링크를 옮기고 서비스 파일을 맞춘다. 되돌릴 때는 인자를 바꿔 부른다.
switch() { # 새로 돌 판  앞 판으로 적을 판
  point "$PREVIOUS" "$VERSIONS/$2"
  point "$CURRENT" "$VERSIONS/$1"
  place_unit
}

# 다시 띄우고 답하는지 본다. systemctl restart 자체가 실패하는 자리가 있다.
# 실행 파일을 띄우지 못하면 그 자리에서 0이 아닌 값이 돌아온다. 그것도 답하지
# 않는 것과 같게 본다. set -e가 그 실패에서 스크립트를 멈추게 두면 링크가 새
# 판을 가리킨 채로 남는다.
restarted_and_answers() {
  systemctl restart "$SERVICE" || return 1
  answers
}

# 판을 옮긴다. 올리기와 되돌리기가 같은 길이다.
#
#   1. 옮겨 갈 판의 csa로 지금 설정을 검사한다. 걸리면 아무것도 바꾸지 않는다.
#   2. 링크를 옮기고 서비스 파일을 맞춘다.
#   3. 서비스가 돌고 있으면 다시 띄우고 답하는지 본다.
#   4. 답하지 않으면 방금까지 돌던 판으로 링크를 되돌리고 다시 띄운다.
move() { # 옮겨 갈 판  지금 판  무엇을 하는 것인지(올리기/되돌리기)
  local to=$1 from=$2 what=$3
  if ! accepts_config "$to"; then
    die "$what: 판 $to 이(가) 지금 설정을 받지 않습니다. 아무것도 바꾸지 않았습니다."
  fi
  switch "$to" "$from"
  say "링크를 옮겼습니다. $from → $to"

  if ! active; then
    say "서비스가 돌고 있지 않아 다시 띄우지 않습니다. $what 끝. 판 $to"
    return 0
  fi
  if restarted_and_answers; then
    say "다시 띄웠고 csa가 답합니다. $what 끝. 판 $to"
    return 0
  fi
  # 답하지 않으면 방금까지 돌던 판으로 돌아온다. 옮기다 멈춘 채로 두는 것보다
  # 앞서 돌던 판이 도는 편이 낫다. 무엇이 잘못됐는지는 journalctl -u csa 에 남는다.
  say "판 $to 이(가) 뜨지 않거나 답하지 않습니다. 판 $from 으로 돌아옵니다." >&2
  switch "$from" "$to"
  if restarted_and_answers; then
    die "$what 실패. 판 $from 으로 돌아왔고 그것이 답합니다. 판 $to 은(는) 뜨지 못했습니다. journalctl -u $SERVICE 를 보십시오"
  fi
  die "$what 실패. 판 $from 으로 돌아왔는데 그것도 답하지 않습니다. journalctl -u $SERVICE 를 보십시오"
}

do_install() {
  need_root install
  [ -L "$CURRENT" ] && die "이미 설치되어 있습니다. 올리려면 $0 upgrade"
  local ver
  ver=$(bundle_version)
  place "$ver"
  point "$CURRENT" "$VERSIONS/$ver"
  install -d -m 755 "$(dirname "$BIN")"
  point "$BIN" "$CURRENT/bin/csa"
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
  if ! accepts_config "$new"; then
    # 두었던 디렉터리를 치운다. 남겨 두면 다음 시도가 헷갈린다. 앞 판이 그
    # 디렉터리면 두어야 한다. 되돌릴 자리가 사라진다.
    if [ "$(readlink -f "$PREVIOUS" 2>/dev/null || true)" != "$VERSIONS/$new" ]; then
      rm -rf "$VERSIONS/$new"
    fi
    die "올리기: 새 판 $new 이(가) 지금 설정을 받지 않습니다. 아무것도 바꾸지 않았습니다. 설정을 고치거나 판을 다시 고르십시오"
  fi
  say "새 판 $new 이(가) 지금 설정을 받습니다."
  move "$new" "$old" "올리기"
}

do_rollback() {
  need_root rollback
  [ -L "$CURRENT" ] || die "설치되어 있지 않습니다"
  [ -L "$PREVIOUS" ] || die "되돌릴 앞 판이 없습니다"
  local cur prev
  cur=$(linked_version "$CURRENT")
  prev=$(linked_version "$PREVIOUS")
  [ -x "$VERSIONS/$prev/bin/csa" ] || die "앞 판의 실행 파일이 없습니다: $VERSIONS/$prev/bin/csa"
  move "$prev" "$cur" "되돌리기"
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
