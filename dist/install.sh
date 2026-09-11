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
# 않으면 시도하기 전 그대로 돌아온다. 돌아오지도 못하면 그렇다고 말한다.
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

# 판 이름으로 쓸 수 있는 값인지 본다. 판 이름은 디렉터리 이름이 되고 그 디렉터리를
# 지우기도 한다. 빈 값이나 . 이나 .. 이나 슬래시가 든 값을 그대로 쓰면 엉뚱한
# 곳을 지운다. 글자와 숫자로 시작하고 점과 붙임표와 밑줄과 더하기만 더 허용한다.
valid_version() {
  case "$1" in
    ""|.|..|*/*) return 1 ;;
  esac
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]
}

# 이 묶음의 판이다. 실행 파일이 말하는 값을 쓴다. 파일 이름이나 디렉터리 이름을
# 믿지 않는다. 묶음에 있어야 할 것이 다 있는지도 여기서 본다.
bundle_version() {
  [ -x "$HERE/bin/csa" ] || die "이 자리에 bin/csa가 없습니다: $HERE"
  [ -f "$HERE/csa.service" ] || die "이 자리에 csa.service가 없습니다: $HERE"
  local v
  v=$("$HERE/bin/csa" version) || die "bin/csa version 이 실패했습니다"
  valid_version "$v" || die "판 이름으로 쓸 수 없는 값입니다. 아무것도 바꾸지 않았습니다: '$v'"
  echo "$v"
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
# 옆에 만드는 자리의 이름은 점으로 시작한다. 판 이름은 글자나 숫자로 시작해야
# 하므로 어떤 판의 디렉터리와도 겹치지 않는다. 판 이름 뒤에 .tmp를 붙여 쓰면
# 지금 판의 이름이 <새 판>.tmp일 때 지금 판을 지운다.
#
# 같은 판의 디렉터리가 이미 있으면 새것을 옆에 다 만든 뒤에야 있던 것을 밀어
# 두고 새것을 놓는다. 있던 것을 먼저 지우고 만들다 실패하면, 그것이 앞 판일 때
# 되돌릴 자리가 사라진다. 지금 도는 판만은 건드리지 않는다.
place() { # 판
  valid_version "$1" || die "판 이름으로 쓸 수 없는 값입니다: '$1'"
  local dir="$VERSIONS/$1" stage old
  if [ "$(readlink -f "$CURRENT" 2>/dev/null || true)" = "$dir" ]; then
    die "지금 도는 판입니다: $dir"
  fi
  install -d -m 755 "$ROOT" "$VERSIONS"
  stage=$(mktemp -d "$VERSIONS/.stage.XXXXXX") || die "옆에 만들 자리를 얻지 못했습니다: $VERSIONS"
  if ! { cp -a "$HERE/." "$stage/" && chown -R root:root "$stage" \
         && chmod -R go-w "$stage" && chmod 0755 "$stage/bin/csa"; }; then
    rm -rf "$stage"
    die "판을 옮기지 못했습니다. 아무것도 바꾸지 않았습니다: $dir"
  fi
  if [ -e "$dir" ]; then
    old=$(mktemp -d "$VERSIONS/.old.XXXXXX") || { rm -rf "$stage"; die "옆에 밀어 둘 자리를 얻지 못했습니다: $VERSIONS"; }
    if ! mv -T "$dir" "$old"; then
      rm -rf "$stage" "$old"
      die "있던 판을 옆으로 밀지 못했습니다. 아무것도 바꾸지 않았습니다: $dir"
    fi
    if ! mv -T "$stage" "$dir"; then
      mv -T "$old" "$dir" || die "새 판을 놓지 못했고 있던 판도 제자리로 돌리지 못했습니다. 있던 판은 $old 에 있습니다. 손으로 되돌리십시오"
      rm -rf "$stage"
      die "새 판을 놓지 못했습니다. 있던 판은 그대로입니다: $dir"
    fi
    rm -rf "$old"
  else
    mv -T "$stage" "$dir" || { rm -rf "$stage"; die "판을 제자리에 놓지 못했습니다: $dir"; }
  fi
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
# 실패하면 0이 아닌 값을 돌려준다. 부르는 쪽이 그것을 받아 되돌린다.
point() { # 링크 대상
  ln -sfn "$2" "$1.tmp" || return 1
  mv -T "$1.tmp" "$1" || return 1
}

# 서비스 파일을 지금 판의 것으로 맞춘다. 이미 같으면 쓰지 않는다. 그래야 서비스
# 파일을 쓸 수 없는 자리에서 되돌릴 때 원래 것을 그대로 두고 지나간다.
place_unit() {
  if ! cmp -s "$CURRENT/csa.service" "$UNIT" 2>/dev/null; then
    install -m 644 "$CURRENT/csa.service" "$UNIT" || return 1
  fi
  systemctl daemon-reload || return 1
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

# 링크 둘과 서비스 파일을 한 상태로 맞춘다. 앞 판이 비어 있으면 그 링크를 없앤다.
# 어느 걸음이든 실패하면 0이 아닌 값을 돌려준다.
set_state() { # 지금 판  앞 판(비어 있을 수 있음)
  point "$CURRENT" "$VERSIONS/$1" || return 1
  if [ -n "$2" ]; then
    point "$PREVIOUS" "$VERSIONS/$2" || return 1
  else
    rm -f "$PREVIOUS" "$PREVIOUS.tmp" || return 1
  fi
  place_unit || return 1
}

# 다시 띄우고 답하는지 본다. systemctl restart 자체가 실패하는 자리가 있다.
# 실행 파일을 띄우지 못하면 그 자리에서 0이 아닌 값이 돌아온다. 그것도 답하지
# 않는 것과 같게 본다.
#
# 띄우기 전에 실패 상태를 푼다. 앞서 뜨지 못한 판이 되풀이해 죽었으면 systemd가
# 기동 횟수 제한에 걸려 그 유닛의 기동을 잠시 막는다. 풀지 않으면 좋은 판으로
# 돌아와도 뜨지 못한다. 그 판은 죽은 적이 없는데 앞 판이 죽은 값을 치른다.
restarted_and_answers() {
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  systemctl restart "$SERVICE" || return 1
  answers
}

# 되돌리지도 못했을 때 말한다. 「돌아왔다」고 하지 않는다. 지금 링크가 무엇을
# 가리키고 서비스 파일이 어느 것인지 그대로 적는다. 손으로 맞추는 사람이 볼 것이다.
mixed() { # 무엇  마지막으로 돌던 판
  {
    echo "오류: $1 실패. 되돌리지도 못했습니다. 이 머신은 반쯤 옮겨진 상태입니다."
    echo "  current  → $(readlink "$CURRENT" 2>/dev/null || echo 없음)"
    echo "  previous → $(readlink "$PREVIOUS" 2>/dev/null || echo 없음)"
    if cmp -s "$CURRENT/csa.service" "$UNIT" 2>/dev/null; then
      echo "  서비스 파일: current의 것과 같습니다"
    else
      echo "  서비스 파일: current의 것과 다릅니다"
    fi
    echo "  서비스: $(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    echo "  마지막으로 돌던 판은 $2 입니다. 서비스를 멈추고 까닭을 치운 뒤 그 판의 묶음으로 upgrade 하거나 rollback 하십시오."
    echo "  $0 status 와 journalctl -u $SERVICE 를 보십시오."
  } >&2
  exit 2
}

# 판을 옮긴다. 올리기와 되돌리기가 같은 길이다.
#
#   1. 옮겨 갈 판의 csa로 지금 설정을 검사한다. 걸리면 아무것도 바꾸지 않는다.
#   2. 링크를 옮기고 서비스 파일을 맞춘다. 여기서 실패하면 시도 전 그대로 돌아온다.
#   3. 서비스가 돌고 있으면 다시 띄우고 답하는지 본다.
#   4. 답하지 않으면 시도 전 그대로 돌아오고 다시 띄운다.
#   5. 돌아오지도 못하면 반쯤 옮겨진 상태라고 말한다.
move() { # 옮겨 갈 판  지금 판  무엇을 하는 것인지(올리기/되돌리기)
  local to=$1 from=$2 what=$3 oldprev
  oldprev=$(linked_version "$PREVIOUS")
  if ! accepts_config "$to"; then
    die "$what: 판 $to 이(가) 지금 설정을 받지 않습니다. 아무것도 바꾸지 않았습니다."
  fi

  if ! set_state "$to" "$from"; then
    say "링크나 서비스 파일을 옮기다 실패했습니다. 시도 전 그대로 돌아옵니다." >&2
    set_state "$from" "$oldprev" || mixed "$what" "$from"
    die "$what 실패. 링크나 서비스 파일을 옮기지 못했습니다. 시도 전 그대로 돌아왔고 아무것도 바뀌지 않았습니다."
  fi
  say "링크를 옮겼습니다. $from → $to"

  if ! active; then
    say "서비스가 돌고 있지 않아 다시 띄우지 않습니다. $what 끝. 판 $to"
    return 0
  fi
  if restarted_and_answers; then
    say "다시 띄웠고 csa가 답합니다. $what 끝. 판 $to"
    return 0
  fi
  # 답하지 않으면 시도 전 그대로 돌아온다. 옮기다 멈춘 채로 두는 것보다 앞서
  # 돌던 판이 도는 편이 낫다. 무엇이 잘못됐는지는 journalctl -u csa 에 남는다.
  say "판 $to 이(가) 뜨지 않거나 답하지 않습니다. 판 $from 으로 돌아옵니다." >&2
  set_state "$from" "$oldprev" || mixed "$what" "$from"
  if restarted_and_answers; then
    die "$what 실패. 판 $from 으로 돌아왔고 그것이 답합니다. 판 $to 은(는) 뜨지 못했습니다. journalctl -u $SERVICE 를 보십시오"
  fi
  die "$what 실패. 판 $from 으로 돌아왔는데 그것도 답하지 않습니다. journalctl -u $SERVICE 를 보십시오"
}

# 처음 설치에서 판을 둔 뒤에 하는 걸음이다. 어느 걸음이든 실패하면 0이 아닌
# 값을 돌려준다.
finish_install() { # 판
  point "$CURRENT" "$VERSIONS/$1" || return 1
  install -d -m 755 "$(dirname "$BIN")" || return 1
  point "$BIN" "$CURRENT/bin/csa" || return 1
  install -d -m 750 "$CONF" || return 1
  place_unit || return 1
  systemctl enable "$SERVICE" >/dev/null || return 1
}

# 처음 설치가 중간에 실패하면 만든 것을 치운다. 반쯤 설치된 채로 두면 다시
# install 해도 「이미 설치되어 있다」로, upgrade 해도 「같은 판이다」로 거절해
# 스크립트만으로는 다시 시도할 수 없다. 설정 디렉터리는 두고 간다. 운영자가
# 거기에 무언가를 두었을 수 있다.
#
# 우리가 만든 것만 지운다. 실행 파일 링크는 우리 자리를 가리킬 때만, 서비스
# 파일은 이 판의 것과 같을 때만이다. 설치는 이미 있는 것이 있으면 시작하지
# 않으므로 여기 오면 모두 우리 것이지만, 그래도 한 번 더 본다.
undo_install() { # 판
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true
  if [ -L "$BIN" ]; then
    case "$(readlink "$BIN")" in "$ROOT"/*) rm -f "$BIN" ;; esac
  fi
  rm -f "$BIN.tmp"
  if [ -f "$UNIT" ] && cmp -s "$UNIT" "$VERSIONS/$1/csa.service"; then
    rm -f "$UNIT"
  fi
  rm -f "$CURRENT" "$CURRENT.tmp"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$VERSIONS/$1"
  rmdir "$VERSIONS" "$ROOT" 2>/dev/null || true
}

# 이미 있는 것을 찾는다. 있으면 그 자리를 적고 0이 아닌 값을 돌려준다.
#
# v0.1.3까지는 설치 묶음이 없어 운영자가 실행 파일을 /usr/local/bin 에 직접
# 두고 서비스 파일도 직접 썼다. 그것을 묻지 않고 덮어쓰거나 실패했을 때 지우면
# 돌던 것을 잃는다. 옮기는 절차는 INSTALL.md에 있다.
in_the_way() {
  local found=0
  for p in "$ROOT" "$BIN" "$UNIT"; do
    if [ -e "$p" ] || [ -L "$p" ]; then echo "  $p"; found=1; fi
  done
  return $found
}

do_install() {
  need_root install
  [ -L "$CURRENT" ] && die "이미 설치되어 있습니다. 올리려면 $0 upgrade"
  local ver way
  if ! way=$(in_the_way); then
    die "이미 있는 것이 있습니다. 설치는 아무것도 덮어쓰거나 지우지 않습니다. 앞서 손으로 설치한 csa라면 INSTALL.md의 「손으로 설치한 csa에서 옮기기」를 보십시오:
$way"
  fi
  ver=$(bundle_version)
  place "$ver"
  if ! finish_install "$ver"; then
    undo_install "$ver"
    die "설치 실패. 만든 것을 치웠습니다. 까닭을 고치고 다시 install 하십시오. 설정 디렉터리 $CONF 는 두었습니다"
  fi
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
  if [ -L "$CURRENT" ]; then
    if cmp -s "$CURRENT/csa.service" "$UNIT" 2>/dev/null; then
      say "서비스 파일:  지금 판의 것과 같음"
    else
      say "서비스 파일:  지금 판의 것과 다름"
    fi
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
