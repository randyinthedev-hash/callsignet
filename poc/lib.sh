# 시험 스크립트가 함께 쓰는 것.

# find_go는 go를 찾는다. 시험은 root로 도는데 sudo는 부르는 사람의 PATH를
# 물려주지 않는다. 부르는 사람이 GO로 자리를 줄 수도 있다.
find_go() {
  if [ -n "${GO:-}" ] && [ -x "$GO" ]; then echo "$GO"; return; fi
  if command -v go > /dev/null 2>&1; then command -v go; return; fi
  local home
  home=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
  for c in /usr/local/go/bin/go "$home/go-toolchain/bin/go" "$home/go/bin/go" \
           /usr/lib/go/bin/go /snap/bin/go; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
  for c in /usr/lib/go-*/bin/go; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
}

# build_csa는 csa를 새로 만든다.
#
# 만들어 둔 것을 그냥 쓰면 시험이 낡은 바이너리로 돈다. 코드를 고치고 시험을
# 돌려 모두 통과해도 고치기 전의 csa를 잰 것이 된다. 실제로 그런 일이 있었다.
build_csa() { # 리포 만들 자리 [static]
  local repo=$1 out=$2 static=${3:-}
  local go
  go=$(find_go)
  if [ -z "$go" ]; then
    echo "go를 찾지 못했습니다. 자리를 주십시오: sudo GO=/path/to/go $0" >&2
    exit 1
  fi
  if [ -n "$static" ]; then
    ( cd "$repo" && CGO_ENABLED=0 "$go" build -o "$out" ./cmd/csa )
  else
    ( cd "$repo" && "$go" build -o "$out" ./cmd/csa )
  fi
  echo "csa를 새로 만들었습니다: $out"
}

# own은 root로 만든 파일을 부른 사람에게 넘긴다. 시험은 root로 도는데 기록은
# 리포에 남으므로, 그대로 두면 부른 사람이 그 파일을 지우지도 고치지도 못한다.
# git이 그 파일을 덮어쓰지 못해 pull이 막히는 일도 생긴다.
own() { # 파일이나 디렉터리
  [ -n "${SUDO_UID:-}" ] || return 0
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null || true
}
