#!/usr/bin/env bash
# 설치 묶음을 만든다.
#
#   dist/pack.sh <csa 실행 파일> <아키텍처> [둘 자리]
#
# 묶음 하나에 csa 실행 파일, csa.service, install.sh, INSTALL.md, 라이선스 셋,
# 그리고 그것들을 설명하는 sbom.spdx.json이 들어간다. 받는 쪽이 실행 파일 하나만
# 가져가는 길을 두지 않는다. 그 사본에 라이선스가 없기 때문이다. 태그 워크플로와
# make dist와 설치 시험이 같은 이 스크립트를 쓴다.
#
# 실행 파일은 bin/ 아래에 둔다. SELinux의 기본 정책이 /opt/*/bin/ 아래의 파일에
# bin_t를 붙이고, systemd는 그 문맥의 파일만 띄운다. 묶음을 푼 그대로
# /opt/callsignet/versions/<판>/에 옮기므로 묶음 안의 자리가 곧 설치된 자리다.
#
# 순서는 설계 문서의 「발행」 절대로다. 실행 파일과 나머지 파일을 자리에 두고,
# SBOM을 만들고(그때 실행 파일의 buildinfo를 검사한다), PACK_HOOK이 있으면 그것을
# 돌려 SBOM을 따로 검사하고, 그다음에야 tar를 만든다. SBOM의 사본을 tar 곁에
# <이름>.spdx.json으로 둔다. tar 안의 것과 바이트가 같다.
#
# 환경 변수
#   PACK_VERSION   판. 비워 두면 실행 파일에 묻고, 이 머신에서 돌지 않으면 cmd/csa/main.go의 Version
#   PACK_COMMIT    커밋 해시. 비워 두면 git rev-parse HEAD
#   PACK_REPO      GitHub 리포. 기본 randyinthedev-hash/callsignet
#   PACK_HOOK      SBOM을 만든 뒤 tar 전에 부를 명령. 묶음 디렉터리를 인자로 받는다
#   PACK_ALLOW_MODIFIED  1이면 작업 나무가 깨끗하지 않아도 만든다. 손으로 만들 때만 쓴다
#   GO             go 실행 파일. sudo 아래에서는 PATH에 go가 없을 수 있다
set -euo pipefail
GO=${GO:-go}

bin=${1:?csa 실행 파일}
arch=${2:?아키텍처}
out=${3:-dist/out}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

version=${PACK_VERSION:-}
if [ -z "$version" ]; then
  if ! version=$("$bin" version 2>/dev/null); then
    # 다른 아키텍처나 운영체제의 실행 파일은 여기서 돌지 않는다. 소스의 값을 쓴다.
    version=$(sed -n 's/^var Version = "\(.*\)"$/\1/p' "$REPO/cmd/csa/main.go")
  fi
  [ -n "$version" ] || { echo "판을 알아내지 못했습니다. PACK_VERSION을 주십시오." >&2; exit 1; }
fi
commit=${PACK_COMMIT:-$(git -C "$REPO" rev-parse HEAD)}
repo=${PACK_REPO:-randyinthedev-hash/callsignet}

name="csa-linux-$arch"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage/bin"
cp "$bin" "$stage/bin/csa"
chmod 0755 "$stage/bin/csa"
cp "$HERE/csa.service" "$HERE/install.sh" "$stage/"
cp "$REPO/INSTALL.md" "$REPO/LICENSE" "$REPO/THIRD-PARTY-NOTICES.md" "$stage/"

allow=()
[ "${PACK_ALLOW_MODIFIED:-0}" = 1 ] && allow=(-allow-modified)
( cd "$REPO" && "$GO" run ./tools/sbom make -dir "$stage" -program csa -arch "$arch" \
    -version "$version" -commit "$commit" -repo "$repo" -license Apache-2.0 ${allow[@]+"${allow[@]}"} )
if [ -n "${PACK_HOOK:-}" ]; then
  $PACK_HOOK "$stage"
fi
cp "$stage/sbom.spdx.json" "$out/$name.spdx.json"
# COPYFILE_DISABLE은 macOS의 tar가 확장 속성을 ._ 항목으로 끼워 넣는 것을 막는다.
# 리눅스에서는 아무 뜻이 없다.
( cd "$out" && COPYFILE_DISABLE=1 tar -czf "$name.tar.gz" "$name" )
rm -rf "$stage"
echo "$out/$name.tar.gz"
