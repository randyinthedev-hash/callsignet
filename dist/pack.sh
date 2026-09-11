#!/usr/bin/env bash
# 설치 묶음을 만든다.
#
#   dist/pack.sh <csa 실행 파일> <아키텍처> [둘 자리]
#
# 묶음 하나에 csa 실행 파일, csa.service, install.sh, INSTALL.md, 라이선스 셋이
# 들어간다. 받는 쪽이 실행 파일 하나만 가져가는 길을 두지 않는다. 그 사본에
# 라이선스가 없기 때문이다. 태그 워크플로와 make dist가 같은 이 스크립트를 쓴다.
set -euo pipefail

bin=${1:?csa 실행 파일}
arch=${2:?아키텍처}
out=${3:-dist/out}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

name="csa-linux-$arch"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$bin" "$stage/csa"
chmod 0755 "$stage/csa"
cp "$HERE/csa.service" "$HERE/install.sh" "$stage/"
cp "$REPO/INSTALL.md" "$REPO/LICENSE" "$REPO/THIRD-PARTY-NOTICES.md" "$stage/"
( cd "$out" && tar -czf "$name.tar.gz" "$name" )
rm -rf "$stage"
echo "$out/$name.tar.gz"
