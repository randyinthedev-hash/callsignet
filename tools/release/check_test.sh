#!/usr/bin/env bash
# tools/release/check.sh의 시험이다. GitHub에 닿지 않는다. gh는 대역이고 자산은 여기서 만든다.
#
# 보는 것 셋이다. 검증에 실패한 묶음은 풀지도 실행하지도 않는다. 체크섬 목록에 묶음이
# 빠지면 거절한다. 상대 경로로 준 기록이 끝난 뒤에도 남는다.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CHECK="$ROOT/tools/release/check.sh"
T=$(mktemp -d /tmp/csn-release-check-test.XXXXXX); trap 'rm -rf "$T"' EXIT
COMMIT=be3cbfeab0700e37b5c918a470d4a84430eba8a7
FAILS=0
pass() { echo "  ok    $1"; }
fail() { echo "  틀림  $1"; FAILS=$((FAILS + 1)); }

# gh 대역. 태그는 기대 커밋을 가리키고, 릴리스는 pre-release이며, 증명 검증은 다른
# 커밋·참조·워크플로를 주면 거절하고 그 밖에는 받아들인다. STUB_ATTEST_FAIL이 있으면
# 모든 증명 검증이 실패한다.
cat > "$T/gh" <<'GH'
#!/usr/bin/env bash
case "$1 $2" in
  "api repos/"*)
    case "$*" in *"--jq .object.type"*) echo commit ;; *) echo "$STUB_COMMIT" ;; esac ;;
  "release view") echo true ;;
  "release download") echo "대역은 내려받지 않는다" >&2; exit 1 ;;
  "attestation trusted-root") echo '{}' ;;
  "attestation verify")
    [ -n "${STUB_ATTEST_FAIL:-}" ] && exit 1
    case "$*" in *0000000000000000000000000000000000000000*|*refs/heads/main*|*ci.yml*) exit 1 ;; esac
    case "$*" in *"--format json"*) echo '[]' ;; esac ;;
  *) echo "대역이 모르는 명령이다: $*" >&2; exit 1 ;;
esac
GH
chmod +x "$T/gh"
export STUB_COMMIT=$COMMIT CHECK_GH="$T/gh"

# 자산 아홉. 묶음 안의 csa는 돌면 흔적을 남기는 스크립트다. 부품 목록은 없으므로 묶음
# 검사에 걸린다. 그 묶음이 풀리거나 돌면 흔적 파일이 생긴다.
make_assets() { # 디렉터리
  local d=$1; mkdir -p "$d"
  for arch in amd64 arm64; do
    local n=csa-linux-$arch; mkdir -p "$T/src/$n/bin"
    printf '#!/bin/sh\necho executed > "%s"\necho 0.2.0\n' "$T/executed-$arch" > "$T/src/$n/bin/csa"; chmod +x "$T/src/$n/bin/csa"
    echo "## Go 런타임과 표준 라이브러리" > "$T/src/$n/THIRD-PARTY-NOTICES.md"
    tar -C "$T/src" -czf "$d/$n.tar.gz" "$n"
    echo '{}' > "$d/$n.spdx.json"
    printf '{}\n{}\n' > "$d/$n.tar.gz.attestations.jsonl"
  done
  echo LICENSE > "$d/LICENSE"; echo notices > "$d/THIRD-PARTY-NOTICES.md"
  (cd "$d" && sha256sum csa-linux-amd64.tar.gz csa-linux-arm64.tar.gz > sha256sum.txt)
}

echo "== 검증에 실패한 묶음은 풀지도 실행하지도 않는다"
make_assets "$T/a1"
mkdir -p "$T/cwd1"
set +e; (cd "$T/cwd1" && "$CHECK" -tag v0.2.0 -commit "$COMMIT" -assets "$T/a1" -record rel/out.md > "$T/run1.log" 2>&1); rc=$?; set -e
[ "$rc" = 1 ] && pass "틀림이 있으면 1로 끝난다" || { fail "종료 코드가 1이 아니다: $rc"; cat "$T/run1.log"; }
if [ ! -e "$T/executed-amd64" ] && [ ! -e "$T/executed-arm64" ]; then pass "검증에 실패한 묶음의 실행 파일이 돌지 않았다"; else fail "검증에 실패한 묶음의 실행 파일이 돌았다"; fi
if [ "$(grep -c '^| 미실행 |' "$T/cwd1/rel/out.md" 2>/dev/null || true)" = 2 ] && ! grep -q '^| ok | buildinfo' "$T/cwd1/rel/out.md"; then pass "그 묶음의 뒤 검사가 미실행으로 남았다"; else fail "미실행 표시가 다르다"; grep '미실행\|buildinfo' "$T/cwd1/rel/out.md" || true; fi
grep -q '묶음 검사에 걸렸다: csa-linux-amd64.tar.gz' "$T/cwd1/rel/out.md" && pass "부품 목록 검사의 실패가 틀림으로 적혔다" || fail "부품 목록 검사의 실패가 적히지 않았다"

echo "== 상대 경로로 준 기록이 끝난 뒤에도 남는다"
[ -s "$T/cwd1/rel/out.md" ] && pass "기록이 부른 자리 기준의 상대 경로에 남았다" || fail "기록이 없다: $T/cwd1/rel/out.md"
grep -q "주어진 디렉터리" "$T/cwd1/rel/out.md" && pass "기록 머리말이 자산의 출처를 주어진 디렉터리라고 적는다" || fail "기록 머리말의 출처가 다르다"

echo "== 증명 검증에 실패해도 묶음을 풀지 않는다"
rm -f "$T/executed-"*
set +e; (cd "$T/cwd1" && STUB_ATTEST_FAIL=1 "$CHECK" -tag v0.2.0 -commit "$COMMIT" -assets "$T/a1" -record out2.md > "$T/run2.log" 2>&1); rc=$?; set -e
if [ "$rc" = 1 ] && [ ! -e "$T/executed-amd64" ] && grep -q '^| 틀림 | 출처 증명이 온라인에서 확인된다' "$T/cwd1/out2.md" && [ "$(grep -c '^| 미실행 |' "$T/cwd1/out2.md")" = 2 ]; then pass "증명 검증에 실패한 묶음이 풀리지 않고 미실행으로 남았다"; else fail "증명 검증 실패의 처리가 다르다 (rc $rc)"; grep '틀림\|미실행' "$T/cwd1/out2.md" | head -5; fi

echo "== 체크섬 목록에 묶음이 빠지면 거절한다"
make_assets "$T/a2"
(cd "$T/a2" && sha256sum csa-linux-amd64.tar.gz > sha256sum.txt)   # arm64를 빠뜨린 목록
set +e; (cd "$T" && "$CHECK" -tag v0.2.0 -commit "$COMMIT" -assets "$T/a2" -record out3.md > "$T/run3.log" 2>&1); rc=$?; set -e
if [ "$rc" = 1 ] && grep -q '^| 틀림 | sha256sum.txt의 항목이 두 묶음과 다르다' "$T/out3.md" && ! grep -q '^| ok | sha256sum.txt' "$T/out3.md"; then pass "빠진 항목이 있는 체크섬 목록을 거절하고 맞는다고 적지 않는다"; else fail "체크섬 목록의 처리가 다르다 (rc $rc)"; grep sha256sum "$T/out3.md" | head -5; fi
(cd "$T/a2" && { sha256sum csa-linux-amd64.tar.gz; sha256sum csa-linux-amd64.tar.gz; sha256sum csa-linux-arm64.tar.gz; } > sha256sum.txt)   # 겹친 항목
set +e; (cd "$T" && "$CHECK" -tag v0.2.0 -commit "$COMMIT" -assets "$T/a2" -record out4.md > "$T/run4.log" 2>&1); rc=$?; set -e
grep -q '^| 틀림 | sha256sum.txt의 항목이 두 묶음과 다르다' "$T/out4.md" && pass "겹친 항목이 있는 체크섬 목록을 거절한다" || fail "겹친 항목을 거절하지 않는다"
(cd "$T/a2" && { sha256sum csa-linux-amd64.tar.gz csa-linux-arm64.tar.gz; echo "0000000000000000000000000000000000000000000000000000000000000000  LICENSE"; } > sha256sum.txt)   # 예상 밖 항목
set +e; (cd "$T" && "$CHECK" -tag v0.2.0 -commit "$COMMIT" -assets "$T/a2" -record out5.md > "$T/run5.log" 2>&1); rc=$?; set -e
grep -q '^| 틀림 | sha256sum.txt의 항목이 두 묶음과 다르다' "$T/out5.md" && pass "예상 밖 항목이 있는 체크섬 목록을 거절한다" || fail "예상 밖 항목을 거절하지 않는다"

echo
if [ "$FAILS" = 0 ]; then echo "tools/release/check.sh의 시험을 모두 지났다"; else echo "tools/release/check.sh의 시험에서 $FAILS개가 틀렸다"; exit 1; fi
