#!/usr/bin/env bash
# 발행한 릴리스의 자산을 워크플로 밖에서 확인하고 기록을 남긴다.
#
#   tools/release/check.sh -tag v0.2.0 -commit <태그가 가리키는 커밋 40자리> [-assets DIR] [-run ID] [-record 파일]
#
# 태그와 기대 커밋은 명시적으로 받는다. 이 머신의 태그를 믿지 않는다. 이 머신에 그 태그가
# 있으면 기대 커밋과 같은지 함께 본다. -assets를 주면 그 디렉터리의 파일을 보고, 주지
# 않으면 GitHub 릴리스에서 내려받는다. -run은 릴리스 워크플로의 실행 번호이고 기록에만
# 적는다. -record는 기록 파일이고 기본은 results/release-<UTC 시각>.md다. 상대 경로는
# 부른 자리를 기준으로 한다.
#
# INSTALL.md의 「받은 묶음을 확인하기」를 그대로 밟는다. 자산의 수, 체크섬 목록이 두 묶음과
# 정확히 같은지, 묶음마다 체크섬, 출처 증명과 부품 목록 증명을 온라인과 오프라인 묶음으로,
# 다른 커밋과 다른 참조와 다른 워크플로를 주면 거절하는지, 부품 목록과 사본, 그 뒤에야
# 묶음을 풀어 실행 파일의 buildinfo와 고지 문서와 판을 본다. 증명 검증은 이 리포의
# 릴리스에 GitHub의 아티팩트 증명이 붙는다는 계약을 전제한다. `gh`는 릴리스 워크플로가
# 쓴 것과 같은 판을 같은 체크섬으로 받아 쓴다. 그 판과 체크섬은 release.yml에서 읽는다.
#
# **검증에 실패한 묶음은 풀지도 실행하지도 않는다.** 체크섬, 증명, 부품 목록 가운데
# 하나라도 어긋나면 그 묶음의 뒤 검사는 「미실행」으로 남긴다. 다른 묶음의 검사는 계속한다.
#
# 결과는 넷이다. ok, 틀림, 건너뜀, 미실행. 이 머신에서 돌릴 수 없는 아키텍처의 실행
# 파일은 판을 찍어 보지 못하므로 건너뜀이다. 건너뜀과 미실행은 통과가 아니고 기록에
# 그렇게 남는다. 틀림이 하나라도 있으면 1로 끝난다.
#
# CHECK_GH에 gh 실행 파일을 주면 받지 않고 그것을 쓴다. 시험이 대역을 넣는 자리다.
set -euo pipefail

REPO=randyinthedev-hash/callsignet
WF=$REPO/.github/workflows/release.yml
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUNDLES="csa-linux-amd64.tar.gz csa-linux-arm64.tar.gz"
ZERO=0000000000000000000000000000000000000000

TAG=; COMMIT=; ASSETS=; RUN=; RECORD=
while [ $# -gt 0 ]; do
  case "$1" in
    -tag) TAG=$2; shift 2 ;;
    -commit) COMMIT=$2; shift 2 ;;
    -assets) ASSETS=$(cd "$2" && pwd); shift 2 ;;
    -run) RUN=$2; shift 2 ;;
    -record) case "$2" in /*) RECORD=$2 ;; *) RECORD=$PWD/$2 ;; esac; shift 2 ;;
    *) echo "모르는 옵션이다: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$TAG" ] || [ -z "$COMMIT" ]; then
  echo "사용법: $0 -tag <태그> -commit <커밋 40자리> [-assets DIR] [-run ID] [-record 파일]" >&2; exit 2
fi
if ! [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then echo "커밋은 40자리 16진수다: $COMMIT" >&2; exit 2; fi
VER=${TAG#v}
NOW=$(date -u +%Y%m%dT%H%M%SZ); STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -n "$RECORD" ] || RECORD="$ROOT/results/release-$NOW.md"
WORK=$(mktemp -d /tmp/csn-release-check.XXXXXX); trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

rows=(); FAIL=0; SKIP=0; NOTRUN=0; V=1
ok()   { rows+=("| ok | $1 |"); echo "  ok    $1"; }
bad()  { rows+=("| 틀림 | $1 |"); echo "  틀림  $1"; FAIL=$((FAIL + 1)); V=0; }
skip() { rows+=("| 건너뜀 | $1 |"); echo "  건너뜀 $1"; SKIP=$((SKIP + 1)); }
miss() { rows+=("| 미실행 | $1. 앞선 검증에 실패한 묶음이라 풀지 않았다 |"); echo "  미실행 $1"; NOTRUN=$((NOTRUN + 1)); }
chk()  { if "${@:2}" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

# gh를 워크플로가 쓴 판으로 받는다. 판과 체크섬은 워크플로 파일이 한 곳에 둔다.
if [ -n "${CHECK_GH:-}" ]; then
  GH=$CHECK_GH; GH_VERSION="대역($GH)"; GH_SHA256=
else
  GH_VERSION=$(sed -n 's/^ *GH_VERSION: *//p' "$ROOT/.github/workflows/release.yml" | head -1)
  GH_SHA256=$(sed -n 's/^ *GH_SHA256: *//p' "$ROOT/.github/workflows/release.yml" | head -1)
  [ -n "$GH_VERSION" ] && [ -n "$GH_SHA256" ] || { echo "release.yml에서 gh의 판과 체크섬을 읽지 못했다" >&2; exit 2; }
  curl -fsSL -o gh.tar.gz "https://github.com/cli/cli/releases/download/v$GH_VERSION/gh_${GH_VERSION}_linux_amd64.tar.gz"
  echo "$GH_SHA256  gh.tar.gz" | sha256sum -c --quiet
  tar -xzf gh.tar.gz; GH="$WORK/gh_${GH_VERSION}_linux_amd64/bin/gh"
fi

# 이 머신의 태그가 있으면 기대 커밋과 견준다. GitHub의 태그도 본다.
if local=$(git -C "$ROOT" rev-parse --verify -q "$TAG^{}" 2>/dev/null); then
  [ "$local" = "$COMMIT" ] && ok "이 머신의 태그 $TAG가 기대 커밋을 가리킨다" || bad "이 머신의 태그 $TAG가 기대 커밋과 다르다: $local"
fi
if [ "$("$GH" api "repos/$REPO/git/ref/tags/$TAG" --jq '.object.type' 2>/dev/null)" = tag ]; then
  remote=$("$GH" api "repos/$REPO/git/tags/$("$GH" api "repos/$REPO/git/ref/tags/$TAG" --jq .object.sha)" --jq .object.sha 2>/dev/null || true)
else
  remote=$("$GH" api "repos/$REPO/git/ref/tags/$TAG" --jq .object.sha 2>/dev/null || true)
fi
[ "$remote" = "$COMMIT" ] && ok "GitHub의 태그 $TAG가 기대 커밋을 가리킨다" || bad "GitHub의 태그 $TAG가 기대 커밋과 다르다: ${remote:-없음}"

if [ -n "$ASSETS" ]; then
  mkdir assets; cp "$ASSETS"/* assets/; ok "주어진 자산 디렉터리를 쓴다: $ASSETS"
else
  chk "릴리스의 자산을 모두 내려받는다" "$GH" release download "$TAG" -R "$REPO" -D assets
fi
n=$(ls assets | wc -l); [ "$n" = 9 ] && ok "자산이 아홉이다: $n" || bad "자산이 아홉이 아니다: $n"
[ "$(ls assets/*.tar.gz 2>/dev/null | wc -l)" = 2 ] && ok "묶음(\`*.tar.gz\`)이 둘이다" || bad "묶음이 둘이 아니다"
[ "$(ls assets/*.spdx.json 2>/dev/null | wc -l)" = 2 ] && ok "부품 목록 사본(\`*.spdx.json\`)이 둘이다" || bad "부품 목록 사본이 둘이 아니다"
[ "$(ls assets/*.attestations.jsonl 2>/dev/null | wc -l)" = 2 ] && ok "증명 묶음(\`*.attestations.jsonl\`)이 둘이다" || bad "증명 묶음이 둘이 아니다"
[ "$("$GH" release view "$TAG" -R "$REPO" --json isPrerelease --jq .isPrerelease 2>/dev/null)" = true ] && ok "pre-release로 표시되어 있다" || bad "pre-release가 아니다"

# 체크섬 목록의 항목이 두 묶음과 정확히 같아야 한다. 빠진 것, 겹친 것, 예상 밖의 것,
# 모양이 틀린 줄을 모두 거절한다. 적힌 것만 맞는지 보면 하나만 적은 목록도 지난다.
LIST=0
if [ -f assets/sha256sum.txt ]; then
  malformed=$(awk 'NF != 2 || $1 !~ /^[0-9a-f]{64}$/' assets/sha256sum.txt | wc -l)
  listed=$(awk '{print $2}' assets/sha256sum.txt | sort)
  expected=$(tr ' ' '\n' <<<"$BUNDLES" | sort)
  if [ "$malformed" = 0 ] && [ "$listed" = "$expected" ]; then ok "sha256sum.txt의 항목이 두 묶음과 정확히 같다"; LIST=1
  else bad "sha256sum.txt의 항목이 두 묶음과 다르다. 빠지거나 겹치거나 예상 밖의 항목이 있다: $(tr '\n' ' ' <<<"$listed")"; fi
else
  bad "sha256sum.txt가 없다"
fi

verify() { "$GH" attestation verify "$1" -R "$REPO" --signer-workflow "$WF" --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" --deny-self-hosted-runners "${@:2}"; }
chk "신뢰 뿌리를 받는다" bash -c "\"$GH\" attestation trusted-root > trusted-root.jsonl"
HOST=$(uname -m); case "$HOST" in x86_64) HOST=amd64 ;; aarch64) HOST=arm64 ;; esac
: > verify.txt; : > proof.txt
for b in $BUNDLES; do
  arch=${b%.tar.gz}; arch=${arch##*-}; f=assets/$b; j=$f.attestations.jsonl
  # 여기서부터 이 묶음의 검증이다. 하나라도 어긋나면 V가 0이 되고 묶음을 풀지 않는다.
  V=1
  if [ "$LIST" = 1 ] && (cd assets && grep " $b\$" sha256sum.txt | sha256sum -c --quiet --strict) >/dev/null 2>&1; then ok "sha256sum.txt의 값과 맞는다: $b"; else bad "sha256sum.txt의 값과 다르다: $b"; fi
  chk "출처 증명이 온라인에서 확인된다: $b" verify "$f"
  chk "부품 목록 증명이 온라인에서 확인된다: $b" verify "$f" --predicate-type https://spdx.dev/Document/v2.3
  if verify "$f" --source-digest "$ZERO" >/dev/null 2>&1; then bad "다른 커밋을 주어도 받아들인다: $b"; else ok "다른 커밋을 주면 거절한다: $b"; fi
  if "$GH" attestation verify "$f" -R "$REPO" --signer-workflow "$WF" --source-ref refs/heads/main --source-digest "$COMMIT" --deny-self-hosted-runners >/dev/null 2>&1; then bad "다른 참조(refs/heads/main)를 주어도 받아들인다: $b"; else ok "다른 참조(refs/heads/main)를 주면 거절한다: $b"; fi
  if "$GH" attestation verify "$f" -R "$REPO" --signer-workflow "$REPO/.github/workflows/ci.yml" --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" --deny-self-hosted-runners >/dev/null 2>&1; then bad "다른 워크플로를 주어도 받아들인다: $b"; else ok "다른 워크플로를 주면 거절한다: $b"; fi
  off() { "$GH" attestation verify "$f" --bundle "$j" --custom-trusted-root trusted-root.jsonl -R "$REPO" --signer-workflow "$WF" --source-ref "refs/tags/$TAG" --source-digest "$COMMIT" --deny-self-hosted-runners "$@"; }
  chk "출처 증명이 오프라인 묶음으로 확인된다: $b" off
  chk "부품 목록 증명이 오프라인 묶음으로 확인된다: $b" off --predicate-type https://spdx.dev/Document/v2.3
  if off --source-digest "$ZERO" >/dev/null 2>&1; then bad "오프라인 묶음이 다른 커밋을 주어도 받아들인다: $b"; else ok "오프라인 묶음도 다른 커밋을 주면 거절한다: $b"; fi
  [ -f "$j" ] && [ "$(wc -l < "$j")" = 2 ] && ok "증명 묶음 안에 증명이 둘이다: $(basename "$j")" || bad "증명 묶음의 줄 수가 둘이 아니다: $(basename "$j")"
  if (cd "$ROOT" && go run ./tools/sbom verify -tar "$WORK/$f" -copy "$WORK/${f%.tar.gz}.spdx.json" -program csa -arch "$arch" -version "$VER" -commit "$COMMIT" -repo "$REPO" -license Apache-2.0) >> verify.txt 2>&1; then ok "묶음이 계약대로이고 사본의 바이트가 같다: $b"; else bad "묶음 검사에 걸렸다: $b"; tail -3 verify.txt; fi
  verify "$f" --format json --jq '.[] | "\(.verificationResult.statement.predicateType)  \(.verificationResult.signature.certificate.sourceRepositoryRef)  \(.verificationResult.signature.certificate.sourceRepositoryDigest)  \(.verificationResult.signature.certificate.buildSignerURI)  \(.verificationResult.signature.certificate.runnerEnvironment)"' >> proof.txt 2>/dev/null || true
  verify "$f" --predicate-type https://spdx.dev/Document/v2.3 --format json --jq '.[] | "\(.verificationResult.statement.predicateType)  \(.verificationResult.signature.certificate.sourceRepositoryRef)  \(.verificationResult.signature.certificate.sourceRepositoryDigest)"' >> proof.txt 2>/dev/null || true

  # 검증을 모두 지난 묶음만 푼다.
  if [ "$V" = 1 ]; then
    mkdir -p "x-$arch"; tar -xzf "$f" -C "x-$arch"
    bi=$(cd "$ROOT" && go version -m "$WORK/x-$arch/csa-linux-$arch/bin/csa" 2>/dev/null || true)
    if grep -q "GOARCH=$arch" <<<"$bi" && grep -q "vcs.revision=$COMMIT" <<<"$bi" && grep -q "vcs.modified=false" <<<"$bi" && grep -q "path.*cmd/csa" <<<"$bi"; then ok "buildinfo가 GOARCH=$arch, vcs.revision=커밋, vcs.modified=false, 주 패키지 cmd/csa다: $b"; else bad "buildinfo가 다르다: $b"; fi
    grep -q "Go 런타임" "x-$arch/csa-linux-$arch/THIRD-PARTY-NOTICES.md" 2>/dev/null && ok "묶음 안의 고지 문서에 Go 런타임의 절이 있다: $b" || bad "고지 문서에 Go 런타임의 절이 없다: $b"
    if [ "$arch" = "$HOST" ]; then
      got=$("x-$arch/csa-linux-$arch/bin/csa" version 2>/dev/null || true)
      [ "$got" = "$VER" ] && ok "$arch 실행 파일이 찍는 판이 $VER이다: $got" || bad "$arch 실행 파일의 판이 다르다: $got"
    else
      skip "$arch 실행 파일은 이 머신($HOST)에서 돌릴 수 없어 판을 찍어 보지 못했다. buildinfo만 보았다"
    fi
  else
    miss "buildinfo와 고지 문서와 판을 보지 못했다: $b"
  fi
done

: > sbom.txt
if [ -f "x-$HOST/csa-linux-$HOST/sbom.spdx.json" ]; then
python3 - "$WORK/x-$HOST/csa-linux-$HOST/sbom.spdx.json" > sbom.txt <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for p in d.get("packages", []):
    if p["SPDXID"] in ("SPDXRef-Package-bundle", "SPDXRef-Package-go", "SPDXRef-Package-go-stdlib"):
        print(p["SPDXID"], "", p.get("versionInfo", ""), "", p.get("licenseConcluded", ""))
for f in d.get("files", []):
    if f["fileName"] in ("./LICENSE", "./THIRD-PARTY-NOTICES.md", "./bin/csa"):
        print(f["fileName"], "", f.get("licenseConcluded", ""))
for r in d.get("relationships", []):
    if r["relationshipType"] == "BUILD_TOOL_OF" or (r["relationshipType"] == "STATIC_LINK" and r["relatedSpdxElement"] == "SPDXRef-Package-go-stdlib"):
        print(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
PY
fi

GOVER=$(cd "$ROOT" && go version | awk '{print $3}')
OKS=$((${#rows[@]} - FAIL - SKIP - NOTRUN))
if [ -n "$ASSETS" ]; then SOURCE="주어진 디렉터리(\`$ASSETS\`)의 자산을"; else SOURCE="릴리스에 실제로 붙은 자산을 GitHub에서 내려받아"; fi
mkdir -p "$(dirname "$RECORD")"
{
  echo "# 발행 확인 ($STAMP)"; echo
  echo "$TAG, 커밋 $COMMIT"; echo
  echo "$SOURCE [INSTALL.md](../INSTALL.md)의 「받은 묶음을 확인하기」대로 확인했다. \`tools/release/check.sh\`가 돌렸다. 돌린 자리는 워크플로 밖의 리눅스 머신($(uname -m), $(. /etc/os-release 2>/dev/null && echo "$NAME" || uname -s))이다. \`gh\`는 워크플로가 쓴 것과 같은 판($GH_VERSION${GH_SHA256:+, 체크섬 \`${GH_SHA256:0:8}…\`})을 따로 받아 썼다. \`sbom verify\`는 이 리포의 소스(\`$(git -C "$ROOT" rev-parse --short HEAD)\`)로 돌렸고 그 도구 사슬은 \`go.mod\`가 정한 ${GOVER}이다.${RUN:+ 릴리스 워크플로 실행은 [$RUN](https://github.com/$REPO/actions/runs/$RUN)이다.} 검증에 실패한 묶음은 풀지 않으므로 그 묶음의 뒤 검사는 미실행이다. 건너뜀은 이 머신에서 돌릴 수 없는 아키텍처의 실행 파일이다. 둘 다 통과가 아니다."; echo
  echo "| 결과 | 확인한 것 |"; echo "|---|---|"; printf '%s\n' "${rows[@]}"; echo
  echo "ok $OKS, 틀림 $FAIL, 건너뜀 $SKIP, 미실행 $NOTRUN."; echo
  echo "증명 검증이 찍은 값이다. 차례로 predicate 종류, 서명된 참조, 서명된 커밋, 서명한 워크플로, 러너 환경이다. amd64가 앞, arm64가 뒤다."; echo; echo '```'; cat proof.txt; echo '```'; echo
  echo "묶음 검사가 찍은 줄이다."; echo; echo '```'; sed "s|$WORK/assets/||g" verify.txt; echo '```'; echo
  echo "부품 목록의 값이다. 묶음 Package와 Go의 두 Package, 실행 파일과 \`LICENSE\`와 고지 문서 File의 \`licenseConcluded\`, Go의 두 관계다."; echo; echo '```'; cat sbom.txt; echo '```'; echo
  echo "\`sha256sum.txt\`의 값이다."; echo; echo '```'; cat assets/sha256sum.txt 2>/dev/null || echo "(없음)"; echo '```'
} > "$RECORD"
echo
echo "기록: $RECORD (ok $OKS, 틀림 $FAIL, 건너뜀 $SKIP, 미실행 $NOTRUN)"
[ "$FAIL" = 0 ]
