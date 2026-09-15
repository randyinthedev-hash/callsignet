#!/usr/bin/env bash
# SBOM을 만든 프로그램과 무관한 도구로 SPDX 2.3의 형식을 검사한다.
#
#   tools/sbom/check-independent.sh <sbom.spdx.json 또는 묶음 디렉터리>…
#
# 디렉터리를 주면 그 안의 sbom.spdx.json을 본다. dist/pack.sh의 PACK_HOOK 자리에
# 그대로 들어간다.
#
# 둘을 돌린다. 공식 SPDX 2.3 JSON 스키마로 보는 스키마 검사와, SPDX 프로젝트의
# 검증 도구(spdx-tools)로 보는 의미 검사다. 같은 프로그램이 만들고 같은 해석으로
# 검사하면 구조를 잘못 이해한 결함이 양쪽에 남는다. 그래서 이것을 따로 둔다.
#
# 스키마는 spdx-spec 리포의 v2.3 태그가 가리키는 커밋에서 받고 sha256을 본다.
# 파이썬 꾸러미는 requirements.txt에 판과 해시를 고정해 두었다. 러너의 파이썬
# 3.12로 가상 환경을 만든다.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_COMMIT=aadf3b0b8dbbabdb4d880b0fc714255fea436ff7   # spdx/spdx-spec 태그 v2.3
SCHEMA_SHA256=239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b
WORK="${SBOM_CHECK_WORK:-$HERE/_work}"

[ "$#" -ge 1 ] || { echo "사용법: $0 <sbom.spdx.json>…" >&2; exit 2; }

# hash256은 파일의 SHA-256을 찍는다. 리눅스의 sha256sum과 macOS의 shasum 둘 다 본다.
hash256() {
  if command -v sha256sum >/dev/null 2>&1 && sha256sum --version >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

mkdir -p "$WORK"
schema="$WORK/spdx-schema.json"
if [ ! -f "$schema" ] || [ "$(hash256 "$schema")" != "$SCHEMA_SHA256" ]; then
  curl -fsSL -o "$schema.part" "https://raw.githubusercontent.com/spdx/spdx-spec/$SCHEMA_COMMIT/schemas/spdx-schema.json"
  got=$(hash256 "$schema.part")
  if [ "$got" != "$SCHEMA_SHA256" ]; then
    echo "SPDX 스키마의 해시가 다릅니다. 기대 $SCHEMA_SHA256, 받음 $got" >&2
    rm -f "$schema.part"
    exit 1
  fi
  mv "$schema.part" "$schema"
fi
# 가상 환경은 python3 -m venv로 만든다. ensurepip이 없는 머신(개발 머신)에서는
# uv가 있으면 그것으로 만든다. 어느 쪽이든 requirements.txt의 해시를 본다.
if [ ! -x "$WORK/venv/bin/pyspdxtools" ]; then
  rm -rf "$WORK/venv"
  if python3 -m venv "$WORK/venv" 2>/dev/null && [ -x "$WORK/venv/bin/pip" ]; then
    "$WORK/venv/bin/pip" install --quiet --require-hashes --no-deps -r "$HERE/requirements.txt"
  elif command -v uv >/dev/null 2>&1; then
    rm -rf "$WORK/venv"
    uv venv -q "$WORK/venv" --python 3.12
    VIRTUAL_ENV="$WORK/venv" uv pip install -q --require-hashes -r "$HERE/requirements.txt"
  else
    echo "python3 -m venv가 되지 않고 uv도 없습니다. python3-venv를 설치하십시오." >&2
    exit 1
  fi
fi

for f in "$@"; do
  [ -d "$f" ] && f="$f/sbom.spdx.json"
  "$WORK/venv/bin/python" - "$schema" "$f" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
jsonschema.Draft7Validator(schema).validate(doc)
print("스키마 검사를 지났습니다:", sys.argv[2])
PY
  "$WORK/venv/bin/pyspdxtools" --infile "$f"
  echo "의미 검사를 지났습니다: $f"
done
