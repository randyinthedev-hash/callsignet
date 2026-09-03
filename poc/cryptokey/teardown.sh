#!/usr/bin/env bash
# 네임스페이스와 브리지를 지운다. 키는 _work에 남긴다.
source "$(dirname "$0")/common.sh"
need_root "$@"
for ns in $ALL_NS; do ip netns delete "$ns" 2>/dev/null || true; done
ip link delete "$BR" 2>/dev/null || true
echo "정리했습니다."
