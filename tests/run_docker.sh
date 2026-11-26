#!/bin/sh
# Docker 컨테이너(Ubuntu 24.04)에서 tests/verify.sh 실행
#   tests/run_docker.sh [--offline]
# 컨테이너 안에서는 root 로 실행되며, raw socket 수집에 필요한 NET_RAW 권한은 Docker 기본값에 포함됨.
# 참고: Docker 의 NAT 때문에 traceroute 는 첫 홉 이후 응답이 없을 수 있음 (합성 traceroute 로 따로 검증).
set -e
TESTS=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$TESTS")
docker build -q -t netscope-verify "$TESTS" >/dev/null
docker run --rm -v "$ROOT":/netscope:ro netscope-verify sh /netscope/tests/verify.sh "$@"
