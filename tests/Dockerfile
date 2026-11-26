# 검증용 Ubuntu 환경 (tests/run_docker.sh 에서 사용)
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential python3 tshark iputils-ping traceroute dnsutils curl net-tools >/dev/null \
    && rm -rf /var/lib/apt/lists/*
