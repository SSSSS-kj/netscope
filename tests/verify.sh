#!/bin/sh
# netscope 검증 스크립트
#
#   sudo tests/verify.sh            전체 검증
#   sudo tests/verify.sh --offline  네트워크가 필요한 항목(run 모드 측정) 제외
#
# 검증 항목
#   1. AddressSanitizer/UndefinedBehaviorSanitizer 를 켠 빌드 (경고 0 확인)
#   2. run 모드: ping, traceroute, nslookup(정방향·역방향), curl(http·https), netstat+소켓 추적
#   3. read 모드: 저장 파일 재분석 (.txt 자동 사용), 상세 트리·hex 덤프
#   4. Ctrl+C(SIGINT) 처리, capture 모드 종료 조건
#   5. 잘못된 입력 처리 (없는 인터페이스·파일·명령어, pcapng, 잘못된 필터)
#   6. 합성 traceroute (설명서 예시와 같은 5홉 구성) 분석 결과
#   7. 퍼징: 잘리거나 변조된 프레임 4000 개를 모든 분석기에 입력 (중단·메모리 오류 없어야 함)
#   8. tshark(Wireshark CLI) 와 프레임별 필드 값 대조
#
# 필요 패키지: build-essential python3 tshark iputils-ping traceroute dnsutils curl net-tools

set -u
TESTS=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$TESTS")
OFFLINE=0
[ "${1:-}" = "--offline" ] && OFFLINE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "root 권한 필요: sudo tests/verify.sh" >&2
    exit 2
fi
for c in gcc make python3 tshark; do
    command -v $c >/dev/null 2>&1 || { echo "'$c' 가 필요함 (tests/README.md 참고)" >&2; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
R=$WORK/results
mkdir -p "$R"
export NO_COLOR=1
# 측정 명령어를 일반 사용자 권한으로 실행하도록 sudo 정보가 없으면 nobody 로 지정
[ -z "${SUDO_UID:-}" ] && export SUDO_UID=65534 SUDO_GID=65534

FAIL=0
ok()   { echo "  [OK]   $1"; }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  [SKIP] $1"; }
san()  {
    if grep -qE "ERROR: AddressSanitizer|runtime error:|LeakSanitizer" "$1"; then
        bad "$2: sanitizer 경고"
        grep -E "ERROR|runtime error|SUMMARY" "$1" | head -5
    fi
}

echo "== 1. 빌드 (ASan/UBSan)"
cp -r "$ROOT/src" "$ROOT/include" "$ROOT/Makefile" "$WORK/"
(cd "$WORK" && make CFLAGS="-O1 -g -Wall -Wextra -std=gnu11 -fsanitize=address,undefined -fno-omit-frame-pointer" >build.log 2>&1)
if [ -x "$WORK/netscope" ]; then
    ok "빌드 성공, 경고 $(grep -c 'warning' "$WORK/build.log") 개"
else
    bad "빌드 실패"; cat "$WORK/build.log"; exit 1
fi
NS=$WORK/netscope
export ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1

if [ $OFFLINE -eq 0 ] && ! ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
    echo "  (1.1.1.1 에 연결할 수 없어 네트워크 항목은 건너뜀)"
    OFFLINE=1
fi

echo "== 2. run 모드"
if [ $OFFLINE -eq 1 ]; then
    skip "네트워크 측정 항목"
else
    $NS run -w $R/ping.pcap -- ping -c 3 1.1.1.1 >$WORK/o 2>&1
    grep -q "\[2\] 통계 대조" $WORK/o && ok "ping" || bad "ping"; san $WORK/o ping

    $NS run -w $R/trace.pcap -- traceroute -q 2 -m 4 1.1.1.1 >$WORK/o 2>&1
    grep -q "traceroute 출력과 대조" $WORK/o && ok "traceroute" || bad "traceroute"; san $WORK/o traceroute

    $NS run -w $R/dns.pcap -- nslookup www.google.com >$WORK/o 2>&1
    grep -q "수집한 DNS 응답과 일치" $WORK/o && ok "nslookup" || bad "nslookup"; san $WORK/o nslookup

    $NS run -w $R/ptr.pcap -- nslookup 8.8.8.8 >$WORK/o 2>&1
    grep -q "PTR 레코드 있음 O" $WORK/o && ok "nslookup 역방향(PTR)" || bad "nslookup PTR"; san $WORK/o ptr

    $NS run -w $R/curl.pcap -- curl -v -o /dev/null http://example.com >$WORK/o 2>&1
    n=$(grep -c "일치 O" $WORK/o)
    [ "$n" -ge 3 ] && ok "curl http (curl -v 대조 일치 $n 건)" || bad "curl http"; san $WORK/o curl

    $NS run -w $R/https.pcap -- curl -s -o /dev/null https://example.com >$WORK/o 2>&1
    grep -q "TCP 스트림" $WORK/o && ok "curl https (TLS)" || bad "curl https"; san $WORK/o https

    $NS run -a netstat -S -w $R/netstat.pcap -- sh -c "curl -s -o /dev/null http://example.com; netstat -tn" >$WORK/o 2>&1
    grep -q "netstat 상태 TIME_WAIT: 일치 O" $WORK/o && ok "netstat + 소켓 상태 추적" || bad "netstat"; san $WORK/o netstat
fi

echo "== 3. read 모드"
if [ $OFFLINE -eq 1 ]; then
    skip "read 재분석 (run 결과 필요)"
else
    for f in ping trace dns curl netstat; do
        $NS read $R/$f.pcap >$WORK/o 2>&1
        grep -q "명령어 연동 분석" $WORK/o && ok "read $f.pcap (.txt 자동 사용)" || bad "read $f"; san $WORK/o "read $f"
    done
    $NS read -v -x -f all $R/curl.pcap >$WORK/o 2>&1 && ok "read -v -x -f all" || bad "read -v -x"; san $WORK/o "read -v -x"
fi

echo "== 4. 신호와 종료 조건"
if [ $OFFLINE -eq 1 ]; then
    skip "Ctrl+C 처리"
else
    timeout -s INT 3 $NS run -- ping 1.1.1.1 >$WORK/o 2>&1
    grep -q "packets transmitted" $WORK/o && grep -q "\[2\] 통계 대조" $WORK/o \
        && ok "run 중 Ctrl+C → 명령어에 전달, ping 통계와 분석 출력" || bad "run Ctrl+C"; san $WORK/o sigint
    (sleep 1; ping -c 3 1.1.1.1 >/dev/null) &
    $NS capture -c 2 -f icmp >$WORK/o 2>&1
    wait
    [ "$(grep -c Echo $WORK/o)" -eq 2 ] && ok "capture -c 2" || bad "capture -c"
fi
timeout -s INT 2 $NS capture -f icmp >$WORK/o 2>&1
grep -q "개 패킷 수집" $WORK/o && ok "capture 모드 Ctrl+C 종료" || bad "capture Ctrl+C"

echo "== 5. 잘못된 입력"
$NS run -i nosuchif0 -- true >$WORK/o 2>&1;  grep -q "찾을 수 없음" $WORK/o && ok "없는 인터페이스" || bad "없는 인터페이스"
$NS read /nonexistent.pcap >$WORK/o 2>&1;    [ $? -ne 0 ] && ok "없는 파일" || bad "없는 파일"
printf '\n\r\r\n00000000000000000000000000000000' >$WORK/x.pcapng
$NS read $WORK/x.pcapng >$WORK/o 2>&1;       grep -q pcapng $WORK/o && ok "pcapng 형식 안내" || bad "pcapng"
$NS run -- nosuchcommand >$WORK/o 2>&1;      [ $? -eq 127 ] && ok "없는 명령어 (exit 127)" || bad "없는 명령어"
$NS >/dev/null 2>&1;                         [ $? -eq 2 ] && ok "인자 없음 (exit 2)" || bad "인자 없음"
for fx in "host" "port 99999" "(icmp" "icmp and" "foo"; do
    $NS read -f "$fx" /nonexistent.pcap >$WORK/o 2>&1
    grep -q "필터 오류" $WORK/o && ok "잘못된 필터 \"$fx\" 거부" || bad "필터 \"$fx\""
    san $WORK/o "filter $fx"
done

echo "== 6. 합성 traceroute (5홉)"
python3 "$TESTS/gen_trace.py" $R/synth_trace.pcap
$NS read $R/synth_trace.pcap >$WORK/o 2>&1
grep -q "5 개 홉 중 5 개 일치" $WORK/o && grep -q "중간 라우터 4 개 경유" $WORK/o \
    && ok "홉 5개 일치, 중간 라우터 4개" || bad "합성 traceroute"; san $WORK/o synth

echo "== 7. 퍼징"
python3 "$TESTS/gen_fuzz.py" $R/fuzz.pcap $R/*.pcap
for a in "" "-a ping" "-a traceroute" "-a nslookup" "-a curl" "-a netstat"; do
    $NS read -v -x -f all $a $R/fuzz.pcap >$WORK/o 2>&1
    e=$?
    if [ $e -eq 0 ] && ! grep -qE "ERROR: AddressSanitizer|runtime error:|LeakSanitizer" $WORK/o; then
        ok "변조 프레임 입력 ${a:-(분석기 없음)}: 정상 종료, 메모리 오류 없음"
    else
        bad "퍼징 $a (exit $e)"; san $WORK/o "fuzz $a"
    fi
done

echo "== 8. tshark 필드 대조"
python3 "$TESTS/compare_tshark.py" "$NS" $(ls $R/*.pcap | grep -v fuzz.pcap) || FAIL=$((FAIL + 1))

echo
echo "== 결과: 실패 $FAIL 건"
[ $FAIL -eq 0 ]
