# netscope 검증

프로그램이 정상 동작하는지 한 번에 확인하는 스크립트 모음.

## 실행

```sh
# 리눅스(Ubuntu VM)에서 직접
sudo apt install -y build-essential python3 tshark iputils-ping traceroute dnsutils curl net-tools
sudo tests/verify.sh              # 또는 make check
sudo tests/verify.sh --offline    # 인터넷 없이 가능한 항목만

# Docker 가 있는 환경에서
tests/run_docker.sh
```

검증용 바이너리는 임시 폴더에 따로 빌드하므로 저장소의 `netscope` 파일에는 영향이 없음.

## 검증 항목

| 번호 | 항목 | 확인 내용 |
|---|---|---|
| 1 | 빌드 | AddressSanitizer·UndefinedBehaviorSanitizer 를 켜고 `-Wall -Wextra` 로 빌드, 경고 0 |
| 2 | run 모드 | ping, traceroute, nslookup(정방향·역방향), curl(http·https), netstat+소켓 추적이 정상 분석되고 명령어 출력과 대조 결과가 일치 |
| 3 | read 모드 | 저장한 pcap 을 다시 읽어 같은 연동 분석, 상세 트리·hex 덤프 출력 |
| 4 | 신호 처리 | 명령어 실행 중 Ctrl+C → 명령어에 전달되어 통계 출력 후 분석, capture 모드 `-c` 와 Ctrl+C 종료 |
| 5 | 잘못된 입력 | 없는 인터페이스·파일·명령어, pcapng 파일, 잘못된 필터 식을 안내 메시지와 함께 거부 |
| 6 | 합성 traceroute | 과제 설명서 예시와 같은 5홉 구성의 패킷을 만들어 홉 표·출력 대조·해석 확인 (`gen_trace.py`) |
| 7 | 퍼징 | 실제 캡처 프레임을 자르거나 변조한 4000 개 프레임을 모든 분석기에 입력, 비정상 종료·메모리 오류 없음 (`gen_fuzz.py`) |
| 8 | tshark 대조 | 같은 pcap 을 tshark 와 netscope 로 해석해 프레임 수와 필드 값(IP·UDP·TCP·ICMP·DNS)이 모두 같은지 비교 (`compare_tshark.py`) |

2~4 번과 8 번 일부는 인터넷 연결(1.1.1.1, example.com)이 필요함.
각 항목 앞에 `[OK]` / `[FAIL]` / `[SKIP]` 이 붙고, 마지막 줄에 실패 건수가 나옴.

## 결과 예

```
== 1. 빌드 (ASan/UBSan)
  [OK]   빌드 성공, 경고 0 개
== 2. run 모드
  [OK]   ping
  [OK]   traceroute
  ...
== 8. tshark 필드 대조
  [OK]    ping.pcap        프레임 10/10, 필드 55 개 대조, 불일치 0
  [OK]    curl.pcap        프레임 15/15, 필드 166 개 대조, 불일치 0
  ...
== 결과: 실패 0 건
```
