# netscope

컴퓨터네트워크 과제용 패킷 수집·분석 프로그램.
C 언어와 Linux AF_PACKET raw socket으로 패킷을 직접 수집하고 계층별 헤더를 직접 해석함 (libpcap 미사용).

명령어를 실행하는 동안 패킷을 수집하고, 끝나면 **명령어 출력과 수집한 패킷을 자동으로 대조**해 줌.

---

## 1. 설치

```sh
sudo apt update
sudo apt install -y build-essential git iputils-ping traceroute dnsutils curl net-tools wireshark
git clone https://github.com/SSSSS-kj/netscope.git
cd netscope
make
```

`./netscope` 파일이 생기면 성공. 코드가 바뀌면 `git pull && make` 로 갱신.

---

## 2. 측정 가이드

모든 측정은 `netscope` 폴더에서 실행. 결과는 `results/` 폴더에 모음.

```sh
mkdir -p results
```

`run` 모드 실행 순서:
1. 패킷 수집을 시작함
2. `--` 뒤의 명령어를 실행함 (명령어 출력은 화면에 그대로 나옴)
3. 명령어가 끝나면 1초 더 수집함
4. **수집 패킷 목록**과 **명령어 연동 분석**을 출력함

`-w 파일.pcap` 을 주면 패킷은 `파일.pcap`, 명령어 출력은 `파일.pcap.txt` 로 저장됨.

### 2-1. ping

```sh
sudo ./netscope run -w results/ping.pcap -- ping -c 5 1.1.1.1
```

분석 출력:
- [1] seq별 요청·응답 프레임 번호, TTL, RTT(패킷 기준 / ping 출력) 비교
- [2] 송신·수신·손실률, rtt min/avg/max/mdev 비교
- [3] 해석: Identifier/Sequence, TTL로 거친 라우터 수 추정

Wireshark 필터: `icmp`

### 2-2. traceroute

```sh
sudo ./netscope run -w results/trace.pcap -- traceroute 1.1.1.1
```

분석 출력:
- [1] 홉별 UDP 프로브 ↔ ICMP 응답(TTL exceeded / Port unreachable) 짝짓기, 응답 라우터, RTT
- [2] traceroute 출력의 홉별 주소와 비교 (O/X)
- [3] 해석: 응답 안에 인용된 원본 TTL, 목적지 도달 홉, 응답 없는 홉(*)

Wireshark 필터: `ip.addr==1.1.1.1`, 프로브 1개만 보기는 `ip.addr==1.1.1.1 && udp.port==33434`

> 2번 홉부터 모두 `* * *` 이면 VM 네트워크가 NAT라서 생기는 현상일 수 있음. VM 설정에서 네트워크를 **브리지(Bridged)** 로 바꾸고 다시 측정해 볼 것.

### 2-3. nslookup

```sh
sudo ./netscope run -w results/dns.pcap -- nslookup www.tukorea.ac.kr
sudo ./netscope run -w results/dns_ptr.pcap -- nslookup 8.8.8.8
```

분석 출력:
- [1] 질의 ↔ 응답 짝짓기 (Transaction ID, 서버, 질의 타입, 응답 시간, 응답 레코드)
- [2] 로컬 스텁(127.0.0.53, systemd-resolved) → 상위 DNS 로 이어지는 과정 (해당될 때)
- [3] nslookup 출력의 Server, Address, canonical name, name = 줄과 응답 레코드 비교
- [4] 해석

Wireshark 필터: `dns`

### 2-4. curl

```sh
sudo ./netscope run -w results/curl.pcap -- curl -v -o /dev/null http://example.com
```

- 반드시 `http://` 로 측정할 것 (`https://` 는 암호화되어 HTTP 내용이 안 보임)
- `-v` 를 붙여야 curl 출력과 패킷을 줄 단위로 대조할 수 있음

분석 출력:
- [0] 연결 전 DNS 질의
- [1] TCP 스트림별 세그먼트 목록 (연결 설정 / 데이터 전송 / 연결 종료 단계, 상대 Seq·Ack, 설명)
  - 요약: 핸드셰이크 RTT, MSS, 전송 바이트, 먼저 FIN 을 보낸 쪽, 양쪽 소켓의 최종 상태
- [2] curl -v 출력(Connected to, > GET, < HTTP/1.1 200, left intact)과 패킷 대조

Wireshark 필터: `tcp.port==80`, 흐름도는 Statistics → Flow Graph

### 2-5. netstat

netstat 은 패킷을 만들지 않으므로, curl 로 연결을 만든 직후에 netstat 을 실행해서 연계함.

```sh
sudo ./netscope run -a netstat -S -w results/netstat.pcap -- sh -c "curl -s -o /dev/null http://example.com; netstat -tn"
```

- `-a netstat` : netstat 분석기 사용
- `-S` : 수집하는 동안 커널 소켓 표(/proc/net/tcp)를 계속 읽어 상태 변화를 기록

분석 출력:
- [1] netstat 출력의 각 연결 ↔ 같은 포트의 TCP 스트림, 패킷으로 추정한 상태와 netstat 상태 비교
- [2] 해석 (TIME_WAIT 이 남는 이유 등)
- 소켓 상태 변화 타임라인: `ESTABLISHED → FIN_WAIT1 → TIME_WAIT` 와 SYN/FIN 패킷 시각을 나란히 표시

---

## 3. Wireshark 로 검증하는 방법

프로그램이 맞게 동작하는지 Wireshark 로 확인해야 함 (과제 필수 항목).

1. **저장 파일 비교**: `results/xxx.pcap` 을 Wireshark 로 열면 프레임 번호(No.)가 netscope 출력과 같음.
   같은 번호의 패킷을 골라 주소, 포트, TTL, Seq/Ack, ICMP id/seq 등이 같은지 비교
2. **동시 캡처 비교**: Wireshark 를 `any` 인터페이스로 캡처하는 상태에서 netscope 측정을 실행하고,
   같은 필터를 적용했을 때 패킷 수와 필드 값이 같은지 비교
3. 상세 화면 비교: netscope 에 `-v` 를 붙이면 Wireshark 패킷 상세 창과 같은 형식의 트리가 나옴

```sh
sudo ./netscope run -v -w results/ping_v.pcap -- ping -c 2 1.1.1.1    # 상세 트리
sudo ./netscope run -x -- ping -c 1 1.1.1.1                           # hex 덤프
```

---

## 4. 저장한 결과 다시 보기

```sh
./netscope read results/ping.pcap                  # 같은 패킷 목록 + 같은 연동 분석 (ping.pcap.txt 자동 사용)
./netscope read -v -f "icmp" results/ping.pcap     # 상세 트리
./netscope read -f "udp port 33434 or icmp" results/trace.pcap
```

---

## 5. 측정 후 보낼 것

- `results/` 폴더 전체 (pcap + txt)
- netscope 실행 화면 캡처 (명령어별 패킷 목록, 연동 분석 [1]~[3])
- 같은 패킷의 Wireshark 화면 캡처 (검증용)

---

## 6. 문제 해결

| 증상 | 해결 |
|---|---|
| `socket(AF_PACKET) 실패` | `sudo` 를 붙여서 실행 |
| `명령어 실행 실패: traceroute` | `sudo apt install traceroute` (netstat 은 `net-tools`, nslookup 은 `dnsutils`) |
| traceroute 2번 홉부터 `*` | VM 네트워크를 브리지 모드로 변경 |
| 색이 깨짐 / 파일로 저장 | `NO_COLOR=1 sudo -E ./netscope ...` 또는 `... | tee 결과.txt` |
| 다른 프로그램 패킷이 섞임 | `-f` 로 필터 지정. 예) `-f "host 1.1.1.1"` |

---

## 7. 명령어 사용법 요약

```
sudo ./netscope capture [-i IF] [-f FILTER] [-c N] [-w FILE] [-v] [-x]
sudo ./netscope run     [-i IF] [-f FILTER] [-w FILE] [-a NAME] [-g MS] [-S] [-v] [-x] -- COMMAND ...
     ./netscope read    [-f FILTER] [-a NAME] [-c N] [-w FILE] [-v] [-x] FILE.pcap
```

| 옵션 | 의미 |
|---|---|
| `-i IF` | 수집 인터페이스 (기본: 전체) |
| `-f FILTER` | 필터. `all`(전체 표시), `icmp`, `icmpv6`, `udp`, `tcp`, `dns`, `http`, `arp`, `ip`, `ip6`, `host A`, `src A`, `dst A`, `port N`, `and`/`or`/`not`, 괄호 |
| `-c N` | N개 표시 후 종료 |
| `-w FILE` | pcap 저장 (run 모드는 명령어 출력도 FILE.txt 로 저장) |
| `-a NAME` | 분석기 지정: ping, traceroute, nslookup, curl, netstat |
| `-v` / `-x` | 계층별 상세 트리 / hex 덤프 |
| `-g MS` | run: 명령어 종료 후 추가 수집 시간 (기본 1000) |
| `-S` | run: 소켓 상태(/proc/net/tcp) 추적 |

host/port 필터는 Wireshark `ip.addr`, `udp.port` 처럼 ICMP 오류 메시지에 인용된 원본 주소·포트도 포함함.

---

## 8. 구조

```
include/              헤더
src/main.c            명령행 처리, capture / read 모드
src/runcmd.c          run 모드 (forkpty + poll 로 수집과 명령어 실행을 동시에 처리)
src/capture.c         AF_PACKET raw socket 수집, 커널 타임스탬프(SO_TIMESTAMPNS)
src/pcapfile.c        pcap 저장/읽기
src/decode.c          계층별 디코더 호출 순서
src/proto_eth.c       Ethernet II, Linux cooked, ARP
src/proto_ip.c        IPv4, IPv6
src/proto_icmp.c      ICMP, ICMPv6 (오류 메시지 안의 원본 헤더 포함)
src/proto_udp.c       UDP
src/proto_dns.c       DNS (이름 압축 포인터 처리)
src/proto_tcp.c       TCP 헤더·옵션, 스트림별 상대 순서번호
src/proto_http.c      HTTP/1.x
src/filter.c          필터 식 파서(재귀 하강)
src/output.c          요약 목록, 상세 트리, hex 덤프
src/store.c           수집 패킷 보관
src/analyze.c         분석기 선택, 일반 통계
src/analyze_ping.c    ping ↔ ICMP Echo
src/analyze_trace.c   traceroute ↔ UDP 프로브 / ICMP 오류
src/analyze_dns.c     nslookup ↔ DNS
src/analyze_tcp.c     curl ↔ TCP / HTTP
src/analyze_netstat.c netstat ↔ TCP 연결 상태
src/sockwatch.c       /proc/net/tcp 소켓 상태 추적
```

## 9. 검증

`tests/` 폴더의 스크립트로 빌드·동작·안정성·Wireshark(tshark) 대조를 한 번에 검증할 수 있음.

```sh
sudo tests/verify.sh          # 리눅스(VM)에서 직접 실행
tests/run_docker.sh           # Docker 컨테이너에서 실행
```

자세한 내용은 [tests/README.md](tests/README.md) 참고.

## 10. 제출용 압축

```sh
make dist    # ../netscope-src.zip (소스, 검증 스크립트 포함 / 빌드 산출물, pcap 제외)
```
