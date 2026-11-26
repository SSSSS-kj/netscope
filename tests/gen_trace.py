#!/usr/bin/env python3
"""합성 traceroute pcap 생성 (과제 설명서 첨부 3 의 예시와 같은 5홉 구성).

사용법: gen_trace.py OUT.pcap
OUT.pcap 과 함께 traceroute 출력 OUT.pcap.txt 를 만든다.
`netscope read OUT.pcap` 으로 traceroute 분석기를 실제 다중 홉 환경 없이 검증할 수 있다.

구성: 출발지 192.168.0.89 → 192.168.0.1 → 210.93.61.254 → 10.1.5.5 → 10.1.8.6 → 210.93.57.50
TTL 1~5 는 3개씩, TTL 6 은 1개 (Linux traceroute 처럼 16개 프로브를 한꺼번에 보냄)
"""
import random
import struct
import sys

SRC, DST = '192.168.0.89', '210.93.57.50'
HOPS = {1: '192.168.0.1', 2: '210.93.61.254', 3: '10.1.5.5', 4: '10.1.8.6'}
RTT = {1: 0.0005, 2: 0.0024, 3: 0.0023, 4: 0.0024, 5: 0.0022, 6: 0.0022}
OUTPUT = """traceroute to 210.93.57.50 (210.93.57.50), 30 hops max, 60 byte packets
 1  192.168.0.1 (192.168.0.1)  0.494 ms  0.539 ms  0.611 ms
 2  210.93.61.254 (210.93.61.254)  2.453 ms  2.446 ms  2.426 ms
 3  10.1.5.5 (10.1.5.5)  2.375 ms  2.362 ms  2.347 ms
 4  10.1.8.6 (10.1.8.6)  2.327 ms  2.489 ms  2.474 ms
 5  210.93.57.50 (210.93.57.50)  2.239 ms  2.187 ms  2.166 ms
"""


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(a):
    return bytes(map(int, a.split('.')))


def ip_packet(src, dst, proto, ttl, payload, ident):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def eth(payload, outgoing):
    a, b = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'
    return (b + a if outgoing else a + b) + b'\x08\x00' + payload


def main():
    out = sys.argv[1]
    random.seed(1)
    t, dport, frames, probes = 1700000000.673, 33434, [], []
    for ttl in range(1, 7):
        for _ in range(3 if ttl < 6 else 1):
            udp = struct.pack('!HHHH', random.randint(32768, 60999), dport, 40, 0) + bytes(range(0x40, 0x60))
            pkt = ip_packet(SRC, DST, 17, ttl, udp, random.randint(1, 65535))
            frames.append((t, eth(pkt, True)))
            probes.append((t, ttl, pkt))
            t += 0.00002
            dport += 1
    for pt, ttl, pkt in probes:
        # 라우터에 도착했을 때의 원본 IP 헤더(TTL 1) + UDP 헤더 8바이트를 인용
        quoted = bytearray(pkt[:28])
        quoted[8] = 1
        quoted[10:12] = b'\0\0'
        quoted[10:12] = struct.pack('!H', csum(bytes(quoted[:20])))
        src, typ, code = (HOPS[ttl], 11, 0) if ttl in HOPS else (DST, 3, 3)
        body = bytearray(struct.pack('!BBHI', typ, code, 0, 0) + bytes(quoted))
        body[2:4] = struct.pack('!H', csum(bytes(body)))
        resp = ip_packet(src, SRC, 1, 64 - ttl, bytes(body), random.randint(1, 65535))
        frames.append((pt + RTT[ttl] + random.random() * 0.0002, eth(resp, False)))
    frames.sort(key=lambda f: f[0])
    with open(out, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack('<IIII', int(ts), int(round((ts % 1) * 1e9)) % 1000000000, len(fr), len(fr)) + fr)
    with open(out + '.txt', 'w') as f:
        f.write('# netscope run\n# cmd: traceroute 210.93.57.50\n# analyzer: traceroute\n'
                '# start: 1700000000.600000000\n' + OUTPUT)


if __name__ == '__main__':
    main()
