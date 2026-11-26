#!/usr/bin/env python3
"""netscope 와 tshark(Wireshark CLI) 의 프레임별 필드 값을 대조한다.

사용법: compare_tshark.py NETSCOPE_BINARY FILE.pcap [FILE.pcap ...]

같은 pcap 파일을 tshark 와 `netscope read -v -f all` 로 각각 해석한 뒤,
프레임 번호가 같은 패킷끼리 아래 필드를 비교한다.
  IP: src, dst, ttl, id / UDP·TCP 포트 / TCP stream, 상대 seq·ack, len, window, MSS
  ICMP: type, code, identifier, sequence, checksum 상태 / DNS: transaction id
ICMP 오류 메시지 안에 인용된 원본 헤더는 바깥 헤더와 섞이지 않도록 제외한다.
"""
import re
import subprocess
import sys

FIELDS = ['frame.number', 'frame.len', 'ip.src', 'ip.dst', 'ip.ttl', 'ip.id',
          'udp.srcport', 'udp.dstport', 'tcp.srcport', 'tcp.dstport', 'tcp.stream',
          'tcp.seq', 'tcp.ack', 'tcp.len', 'tcp.window_size_value', 'tcp.options.mss_val',
          'icmp.type', 'icmp.code', 'icmp.ident', 'icmp.seq', 'icmp.checksum.status', 'dns.id']

PATTERNS = [
    ('ip.ttl', r'^Time to Live: (\d+)'),
    ('ip.id', r'^Identification: (0x[0-9a-f]+)'),
    ('ip.src', r'^Source Address: (\S+)'),
    ('ip.dst', r'^Destination Address: (\S+)'),
    ('icmp.type', r'^Type: (\d+) '),
    ('icmp.code', r'^Code: (\d+)'),
    ('icmp.ident', r'^Identifier \(BE\): (\d+)'),
    ('icmp.seq', r'^Sequence Number \(BE\): (\d+)'),
    ('tcp.stream', r'^\[Stream index: (\d+)\]'),
    ('tcp.seq', r'^Sequence Number: (\d+) '),
    ('tcp.ack', r'^Acknowledgment Number: (\d+) '),
    ('tcp.len', r'^\[TCP Segment Len: (\d+)\]'),
    ('tcp.window_size_value', r'^Window: (\d+)'),
    ('tcp.options.mss_val', r'^Maximum segment size: (\d+)'),
    ('dns.id', r'^Transaction ID: (0x[0-9a-f]+)'),
    ('icmp.checksum.status', r'^Checksum: 0x[0-9a-f]+ \[(correct|incorrect)\]'),
]


def parse_netscope(binary, path):
    out = subprocess.run([binary, 'read', '-v', '-f', 'all', path],
                         capture_output=True, env={'NO_COLOR': '1'}).stdout.decode('utf-8', 'replace')
    frames, cur = {}, None
    for line in out.split('\n'):
        m = re.match(r'▾ Frame (\d+): (\d+) bytes on wire', line)
        if m:
            cur = frames.setdefault(int(m.group(1)), {'frame.len': m.group(2), '_inner': False})
            continue
        if cur is None:
            continue
        if line.startswith('    ▾ Internet Protocol'):   # ICMP 오류 안의 원본 헤더 시작
            cur['_inner'] = True
        if cur['_inner']:
            continue
        s = line.strip()
        for key, rx in PATTERNS:
            m = re.match(rx, s)
            if m and key not in cur:
                cur[key] = m.group(1)
        for proto, a, b in (('User Datagram Protocol', 'udp.srcport', 'udp.dstport'),
                            ('Transmission Control Protocol', 'tcp.srcport', 'tcp.dstport')):
            m = re.match(r'^▾ ' + proto + r', Src Port: (\d+), Dst Port: (\d+)', s)
            if m and a not in cur:
                cur[a], cur[b] = m.group(1), m.group(2)
    return frames


def parse_tshark(path):
    cmd = ['tshark', '-r', path, '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=f']
    for f in FIELDS:
        cmd += ['-e', f]
    rows = subprocess.run(cmd, capture_output=True, text=True).stdout.strip().split('\n')
    return [dict(zip(FIELDS, r.split('\t'))) for r in rows if r]


def main():
    binary, files = sys.argv[1], sys.argv[2:]
    failed = 0
    for path in files:
        mine = parse_netscope(binary, path)
        theirs = parse_tshark(path)
        compared, mismatches, examples = 0, 0, []
        for row in theirs:
            no = int(row['frame.number'])
            m = mine.get(no)
            if m is None:
                mismatches += 1
                examples.append(f'frame {no}: netscope 출력에 없음')
                continue
            for key in FIELDS[1:]:
                t = row.get(key, '')
                if not t or key not in m:
                    continue
                if key in ('ip.id', 'dns.id'):
                    t = t.lower()
                if key == 'icmp.checksum.status':
                    t = {'1': 'correct', '0': 'incorrect'}.get(t, t)
                compared += 1
                if m[key] != t:
                    mismatches += 1
                    if len(examples) < 5:
                        examples.append(f'frame {no} {key}: netscope={m[key]} tshark={t}')
        good = mismatches == 0 and len(mine) == len(theirs)
        failed += not good
        name = path.rsplit('/', 1)[-1]
        print(f"  [{'OK' if good else 'FAIL'}]{'   ' if good else ' '} {name:<16} "
              f"프레임 {len(mine)}/{len(theirs)}, 필드 {compared} 개 대조, 불일치 {mismatches}")
        for e in examples:
            print('           ' + e)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
