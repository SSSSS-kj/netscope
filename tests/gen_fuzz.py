#!/usr/bin/env python3
"""퍼징용 pcap 생성: 실제 캡처 프레임을 잘라내거나 무작위로 변조한다.

사용법: gen_fuzz.py OUT.pcap IN.pcap [IN.pcap ...]
입력 파일이 없으면 무작위 바이트 프레임만 만든다.
"""
import random
import struct
import sys

COUNT = 4000


def read_frames(path):
    try:
        data = open(path, 'rb').read()
    except OSError:
        return []
    if len(data) < 24:
        return []
    frames, i = [], 24
    while i + 16 <= len(data):
        _, _, incl, _ = struct.unpack('<IIII', data[i:i + 16])
        frames.append(data[i + 16:i + 16 + incl])
        i += 16 + incl
    return frames


def main():
    out_path, inputs = sys.argv[1], sys.argv[2:]
    random.seed(7)
    frames = [f for p in inputs if p != out_path for f in read_frames(p) if f]
    with open(out_path, 'wb') as out:
        out.write(struct.pack('<IHHiIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        for n in range(COUNT):
            mode = random.randint(0, 3) if frames else 3
            f = bytearray(random.choice(frames)) if frames else bytearray()
            if mode == 0:                                   # 임의 길이로 자르기
                f = f[:random.randint(0, len(f))]
            elif mode == 1:                                 # 임의 바이트 변조
                for _ in range(random.randint(1, 8)):
                    f[random.randrange(len(f))] = random.randrange(256)
            elif mode == 2:                                 # 헤더 이후 2바이트 변조 (길이·포트 필드 등)
                k = random.randrange(14, max(15, len(f)))
                f[k:k + 2] = bytes([random.randrange(256), random.randrange(256)])
            else:                                           # 완전 무작위
                f = bytearray(random.getrandbits(8) for _ in range(random.randint(0, 200)))
            out.write(struct.pack('<IIII', 1700000000 + n, 0, len(f), len(f)) + bytes(f))
    print(f'    변조 프레임 {COUNT} 개 생성 (원본 프레임 {len(frames)} 개 기반)')


if __name__ == '__main__':
    main()
