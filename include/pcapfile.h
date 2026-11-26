/*
 * pcapfile.h - pcap 파일 저장/읽기 (Wireshark 에서 열어 검증하는 용도)
 *
 * 저장 형식: pcap (나노초 타임스탬프, magic 0xa1b23c4d), 링크 타입 Ethernet
 * 읽기 지원: 마이크로초/나노초 pcap, 링크 타입 Ethernet / Linux cooked(SLL)
 * pcapng 는 지원하지 않음 → Wireshark 에서 "다른 이름으로 저장 > pcap" 으로 변환
 */
#ifndef NETSCOPE_PCAPFILE_H
#define NETSCOPE_PCAPFILE_H

#include <stdio.h>
#include <stddef.h>
#include "packet.h"

typedef struct {
    FILE *fp;
    char  path[512];
    long  count;
} pcap_writer_t;

typedef struct {
    FILE *fp;
    int   nsec;      /* 1 = 나노초 타임스탬프 */
    int   swapped;   /* 1 = 바이트 순서 반대 */
    int   linktype;
} pcap_reader_t;

int  pcapw_open(pcap_writer_t *w, const char *path);
int  pcapw_write(pcap_writer_t *w, const rawpkt_t *r);
void pcapw_close(pcap_writer_t *w);

int  pcapr_open(pcap_reader_t *rd, const char *path, char *err, size_t errlen);
int  pcapr_next(pcap_reader_t *rd, rawpkt_t *r, uint8_t *buf, size_t buflen); /* 1 / 0(EOF) / -1 */
void pcapr_close(pcap_reader_t *rd);

#endif
