/*
 * capture.h - AF_PACKET raw socket 을 이용한 실시간 패킷 수집
 */
#ifndef NETSCOPE_CAPTURE_H
#define NETSCOPE_CAPTURE_H

#include <stddef.h>
#include <stdint.h>
#include "packet.h"

typedef struct {
    int  fd;
    int  ifindex;      /* 0 = 전체 인터페이스 */
    char ifname[32];
} capture_t;

/* ifname 이 NULL 이면 전체 인터페이스. 실패 시 -1 과 err 메시지 */
int  capture_open(capture_t *c, const char *ifname, char *err, size_t errlen);

/* 수신 대기 중인 패킷 1개 읽기 (비차단). 1 = 수신, 0 = 없음/무시, -1 = 오류 */
int  capture_recv(capture_t *c, rawpkt_t *r, uint8_t *buf, size_t buflen);

/* timeout_ms 동안 기다렸다가 1개 읽기. 반환값은 capture_recv 와 같음 */
int  capture_next(capture_t *c, rawpkt_t *r, uint8_t *buf, size_t buflen, int timeout_ms);

void capture_close(capture_t *c);

#endif
