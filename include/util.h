/*
 * util.h - 바이트 읽기, 체크섬, 주소 문자열 변환 등 공용 함수
 */
#ifndef NETSCOPE_UTIL_H
#define NETSCOPE_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "packet.h"

/* 네트워크 바이트 순서(빅 엔디언) 읽기 */
static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* 인터넷 체크섬 (RFC 1071). 체크섬 필드를 포함해 계산한 결과가 0 이면 정상 */
uint32_t cksum_add(uint32_t sum, const uint8_t *d, uint32_t n);
uint16_t cksum_fold(uint32_t sum);
uint16_t inet_cksum(const uint8_t *d, uint32_t n);

const char *addr_s(const addr_t *a);          /* 순환 정적 버퍼 사용 */
const char *mac_s(const uint8_t m[6]);
int         addr_eq(const addr_t *a, const addr_t *b);
int         addr_parse(const char *s, addr_t *out);

double ts_sub(const struct timespec *a, const struct timespec *b);  /* a - b (초) */
void   fmt_localtime(const struct timespec *ts, char *buf, size_t n);

/* 한글(폭 2)을 고려한 왼쪽 정렬 출력 */
int  str_width(const char *s);
void put_col(const char *s, int width);

int  use_color(void);
void chown_to_sudo_user(const char *path);
void drop_privileges(void);

#endif
