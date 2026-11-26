/*
 * output.h - 요약 목록, 상세 트리, hex 덤프 출력
 */
#ifndef NETSCOPE_OUTPUT_H
#define NETSCOPE_OUTPUT_H

#include <stdint.h>
#include <time.h>
#include "packet.h"
#include "util.h"

typedef struct {
    int             verbose;   /* -v 상세 트리 */
    int             hex;       /* -x hex 덤프 */
    struct timespec t0;        /* Time 열의 기준 시각 */
} outopt_t;

#define C_RESET  (use_color() ? "\033[0m"  : "")
#define C_BOLD   (use_color() ? "\033[1m"  : "")
#define C_DIM    (use_color() ? "\033[2m"  : "")
#define C_RED    (use_color() ? "\033[31m" : "")
#define C_GREEN  (use_color() ? "\033[32m" : "")
#define C_YELLOW (use_color() ? "\033[33m" : "")
#define C_CYAN   (use_color() ? "\033[36m" : "")

void output_header(void);
void output_packet(const outopt_t *o, const pkt_t *p);
void output_section(const char *title);
void hexdump(const uint8_t *d, uint32_t n);

/* 상세 트리 출력 도우미 (level 단위 들여쓰기) */
void tree_hdr(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void tree_item(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif
