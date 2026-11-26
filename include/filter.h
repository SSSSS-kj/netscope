/*
 * filter.h - 표시/저장 필터
 *
 * 문법:
 *   expr   := term   ( ("or" | "||") term )*
 *   term   := factor ( ("and" | "&&") factor )*
 *   factor := ("not" | "!") factor | "(" expr ")" | prim
 *   prim   := all | ip | ip6 | arp | icmp | icmpv6 | udp | tcp | dns | http
 *           | host ADDR | src ADDR | dst ADDR | port N
 *
 * 예: "icmp", "udp port 53", "host 1.1.1.1 and (udp or icmp)", "tcp and not port 22"
 *
 * Wireshark 의 ip.addr / udp.port 와 같이, ICMP 오류 메시지 안에 인용된
 * 원본 IP 주소와 포트도 host/port 판정에 포함한다. (traceroute 분석에 필요)
 */
#ifndef NETSCOPE_FILTER_H
#define NETSCOPE_FILTER_H

#include <stddef.h>
#include "packet.h"

typedef struct filter filter_t;

filter_t *filter_compile(const char *expr, char *err, size_t errlen);
int       filter_match(const filter_t *f, const pkt_t *p);   /* f 가 NULL 이면 항상 1 */
void      filter_free(filter_t *f);

#endif
