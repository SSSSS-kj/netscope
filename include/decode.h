/*
 * decode.h - 계층별 디코더와 출력 함수
 *
 * 각 프로토콜 파일(proto_*.c)은 세 가지를 제공한다.
 *   decode_xxx() : 헤더를 해석해 pkt_t 를 채우고 상위 계층 디코더를 호출
 *   info_xxx()   : 요약 목록의 Info 열 문자열
 *   detail_xxx() : -v 상세 트리 출력
 */
#ifndef NETSCOPE_DECODE_H
#define NETSCOPE_DECODE_H

#include <stddef.h>
#include "packet.h"

int  decode_packet(const rawpkt_t *raw, pkt_t *p);
void decode_l4(pkt_t *p, uint8_t proto, const uint8_t *d, uint32_t n);

const char *proto_name(const pkt_t *p);
void        info_string(const pkt_t *p, char *buf, size_t n);
void        detail_all(const pkt_t *p);

/* proto_eth.c */
void decode_eth(pkt_t *p, const uint8_t *d, uint32_t n);
void decode_sll(pkt_t *p, const uint8_t *d, uint32_t n);
void decode_arp(pkt_t *p, const uint8_t *d, uint32_t n);
void info_arp(const pkt_t *p, char *b, size_t n);
void detail_eth(const pkt_t *p);
void detail_arp(const pkt_t *p);

/* proto_ip.c */
int  parse_ipv4_hdr(ip_t *ip, const uint8_t *d, uint32_t n);
int  parse_ipv6_hdr(ip_t *ip, const uint8_t *d, uint32_t n);
void decode_ipv4(pkt_t *p, const uint8_t *d, uint32_t n);
void decode_ipv6(pkt_t *p, const uint8_t *d, uint32_t n);
const char *ip_proto_name(uint8_t proto);
void detail_ip(const pkt_t *p);
void detail_ip_fields(const ip_t *ip, int level);

/* proto_icmp.c */
void decode_icmp(pkt_t *p, const uint8_t *d, uint32_t n);
void decode_icmpv6(pkt_t *p, const uint8_t *d, uint32_t n);
const char *icmp_type_name(int v6, uint8_t type);
const char *icmp_code_name(int v6, uint8_t type, uint8_t code);
void info_icmp(const pkt_t *p, char *b, size_t n);
void detail_icmp(const pkt_t *p);

/* proto_udp.c */
void decode_udp(pkt_t *p, const uint8_t *d, uint32_t n);
void info_udp(const pkt_t *p, char *b, size_t n);
void detail_udp(const pkt_t *p);

/* proto_dns.c */
void decode_dns(pkt_t *p, const uint8_t *d, uint32_t n);
const char *dns_type_name(uint16_t type);
void info_dns(const pkt_t *p, char *b, size_t n);
void detail_dns(const pkt_t *p);

/* proto_tcp.c */
void decode_tcp(pkt_t *p, const uint8_t *d, uint32_t n);
void tcp_flags_str(uint8_t flags, char *b, size_t n);
uint32_t tcp_next_rel_seq(const pkt_t *p);
uint32_t tcp_ws_mult(int wscale);
void info_tcp(const pkt_t *p, char *b, size_t n);
void detail_tcp(const pkt_t *p);

/* proto_http.c */
void decode_http(pkt_t *p, const uint8_t *d, uint32_t n);
void info_http(const pkt_t *p, char *b, size_t n);
void detail_http(const pkt_t *p);

#endif
