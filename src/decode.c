/*
 * decode.c - 계층별 디코더 호출 순서와 요약/상세 출력 분기
 *
 *   L2  Ethernet / Linux cooked ─┬─ ARP
 *                                ├─ IPv4 ─┐
 *                                └─ IPv6 ─┼─ ICMP / ICMPv6
 *                                         ├─ UDP ── DNS (53, 5353, 5355)
 *                                         └─ TCP ── HTTP (80, 8080)
 */
#include <stdio.h>
#include <string.h>

#include "decode.h"

int decode_packet(const rawpkt_t *raw, pkt_t *p)
{
    memset(p, 0, sizeof(*p));
    p->raw = raw;
    if (raw->linktype == LINKTYPE_LINUX_SLL)
        decode_sll(p, raw->data, raw->caplen);
    else
        decode_eth(p, raw->data, raw->caplen);
    return 0;
}

void decode_l4(pkt_t *p, uint8_t proto, const uint8_t *d, uint32_t n)
{
    switch (proto) {
    case 1:  decode_icmp(p, d, n);   break;
    case 6:  decode_tcp(p, d, n);    break;
    case 17: decode_udp(p, d, n);    break;
    case 58: decode_icmpv6(p, d, n); break;
    default: p->l4 = L4_OTHER;       break;
    }
}

const char *proto_name(const pkt_t *p)
{
    static char buf[16];

    switch (p->l7) {
    case L7_DNS:  return p->udp.sport == 5353 || p->udp.dport == 5353 ? "MDNS" : "DNS";
    case L7_HTTP: return "HTTP";
    }
    switch (p->l4) {
    case L4_ICMP:   return "ICMP";
    case L4_ICMPV6: return "ICMPv6";
    case L4_UDP:    return "UDP";
    case L4_TCP:    return "TCP";
    case L4_OTHER:  return ip_proto_name(p->ip.proto);
    }
    switch (p->l3) {
    case L3_ARP:  return "ARP";
    case L3_IPV4: return "IPv4";
    case L3_IPV6: return "IPv6";
    }
    snprintf(buf, sizeof(buf), "0x%04x", p->ethertype);
    return buf;
}

void info_string(const pkt_t *p, char *b, size_t n)
{
    b[0] = '\0';
    if (p->l7 == L7_DNS)
        info_dns(p, b, n);
    else if (p->l7 == L7_HTTP)
        info_http(p, b, n);
    else if (p->l4 == L4_ICMP || p->l4 == L4_ICMPV6)
        info_icmp(p, b, n);
    else if (p->l4 == L4_UDP)
        info_udp(p, b, n);
    else if (p->l4 == L4_TCP)
        info_tcp(p, b, n);
    else if (p->l3 == L3_ARP)
        info_arp(p, b, n);
    else if (p->l4 == L4_OTHER)
        snprintf(b, n, "IP protocol %u", p->ip.proto);
    else if (p->truncated)
        snprintf(b, n, "[잘린 패킷]");
}

void detail_all(const pkt_t *p)
{
    detail_eth(p);
    if (p->l3 == L3_ARP)
        detail_arp(p);
    if (p->l3 == L3_IPV4 || p->l3 == L3_IPV6)
        detail_ip(p);
    switch (p->l4) {
    case L4_ICMP:
    case L4_ICMPV6: detail_icmp(p); break;
    case L4_UDP:    detail_udp(p);  break;
    case L4_TCP:    detail_tcp(p);  break;
    }
    if (p->l7 == L7_DNS)
        detail_dns(p);
    else if (p->l7 == L7_HTTP)
        detail_http(p);
}
