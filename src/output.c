/*
 * output.c - 화면 출력
 *
 * 요약 목록은 Wireshark 패킷 목록과 같은 열 구성:
 *   No.  Time  Source  Destination  Protocol  Length  Info
 */
#define _GNU_SOURCE
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "output.h"
#include "util.h"

void tree_hdr(int level, const char *fmt, ...)
{
    va_list ap;

    printf("%*s%s▾ ", level * 4, "", C_BOLD);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("%s\n", C_RESET);
}

void tree_item(int level, const char *fmt, ...)
{
    va_list ap;

    printf("%*s", level * 4, "");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

void output_section(const char *title)
{
    printf("\n%s━━━━━━━━ %s ━━━━━━━━%s\n", C_BOLD, title, C_RESET);
}

void output_header(void)
{
    printf("%s%6s %-11s %-24s %-24s %-8s %6s  %s%s\n", C_BOLD,
           "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", C_RESET);
}

/* Wireshark 기본 색상 규칙을 단순화한 색 */
static const char *row_color(const pkt_t *p)
{
    if (!use_color())
        return "";
    if ((p->l4 == L4_ICMP || p->l4 == L4_ICMPV6) && p->icmp.has_inner)
        return "\033[30;102m";             /* ICMP 오류: 검정 글자 + 연두 배경 */
    if (p->l4 == L4_TCP && (p->tcp.flags & TCP_RST))
        return "\033[1;31m";
    if (p->l4 == L4_TCP && (p->tcp.flags & (TCP_SYN | TCP_FIN)))
        return "\033[90m";
    switch (p->l7) {
    case L7_DNS:  return "\033[36m";
    case L7_HTTP: return "\033[1;32m";
    }
    switch (p->l4) {
    case L4_ICMP: case L4_ICMPV6: return "\033[35m";
    case L4_TCP:  return "\033[32m";
    case L4_UDP:  return "\033[34m";
    }
    if (p->l3 == L3_ARP)
        return "\033[33m";
    return "";
}

static void endpoints(const pkt_t *p, const char **src, const char **dst)
{
    if (p->l3 == L3_IPV4 || p->l3 == L3_IPV6) {
        *src = addr_s(&p->ip.src);
        *dst = addr_s(&p->ip.dst);
    } else if (p->has_eth) {
        *src = mac_s(p->eth_src);
        *dst = mac_s(p->eth_dst);
    } else {
        *src = *dst = "-";
    }
}

static void detail_frame(const outopt_t *o, const pkt_t *p)
{
    const rawpkt_t *r = p->raw;
    char tbuf[64], ifn[IF_NAMESIZE + 16] = "";

    if (r->ifindex > 0) {
        char name[IF_NAMESIZE];
        if (if_indextoname((unsigned)r->ifindex, name))
            snprintf(ifn, sizeof(ifn), " on interface %s", name);
    }
    fmt_localtime(&r->ts, tbuf, sizeof(tbuf));
    tree_hdr(0, "Frame %u: %u bytes on wire (%u bits), %u bytes captured (%u bits)%s",
             r->no, r->origlen, r->origlen * 8, r->caplen, r->caplen * 8, ifn);
    tree_item(1, "Arrival Time: %s", tbuf);
    tree_item(1, "[Time since reference or first frame: %.9f seconds]", ts_sub(&r->ts, &o->t0));
    if (r->pkttype >= 0)
        tree_item(1, "[Direction: %s]", r->pkttype == PACKET_OUTGOING ? "outgoing (송신)" : "incoming (수신)");
}

void output_packet(const outopt_t *o, const pkt_t *p)
{
    const char *src, *dst;
    char info[512];

    endpoints(p, &src, &dst);
    info_string(p, info, sizeof(info));
    printf("%s%6u %11.6f %-24s %-24s %-8s %6u  %s%s\n", row_color(p),
           p->raw->no, ts_sub(&p->raw->ts, &o->t0), src, dst, proto_name(p), p->raw->origlen, info,
           use_color() ? "\033[0m" : "");
    if (o->verbose) {
        detail_frame(o, p);
        detail_all(p);
    }
    if (o->hex)
        hexdump(p->raw->data, p->raw->caplen);
    if (o->verbose || o->hex)
        putchar('\n');
}

void hexdump(const uint8_t *d, uint32_t n)
{
    for (uint32_t off = 0; off < n; off += 16) {
        printf("%s%04x%s  ", C_DIM, off, C_RESET);
        for (uint32_t i = 0; i < 16; i++) {
            if (off + i < n)
                printf("%02x ", d[off + i]);
            else
                printf("   ");
            if (i == 7)
                putchar(' ');
        }
        printf(" ");
        for (uint32_t i = 0; i < 16 && off + i < n; i++) {
            uint8_t c = d[off + i];
            putchar(c >= 0x20 && c < 0x7f ? c : '.');
        }
        putchar('\n');
    }
}
