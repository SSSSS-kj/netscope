/*
 * proto_icmp.c - ICMP(IPv4), ICMPv6
 *
 * ping       : Echo request(8) / Echo reply(0)
 * traceroute : Time-to-live exceeded(11), Destination unreachable(3)/Port unreachable(3)
 *              오류 메시지에는 원인이 된 원본 IP 헤더 + 상위 8바이트가 인용되어 있어서
 *              어떤 UDP 프로브에 대한 응답인지 포트 번호로 알 수 있다.
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "decode.h"
#include "output.h"
#include "util.h"

const char *icmp_type_name(int v6, uint8_t type)
{
    if (!v6) {
        switch (type) {
        case 0:  return "Echo (ping) reply";
        case 3:  return "Destination unreachable";
        case 5:  return "Redirect";
        case 8:  return "Echo (ping) request";
        case 11: return "Time-to-live exceeded";
        case 12: return "Parameter problem";
        default: return "ICMP";
        }
    }
    switch (type) {
    case 1:   return "Destination Unreachable";
    case 2:   return "Packet Too Big";
    case 3:   return "Time Exceeded";
    case 128: return "Echo (ping) request";
    case 129: return "Echo (ping) reply";
    case 133: return "Router Solicitation";
    case 134: return "Router Advertisement";
    case 135: return "Neighbor Solicitation";
    case 136: return "Neighbor Advertisement";
    case 143: return "Multicast Listener Report Message v2";
    default:  return "ICMPv6";
    }
}

const char *icmp_code_name(int v6, uint8_t type, uint8_t code)
{
    if (!v6 && type == 3) {
        static const char *u[] = {
            "Network unreachable", "Host unreachable", "Protocol unreachable", "Port unreachable",
            "Fragmentation needed", "Source route failed", "Destination network unknown",
            "Destination host unknown", "Source host isolated", "Network administratively prohibited",
            "Host administratively prohibited", "Network unreachable for TOS",
            "Host unreachable for TOS", "Communication administratively filtered",
        };
        return code < sizeof(u) / sizeof(u[0]) ? u[code] : "Unknown";
    }
    if (!v6 && type == 11)
        return code == 0 ? "Time to live exceeded in transit" : "Fragment reassembly time exceeded";
    if (v6 && type == 1) {
        static const char *u[] = {
            "no route to destination", "communication administratively prohibited",
            "beyond scope of source address", "address unreachable", "port unreachable",
        };
        return code < sizeof(u) / sizeof(u[0]) ? u[code] : "Unknown";
    }
    if (v6 && type == 3)
        return code == 0 ? "hop limit exceeded in transit" : "fragment reassembly time exceeded";
    return NULL;
}

static int is_error_type(int v6, uint8_t type)
{
    return v6 ? (type >= 1 && type <= 4) : (type == 3 || type == 11 || type == 12);
}

static int is_echo_type(int v6, uint8_t type)
{
    return v6 ? (type == 128 || type == 129) : (type == 0 || type == 8);
}

/* 오류 메시지에 인용된 원본 데이터그램 해석 */
static void parse_inner(icmp_t *ic, const uint8_t *d, uint32_t n, int v6)
{
    int hl = v6 ? parse_ipv6_hdr(&ic->inner_ip, d, n) : parse_ipv4_hdr(&ic->inner_ip, d, n);
    uint32_t h;

    if (hl < 0)
        return;
    h = (uint32_t)hl;
    ic->has_inner   = 1;
    ic->inner_proto = ic->inner_ip.proto;
    if ((ic->inner_proto == 6 || ic->inner_proto == 17) && n >= h + 4) {
        ic->inner_has_ports = 1;
        ic->inner_sport = rd16(d + h);
        ic->inner_dport = rd16(d + h + 2);
    } else if ((ic->inner_proto == 1 || ic->inner_proto == 58) && n >= h + 8) {
        ic->inner_icmp_type = d[h];
        ic->inner_id  = rd16(d + h + 4);
        ic->inner_seq = rd16(d + h + 6);
    }
}

static void decode_common(pkt_t *p, const uint8_t *d, uint32_t n, int v6)
{
    icmp_t *ic = &p->icmp;

    p->l4 = v6 ? L4_ICMPV6 : L4_ICMP;
    if (n < 8) {
        p->truncated = 1;
        return;
    }
    ic->type     = d[0];
    ic->code     = d[1];
    ic->checksum = rd16(d + 2);

    if (p->truncated) {
        ic->checksum_ok = -1;
    } else if (!v6) {
        ic->checksum_ok = inet_cksum(d, n) == 0;
    } else {
        /* ICMPv6 체크섬은 IPv6 의사 헤더(출발지, 목적지, 길이, 다음 헤더)를 포함 */
        uint8_t  tail[8] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n, 0, 0, 0, 58 };
        uint32_t sum = cksum_add(0, p->ip.src.a, 16);
        sum = cksum_add(sum, p->ip.dst.a, 16);
        sum = cksum_add(sum, tail, 8);
        sum = cksum_add(sum, d, n);
        ic->checksum_ok = cksum_fold(sum) == 0;
    }

    if (is_echo_type(v6, ic->type)) {
        ic->id  = rd16(d + 4);
        ic->seq = rd16(d + 6);
    } else if (is_error_type(v6, ic->type)) {
        parse_inner(ic, d + 8, n - 8, v6);
    } else if (v6 && (ic->type == 135 || ic->type == 136) && n >= 24) {
        ic->nd_target.family = AF_INET6;
        memcpy(ic->nd_target.a, d + 8, 16);
    }
    p->payload     = d + 8;
    p->payload_len = n - 8;
}

void decode_icmp(pkt_t *p, const uint8_t *d, uint32_t n)   { decode_common(p, d, n, 0); }
void decode_icmpv6(pkt_t *p, const uint8_t *d, uint32_t n) { decode_common(p, d, n, 1); }

void info_icmp(const pkt_t *p, char *b, size_t n)
{
    const icmp_t *ic = &p->icmp;
    int v6 = p->l4 == L4_ICMPV6;
    const char *code = icmp_code_name(v6, ic->type, ic->code);

    if (is_echo_type(v6, ic->type)) {
        snprintf(b, n, "%-20s id=0x%04x, seq=%u, %s=%u", icmp_type_name(v6, ic->type),
                 ic->id, ic->seq, v6 ? "hlim" : "ttl", p->ip.ttl);
    } else if (is_error_type(v6, ic->type)) {
        int k = snprintf(b, n, "%s (%s)", icmp_type_name(v6, ic->type), code ? code : "?");
        if (ic->inner_has_ports && k > 0 && (size_t)k < n)
            snprintf(b + k, n - (size_t)k, " [원본 %s %u → %u]",
                     ic->inner_proto == 17 ? "UDP" : "TCP", ic->inner_sport, ic->inner_dport);
    } else if (v6 && (ic->type == 135 || ic->type == 136)) {
        snprintf(b, n, "%s for %s", icmp_type_name(v6, ic->type), addr_s(&ic->nd_target));
    } else {
        snprintf(b, n, "%s (type %u, code %u)", icmp_type_name(v6, ic->type), ic->type, ic->code);
    }
}

/*
 * Linux ping 은 Echo 데이터 앞 16바이트에 송신 시각(struct timeval: 초 8바이트 + 마이크로초 8바이트,
 * 호스트 바이트 순서)을 넣는다. Wireshark 4.x 와 같이 16바이트 timeval 로 해석하고,
 * 맞지 않으면 예전 Wireshark(3.x)처럼 8바이트(초 4 + 나노초 4)로 해석한다.
 * 반환값: 타임스탬프로 소비한 바이트 수 (0, 8, 16) → 나머지를 Data 로 표시
 */
static uint32_t detail_ping_timestamp(const pkt_t *p)
{
    uint64_t sec = 0, usec = 0;
    uint32_t sec32 = 0, frac32 = 0, used = 0;
    struct timespec t;
    char buf[64];

    if (p->payload_len < 16)
        return 0;
    for (int i = 7; i >= 0; i--) {
        sec  = (sec << 8) | p->payload[i];
        usec = (usec << 8) | p->payload[8 + i];
    }
    for (int i = 3; i >= 0; i--) {
        sec32  = (sec32 << 8) | p->payload[i];
        frac32 = (frac32 << 8) | p->payload[4 + i];
    }
    if (usec < 1000000 && (int64_t)sec > p->raw->ts.tv_sec - 86400 && (int64_t)sec < p->raw->ts.tv_sec + 86400) {
        t.tv_sec = (time_t)sec;
        t.tv_nsec = (long)usec * 1000;
        used = 16;
    } else if (frac32 < 1000000000u && (int64_t)sec32 > p->raw->ts.tv_sec - 86400 && (int64_t)sec32 < p->raw->ts.tv_sec + 86400) {
        t.tv_sec = (time_t)sec32;
        t.tv_nsec = (long)frac32;
        used = 8;
    } else {
        return 0;
    }
    fmt_localtime(&t, buf, sizeof(buf));
    tree_item(1, "Timestamp from icmp data: %s", buf);
    tree_item(1, "[Timestamp from icmp data (relative): %.9f seconds]", ts_sub(&p->raw->ts, &t));
    return used;
}

void detail_icmp(const pkt_t *p)
{
    const icmp_t *ic = &p->icmp;
    int v6 = p->l4 == L4_ICMPV6;
    const char *code = icmp_code_name(v6, ic->type, ic->code);

    tree_hdr(0, "Internet Control Message Protocol%s", v6 ? " v6" : "");
    tree_item(1, "Type: %u (%s)", ic->type, icmp_type_name(v6, ic->type));
    tree_item(1, "Code: %u%s%s%s", ic->code, code ? " (" : "", code ? code : "", code ? ")" : "");
    tree_item(1, "Checksum: 0x%04x [%s]", ic->checksum,
              ic->checksum_ok < 0 ? "unverified" : ic->checksum_ok ? "correct" : "incorrect");

    if (is_echo_type(v6, ic->type)) {
        tree_item(1, "Identifier (BE): %u (0x%04x)", ic->id, ic->id);
        tree_item(1, "Sequence Number (BE): %u (0x%04x)", ic->seq, ic->seq);
        uint32_t used = detail_ping_timestamp(p);
        tree_item(1, "Data (%u bytes)", p->payload_len - used);
    } else if (ic->has_inner) {
        const ip_t *in = &ic->inner_ip;
        tree_item(1, "Unused: 00000000");
        tree_hdr(1, "Internet Protocol Version %u, Src: %s, Dst: %s", in->version, addr_s(&in->src), addr_s(&in->dst));
        detail_ip_fields(in, 2);
        if (ic->inner_has_ports)
            tree_hdr(1, "%s, Src Port: %u, Dst Port: %u",
                     ic->inner_proto == 17 ? "User Datagram Protocol" : "Transmission Control Protocol",
                     ic->inner_sport, ic->inner_dport);
        else if (ic->inner_proto == 1 || ic->inner_proto == 58)
            tree_hdr(1, "Internet Control Message Protocol, Type: %u, id=0x%04x, seq=%u",
                     ic->inner_icmp_type, ic->inner_id, ic->inner_seq);
    } else if (ic->nd_target.family) {
        tree_item(1, "Target Address: %s", addr_s(&ic->nd_target));
    }
}
