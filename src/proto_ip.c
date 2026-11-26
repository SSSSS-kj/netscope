/*
 * proto_ip.c - IPv4, IPv6 헤더
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "decode.h"
#include "output.h"
#include "util.h"

const char *ip_proto_name(uint8_t proto)
{
    switch (proto) {
    case 0:  return "HOPOPT";
    case 1:  return "ICMP";
    case 2:  return "IGMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    case 58: return "ICMPv6";
    default: return "IP";
    }
}

/* IPv4 헤더만 해석 (ICMP 오류 메시지 안의 원본 헤더에도 사용). 헤더 길이 또는 -1 */
int parse_ipv4_hdr(ip_t *ip, const uint8_t *d, uint32_t n)
{
    memset(ip, 0, sizeof(*ip));
    if (n < 20 || (d[0] >> 4) != 4)
        return -1;
    ip->version   = 4;
    ip->hlen      = (uint8_t)((d[0] & 0x0f) * 4);
    if (ip->hlen < 20 || ip->hlen > n)
        return -1;
    ip->tos       = d[1];
    ip->total_len = rd16(d + 2);
    ip->id        = rd16(d + 4);
    ip->frag      = rd16(d + 6);
    ip->ttl       = d[8];
    ip->proto     = d[9];
    ip->checksum  = rd16(d + 10);
    ip->checksum_ok = inet_cksum(d, ip->hlen) == 0;
    ip->src.family = ip->dst.family = AF_INET;
    memcpy(ip->src.a, d + 12, 4);
    memcpy(ip->dst.a, d + 16, 4);
    return ip->hlen;
}

/* IPv6 고정 헤더 + 확장 헤더 건너뛰기. 헤더 전체 길이 또는 -1 */
int parse_ipv6_hdr(ip_t *ip, const uint8_t *d, uint32_t n)
{
    uint32_t off = 40;
    uint8_t  nh;

    memset(ip, 0, sizeof(*ip));
    if (n < 40 || (d[0] >> 4) != 6)
        return -1;
    ip->version    = 6;
    ip->tos        = (uint8_t)((rd16(d) >> 4) & 0xff);
    ip->flow_label = rd32(d) & 0xfffff;
    ip->total_len  = rd16(d + 4);
    nh             = d[6];
    ip->ttl        = d[7];
    ip->checksum_ok = 1;
    ip->src.family = ip->dst.family = AF_INET6;
    memcpy(ip->src.a, d + 8, 16);
    memcpy(ip->dst.a, d + 24, 16);

    for (int i = 0; i < 8; i++) {
        if (nh == 0 || nh == 43 || nh == 60) {          /* Hop-by-Hop, Routing, Destination */
            if (off + 2 > n)
                break;
            uint8_t next = d[off];
            off += (uint32_t)(d[off + 1] + 1) * 8;
            nh = next;
        } else if (nh == 44) {                           /* Fragment */
            if (off + 8 > n)
                break;
            nh = d[off];
            off += 8;
        } else {
            break;
        }
    }
    if (off > n)
        return -1;
    ip->proto = nh;
    ip->hlen  = (uint8_t)(off > 255 ? 255 : off);
    return (int)off;
}

void decode_ipv4(pkt_t *p, const uint8_t *d, uint32_t n)
{
    uint32_t end;
    int hl;

    p->l3 = L3_IPV4;
    hl = parse_ipv4_hdr(&p->ip, d, n);
    if (hl < 0) {
        p->truncated = 1;
        return;
    }
    /* Total Length 기준으로 자름 (최소 길이 프레임의 Ethernet 패딩 제거) */
    end = p->ip.total_len;
    if (end > n) {
        p->truncated = 1;
        end = n;
    }
    if (end < (uint32_t)hl)
        end = n;
    if ((p->ip.frag & 0x1fff) != 0) {   /* 두 번째 이후 조각은 상위 헤더가 없음 */
        p->l4 = L4_OTHER;
        return;
    }
    decode_l4(p, p->ip.proto, d + hl, end - (uint32_t)hl);
}

void decode_ipv6(pkt_t *p, const uint8_t *d, uint32_t n)
{
    uint32_t end;
    int hl;

    p->l3 = L3_IPV6;
    hl = parse_ipv6_hdr(&p->ip, d, n);
    if (hl < 0) {
        p->truncated = 1;
        return;
    }
    end = 40u + p->ip.total_len;
    if (end > n) {
        p->truncated = 1;
        end = n;
    }
    if (end < (uint32_t)hl)
        end = (uint32_t)hl;
    decode_l4(p, p->ip.proto, d + hl, end - (uint32_t)hl);
}

void detail_ip_fields(const ip_t *ip, int level)
{
    if (ip->version == 4) {
        tree_item(level, "Version: 4");
        tree_item(level, "Header Length: %u bytes (%u)", ip->hlen, ip->hlen / 4);
        tree_item(level, "Differentiated Services Field: 0x%02x (DSCP: %u, ECN: %u)", ip->tos, ip->tos >> 2, ip->tos & 3);
        tree_item(level, "Total Length: %u", ip->total_len);
        tree_item(level, "Identification: 0x%04x (%u)", ip->id, ip->id);
        tree_item(level, "Flags: 0x%x%s%s", ip->frag >> 13,
                  (ip->frag & 0x4000) ? ", Don't fragment" : "", (ip->frag & 0x2000) ? ", More fragments" : "");
        tree_item(level, "Fragment Offset: %u", (ip->frag & 0x1fff) * 8);
        tree_item(level, "Time to Live: %u", ip->ttl);
        tree_item(level, "Protocol: %s (%u)", ip_proto_name(ip->proto), ip->proto);
        tree_item(level, "Header Checksum: 0x%04x [%s]", ip->checksum, ip->checksum_ok ? "correct" : "incorrect");
        tree_item(level, "Source Address: %s", addr_s(&ip->src));
        tree_item(level, "Destination Address: %s", addr_s(&ip->dst));
    } else {
        tree_item(level, "Version: 6");
        tree_item(level, "Traffic Class: 0x%02x", ip->tos);
        tree_item(level, "Flow Label: 0x%05x", ip->flow_label);
        tree_item(level, "Payload Length: %u", ip->total_len);
        tree_item(level, "Next Header: %s (%u)", ip_proto_name(ip->proto), ip->proto);
        tree_item(level, "Hop Limit: %u", ip->ttl);
        tree_item(level, "Source Address: %s", addr_s(&ip->src));
        tree_item(level, "Destination Address: %s", addr_s(&ip->dst));
    }
}

void detail_ip(const pkt_t *p)
{
    tree_hdr(0, "Internet Protocol Version %u, Src: %s, Dst: %s",
             p->ip.version, addr_s(&p->ip.src), addr_s(&p->ip.dst));
    detail_ip_fields(&p->ip, 1);
}
