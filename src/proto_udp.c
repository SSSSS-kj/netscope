/*
 * proto_udp.c - UDP
 */
#include <stdio.h>

#include "decode.h"
#include "output.h"
#include "util.h"

static int is_dns_port(uint16_t p) { return p == 53 || p == 5353 || p == 5355; }

void decode_udp(pkt_t *p, const uint8_t *d, uint32_t n)
{
    udp_t *u = &p->udp;
    uint32_t plen;

    p->l4 = L4_UDP;
    if (n < 8) {
        p->truncated = 1;
        return;
    }
    u->sport    = rd16(d);
    u->dport    = rd16(d + 2);
    u->len      = rd16(d + 4);
    u->checksum = rd16(d + 6);

    plen = n - 8;
    if (u->len >= 8 && (uint32_t)(u->len - 8) < plen)
        plen = u->len - 8u;
    p->payload     = d + 8;
    p->payload_len = plen;

    if ((is_dns_port(u->sport) || is_dns_port(u->dport)) && plen >= 12)
        decode_dns(p, d + 8, plen);
}

void info_udp(const pkt_t *p, char *b, size_t n)
{
    snprintf(b, n, "%u → %u Len=%u", p->udp.sport, p->udp.dport, p->payload_len);
}

void detail_udp(const pkt_t *p)
{
    const udp_t *u = &p->udp;

    tree_hdr(0, "User Datagram Protocol, Src Port: %u, Dst Port: %u", u->sport, u->dport);
    tree_item(1, "Source Port: %u", u->sport);
    tree_item(1, "Destination Port: %u", u->dport);
    tree_item(1, "Length: %u", u->len);
    tree_item(1, "Checksum: 0x%04x [unverified]", u->checksum);
    tree_item(1, "UDP payload (%u bytes)", p->payload_len);
}
