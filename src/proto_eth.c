/*
 * proto_eth.c - Ethernet II, Linux cooked capture, ARP
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "decode.h"
#include "output.h"
#include "util.h"

static const char *ethertype_name(uint16_t t)
{
    switch (t) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86dd: return "IPv6";
    case 0x8100: return "802.1Q";
    default:     return "Unknown";
    }
}

static void dispatch_l3(pkt_t *p, const uint8_t *d, uint32_t n)
{
    switch (p->ethertype) {
    case 0x0800: decode_ipv4(p, d, n); break;
    case 0x86dd: decode_ipv6(p, d, n); break;
    case 0x0806: decode_arp(p, d, n);  break;
    default:     p->l3 = L3_OTHER;     break;
    }
}

void decode_eth(pkt_t *p, const uint8_t *d, uint32_t n)
{
    uint32_t off = 14;

    if (n < 14) {
        p->truncated = 1;
        return;
    }
    p->has_eth = 1;
    memcpy(p->eth_dst, d, 6);
    memcpy(p->eth_src, d + 6, 6);
    p->ethertype = rd16(d + 12);
    if (p->ethertype == 0x8100 && n >= 18) {   /* VLAN 태그 */
        p->ethertype = rd16(d + 16);
        off = 18;
    }
    dispatch_l3(p, d + off, n - off);
}

/* Linux cooked capture v1: Wireshark 에서 'any' 로 수집한 파일을 읽을 때 사용 */
void decode_sll(pkt_t *p, const uint8_t *d, uint32_t n)
{
    uint16_t halen;

    if (n < 16) {
        p->truncated = 1;
        return;
    }
    p->has_sll = 1;
    p->sll_pkttype = rd16(d);
    halen = rd16(d + 4);
    memcpy(p->eth_src, d + 6, halen < 6 ? halen : 6);
    p->ethertype = rd16(d + 14);
    dispatch_l3(p, d + 16, n - 16);
}

void decode_arp(pkt_t *p, const uint8_t *d, uint32_t n)
{
    arp_t *a = &p->arp;

    p->l3 = L3_ARP;
    if (n < 8) {
        p->truncated = 1;
        return;
    }
    a->htype = rd16(d);
    a->ptype = rd16(d + 2);
    a->op    = rd16(d + 6);
    if (a->htype != 1 || a->ptype != 0x0800 || d[4] != 6 || d[5] != 4 || n < 28)
        return;
    memcpy(a->sha, d + 8, 6);
    a->spa.family = AF_INET;
    memcpy(a->spa.a, d + 14, 4);
    memcpy(a->tha, d + 18, 6);
    a->tpa.family = AF_INET;
    memcpy(a->tpa.a, d + 24, 4);
}

void info_arp(const pkt_t *p, char *b, size_t n)
{
    const arp_t *a = &p->arp;

    if (a->op == 1)
        snprintf(b, n, "Who has %s? Tell %s", addr_s(&a->tpa), addr_s(&a->spa));
    else if (a->op == 2)
        snprintf(b, n, "%s is at %s", addr_s(&a->spa), mac_s(a->sha));
    else
        snprintf(b, n, "ARP opcode %u", a->op);
}

void detail_eth(const pkt_t *p)
{
    if (p->has_eth) {
        tree_hdr(0, "Ethernet II, Src: %s, Dst: %s", mac_s(p->eth_src), mac_s(p->eth_dst));
        tree_item(1, "Destination: %s", mac_s(p->eth_dst));
        tree_item(1, "Source: %s", mac_s(p->eth_src));
        tree_item(1, "Type: %s (0x%04x)", ethertype_name(p->ethertype), p->ethertype);
    } else if (p->has_sll) {
        static const char *pt[] = { "Unicast to us", "Broadcast", "Multicast", "Unicast to another host", "Sent by us" };
        tree_hdr(0, "Linux cooked capture v1");
        tree_item(1, "Packet type: %s (%u)", p->sll_pkttype < 5 ? pt[p->sll_pkttype] : "?", p->sll_pkttype);
        tree_item(1, "Source: %s", mac_s(p->eth_src));
        tree_item(1, "Protocol: %s (0x%04x)", ethertype_name(p->ethertype), p->ethertype);
    }
}

void detail_arp(const pkt_t *p)
{
    const arp_t *a = &p->arp;

    tree_hdr(0, "Address Resolution Protocol (%s)", a->op == 1 ? "request" : a->op == 2 ? "reply" : "?");
    tree_item(1, "Hardware type: %s (%u)", a->htype == 1 ? "Ethernet" : "?", a->htype);
    tree_item(1, "Protocol type: %s (0x%04x)", ethertype_name(a->ptype), a->ptype);
    tree_item(1, "Opcode: %s (%u)", a->op == 1 ? "request" : a->op == 2 ? "reply" : "?", a->op);
    tree_item(1, "Sender MAC address: %s", mac_s(a->sha));
    tree_item(1, "Sender IP address: %s", addr_s(&a->spa));
    tree_item(1, "Target MAC address: %s", mac_s(a->tha));
    tree_item(1, "Target IP address: %s", addr_s(&a->tpa));
}
