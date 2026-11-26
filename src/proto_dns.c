/*
 * proto_dns.c - DNS 메시지 (RFC 1035)
 *
 * 헤더 12바이트 + Question + Answer/Authority/Additional RR
 * 도메인 이름은 길이-라벨 형식이며, 상위 2비트가 11 이면 메시지 내 오프셋을 가리키는 압축 포인터.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "decode.h"
#include "output.h"
#include "util.h"

const char *dns_type_name(uint16_t t)
{
    static char buf[16];

    switch (t) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 41:  return "OPT";
    case 64:  return "SVCB";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    }
    snprintf(buf, sizeof(buf), "TYPE%u", t);
    return buf;
}

static const char *rcode_name(int rc)
{
    static const char *r[] = { "No error", "Format error", "Server failure", "No such name", "Not implemented", "Refused" };
    return rc >= 0 && rc < 6 ? r[rc] : "Unknown";
}

/* 이름 읽기. 성공 시 0, *next 에 이름 다음 오프셋 */
static int dns_name(const uint8_t *m, uint32_t mlen, uint32_t off, char *out, size_t outn, uint32_t *next)
{
    size_t   o = 0;
    uint32_t pos = off;
    int      jumped = 0, hops = 0;

    out[0] = '\0';
    while (pos < mlen) {
        uint8_t len = m[pos];

        if (len == 0) {
            if (!jumped)
                *next = pos + 1;
            if (o == 0)
                snprintf(out, outn, "<Root>");
            return 0;
        }
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= mlen || ++hops > 32)
                return -1;
            if (!jumped)
                *next = pos + 2;
            jumped = 1;
            pos = (uint32_t)((len & 0x3f) << 8) | m[pos + 1];
            continue;
        }
        if (len & 0xc0)
            return -1;
        pos++;
        if (pos + len > mlen)
            return -1;
        if (o && o + 1 < outn)
            out[o++] = '.';
        for (uint32_t i = 0; i < len && o + 1 < outn; i++) {
            uint8_t c = m[pos + i];
            out[o++] = (c >= 0x21 && c < 0x7f) ? (char)c : '?';
        }
        out[o] = '\0';
        pos += len;
    }
    return -1;
}

static void rr_data(const uint8_t *m, uint32_t mlen, uint32_t off, dns_rr_t *rr, uint16_t rdlen)
{
    uint32_t next;
    addr_t a;

    rr->data[0] = '\0';
    memset(&a, 0, sizeof(a));
    switch (rr->type) {
    case 1:
        if (rdlen == 4) {
            a.family = AF_INET;
            memcpy(a.a, m + off, 4);
            snprintf(rr->data, sizeof(rr->data), "%s", addr_s(&a));
        }
        break;
    case 28:
        if (rdlen == 16) {
            a.family = AF_INET6;
            memcpy(a.a, m + off, 16);
            snprintf(rr->data, sizeof(rr->data), "%s", addr_s(&a));
        }
        break;
    case 2: case 5: case 12:
        dns_name(m, mlen, off, rr->data, sizeof(rr->data), &next);
        break;
    case 15:
        if (rdlen > 2) {
            char nm[DNS_NAME_MAX];
            dns_name(m, mlen, off + 2, nm, sizeof(nm), &next);
            snprintf(rr->data, sizeof(rr->data), "%u %.240s", rd16(m + off), nm);
        }
        break;
    case 6: {
        char mname[DNS_NAME_MAX];
        dns_name(m, mlen, off, mname, sizeof(mname), &next);
        snprintf(rr->data, sizeof(rr->data), "%s", mname);
        break;
    }
    default:
        snprintf(rr->data, sizeof(rr->data), "(%u bytes)", rdlen);
    }
}

void decode_dns(pkt_t *p, const uint8_t *d, uint32_t n)
{
    dns_t   *dn = &p->dns;
    uint32_t off = 12, next;
    int      total;

    if (n < 12)
        return;
    dn->id      = rd16(d);
    dn->flags   = rd16(d + 2);
    dn->qdcount = rd16(d + 4);
    dn->ancount = rd16(d + 6);
    dn->nscount = rd16(d + 8);
    dn->arcount = rd16(d + 10);
    p->l7 = L7_DNS;

    for (int i = 0; i < dn->qdcount; i++) {
        char nm[DNS_NAME_MAX];
        if (dns_name(d, n, off, nm, sizeof(nm), &next) < 0 || next + 4 > n)
            return;
        if (i == 0) {
            snprintf(dn->qname, sizeof(dn->qname), "%s", nm);
            dn->qtype  = rd16(d + next);
            dn->qclass = rd16(d + next + 2);
        }
        off = next + 4;
    }

    total = dn->ancount + dn->nscount + dn->arcount;
    for (int i = 0; i < total && dn->n_rr < DNS_RR_MAX; i++) {
        dns_rr_t *rr = &dn->rr[dn->n_rr];
        uint16_t rdlen;

        if (dns_name(d, n, off, rr->name, sizeof(rr->name), &next) < 0 || next + 10 > n)
            return;
        rr->type = rd16(d + next);
        rr->cls  = rd16(d + next + 2);
        rr->ttl  = rd32(d + next + 4);
        rdlen    = rd16(d + next + 8);
        if (next + 10 + rdlen > n)
            return;
        rr->section = i < dn->ancount ? 1 : i < dn->ancount + dn->nscount ? 2 : 3;
        rr_data(d, n, next + 10, rr, rdlen);
        off = next + 10 + rdlen;
        dn->n_rr++;
    }
}

void info_dns(const pkt_t *p, char *b, size_t n)
{
    const dns_t *dn = &p->dns;
    int    resp = (dn->flags & 0x8000) != 0;
    int    rc   = dn->flags & 0x000f;
    size_t k;

    k = (size_t)snprintf(b, n, "Standard query%s 0x%04x", resp ? " response" : "", dn->id);
    if (k < n && dn->qname[0])
        k += (size_t)snprintf(b + k, n - k, " %s %s", dns_type_name(dn->qtype), dn->qname);
    if (resp && rc && k < n)
        k += (size_t)snprintf(b + k, n - k, " %s", rcode_name(rc));
    for (int i = 0; i < dn->n_rr && k < n; i++) {
        if (dn->rr[i].section != 1)
            continue;
        k += (size_t)snprintf(b + k, n - k, " %s %s", dns_type_name(dn->rr[i].type), dn->rr[i].data);
    }
}

void detail_dns(const pkt_t *p)
{
    const dns_t *dn = &p->dns;
    uint16_t f = dn->flags;
    static const char *sec[] = { "", "Answers", "Authoritative nameservers", "Additional records" };
    int last = 0;

    tree_hdr(0, "Domain Name System (%s)", (f & 0x8000) ? "response" : "query");
    tree_item(1, "Transaction ID: 0x%04x", dn->id);
    tree_item(1, "Flags: 0x%04x %s%s", f, (f & 0x8000) ? "Standard query response, " : "Standard query",
              (f & 0x8000) ? rcode_name(f & 0xf) : "");
    tree_item(2, "Response: %s", (f & 0x8000) ? "Message is a response" : "Message is a query");
    tree_item(2, "Opcode: %u", (f >> 11) & 0xf);
    if (f & 0x8000)
        tree_item(2, "Authoritative: %s", (f & 0x0400) ? "Yes" : "No");
    tree_item(2, "Truncated: %s", (f & 0x0200) ? "Yes" : "No");
    tree_item(2, "Recursion desired: %s", (f & 0x0100) ? "Yes" : "No");
    if (f & 0x8000) {
        tree_item(2, "Recursion available: %s", (f & 0x0080) ? "Yes" : "No");
        tree_item(2, "Reply code: %s (%u)", rcode_name(f & 0xf), f & 0xf);
    }
    tree_item(1, "Questions: %u", dn->qdcount);
    tree_item(1, "Answer RRs: %u", dn->ancount);
    tree_item(1, "Authority RRs: %u", dn->nscount);
    tree_item(1, "Additional RRs: %u", dn->arcount);
    if (dn->qname[0]) {
        tree_hdr(1, "Queries");
        tree_item(2, "%s: type %s, class %s", dn->qname, dns_type_name(dn->qtype), dn->qclass == 1 ? "IN" : "?");
    }
    for (int i = 0; i < dn->n_rr; i++) {
        const dns_rr_t *rr = &dn->rr[i];
        if (rr->type == 41)   /* EDNS OPT 레코드는 생략 */
            continue;
        if (rr->section != last) {
            tree_hdr(1, "%s", sec[rr->section]);
            last = rr->section;
        }
        tree_item(2, "%s: type %s, class IN, TTL %u, %s", rr->name, dns_type_name(rr->type), rr->ttl, rr->data);
    }
}
