/*
 * proto_tcp.c - TCP 헤더, 옵션, 스트림 추적
 *
 * 헤더 필드와 옵션(MSS, WS, SACK_PERM, Timestamps)을 해석하고,
 * 4-튜플(출발지 IP:포트, 목적지 IP:포트)별로 스트림 번호를 붙인다.
 * 상대 순서번호는 Wireshark 와 같은 기준으로 계산한다.
 *   - SYN 을 본 방향: 초기 순서번호(ISN)를 0 으로 (SYN 다음 바이트가 1)
 *   - SYN 을 못 본 방향: 처음 본 순서번호를 1 로
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode.h"
#include "output.h"
#include "util.h"

/* ---------- 스트림 표 ---------- */

typedef struct {
    addr_t   a, b;          /* a = 처음 본 세그먼트의 송신 측 */
    uint16_t pa, pb;
    int      base_set[2];
    uint32_t base[2];       /* 방향별 기준 순서번호 */
} tstream_t;

static tstream_t *streams;
static int        nstreams, capstreams;

static int find_stream(const pkt_t *p, int *dir)
{
    const tcp_t *t = &p->tcp;

    for (int i = nstreams - 1; i >= 0; i--) {
        tstream_t *s = &streams[i];
        if (s->pa == t->sport && s->pb == t->dport && addr_eq(&s->a, &p->ip.src) && addr_eq(&s->b, &p->ip.dst)) {
            *dir = 0;
            return i;
        }
        if (s->pa == t->dport && s->pb == t->sport && addr_eq(&s->a, &p->ip.dst) && addr_eq(&s->b, &p->ip.src)) {
            *dir = 1;
            return i;
        }
    }
    return -1;
}

static void track_stream(pkt_t *p)
{
    tcp_t *t = &p->tcp;
    int    dir, idx = find_stream(p, &dir);
    tstream_t *s;

    if (idx < 0) {
        if (nstreams == capstreams) {
            int nc = capstreams ? capstreams * 2 : 64;
            tstream_t *ns = realloc(streams, (size_t)nc * sizeof(*ns));
            if (!ns)
                return;
            streams = ns;
            capstreams = nc;
        }
        idx = nstreams++;
        s = &streams[idx];
        memset(s, 0, sizeof(*s));
        s->a = p->ip.src;
        s->b = p->ip.dst;
        s->pa = t->sport;
        s->pb = t->dport;
        dir = 0;
    }
    s = &streams[idx];

    if (!s->base_set[dir]) {
        s->base[dir] = (t->flags & TCP_SYN) ? t->seq : t->seq - 1;
        s->base_set[dir] = 1;
    }
    if ((t->flags & TCP_ACK) && !s->base_set[!dir]) {
        s->base[!dir] = t->ack - 1;
        s->base_set[!dir] = 1;
    }
    t->stream  = idx;
    t->dir     = dir;
    t->rel_seq = t->seq - s->base[dir];
    t->rel_ack = (t->flags & TCP_ACK) ? t->ack - s->base[!dir] : 0;
}

/* ---------- 헤더 ---------- */

static void parse_options(tcp_t *t, const uint8_t *o, uint32_t n)
{
    uint32_t i = 0;

    while (i < n) {
        uint8_t kind = o[i], len;

        if (kind == 0)          /* End of option list */
            break;
        if (kind == 1) {        /* NOP */
            i++;
            continue;
        }
        if (i + 1 >= n)
            break;
        len = o[i + 1];
        if (len < 2 || i + len > n)
            break;
        switch (kind) {
        case 2: if (len == 4)  t->mss = rd16(o + i + 2); break;
        case 3: if (len == 3)  t->wscale = o[i + 2]; break;
        case 4: t->sack_perm = 1; break;
        case 8: if (len == 10) { t->has_ts = 1; t->tsval = rd32(o + i + 2); t->tsecr = rd32(o + i + 6); } break;
        }
        i += len;
    }
}

void decode_tcp(pkt_t *p, const uint8_t *d, uint32_t n)
{
    tcp_t *t = &p->tcp;

    p->l4 = L4_TCP;
    t->wscale = -1;
    if (n < 20) {
        p->truncated = 1;
        return;
    }
    t->sport    = rd16(d);
    t->dport    = rd16(d + 2);
    t->seq      = rd32(d + 4);
    t->ack      = rd32(d + 8);
    t->hlen     = (uint8_t)((d[12] >> 4) * 4);
    t->flags    = d[13];
    t->win      = rd16(d + 14);
    t->checksum = rd16(d + 16);
    t->urg      = rd16(d + 18);
    if (t->hlen < 20 || t->hlen > n) {
        p->truncated = 1;
        return;
    }
    parse_options(t, d + 20, t->hlen - 20u);
    p->payload     = d + t->hlen;
    p->payload_len = n - t->hlen;
    track_stream(p);

    if (p->payload_len > 0 && (t->sport == 80 || t->dport == 80 || t->sport == 8080 || t->dport == 8080))
        decode_http(p, p->payload, p->payload_len);
}

/* 이 세그먼트 다음에 올 상대 순서번호 (SYN, FIN 은 1 바이트로 계산) */
uint32_t tcp_next_rel_seq(const pkt_t *p)
{
    uint32_t n = p->tcp.rel_seq + p->payload_len;

    if (p->tcp.flags & TCP_SYN)
        n++;
    if (p->tcp.flags & TCP_FIN)
        n++;
    return n;
}

/* Window Scale 배수. RFC 7323 에 따라 시프트 값은 최대 14 */
uint32_t tcp_ws_mult(int wscale)
{
    if (wscale < 0)
        return 1;
    return 1u << (wscale > 14 ? 14 : wscale);
}

void tcp_flags_str(uint8_t f, char *b, size_t n)
{
    static const struct { uint8_t bit; const char *name; } tbl[] = {
        { TCP_FIN, "FIN" }, { TCP_SYN, "SYN" }, { TCP_RST, "RST" }, { TCP_PSH, "PSH" },
        { TCP_ACK, "ACK" }, { TCP_URG, "URG" }, { TCP_ECE, "ECE" }, { TCP_CWR, "CWR" },
    };
    size_t k = 0;

    b[0] = '\0';
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]) && k < n; i++)
        if (f & tbl[i].bit)
            k += (size_t)snprintf(b + k, n - k, "%s%s", k ? ", " : "", tbl[i].name);
}

void info_tcp(const pkt_t *p, char *b, size_t n)
{
    const tcp_t *t = &p->tcp;
    char   fl[48];
    size_t k;

    tcp_flags_str(t->flags, fl, sizeof(fl));
    k = (size_t)snprintf(b, n, "%u → %u [%s] Seq=%u", t->sport, t->dport, fl, t->rel_seq);
    if ((t->flags & TCP_ACK) && k < n)
        k += (size_t)snprintf(b + k, n - k, " Ack=%u", t->rel_ack);
    if (k < n)
        k += (size_t)snprintf(b + k, n - k, " Win=%u Len=%u", t->win, p->payload_len);
    if (t->mss && k < n)
        k += (size_t)snprintf(b + k, n - k, " MSS=%u", t->mss);
    if (t->wscale >= 0 && k < n)
        k += (size_t)snprintf(b + k, n - k, " WS=%u", tcp_ws_mult(t->wscale));
    if (t->sack_perm && k < n)
        snprintf(b + k, n - k, " SACK_PERM");
}

void detail_tcp(const pkt_t *p)
{
    const tcp_t *t = &p->tcp;
    char fl[48];

    tcp_flags_str(t->flags, fl, sizeof(fl));
    tree_hdr(0, "Transmission Control Protocol, Src Port: %u, Dst Port: %u, Seq: %u, Ack: %u, Len: %u",
             t->sport, t->dport, t->rel_seq, t->rel_ack, p->payload_len);
    tree_item(1, "Source Port: %u", t->sport);
    tree_item(1, "Destination Port: %u", t->dport);
    tree_item(1, "[Stream index: %d]", t->stream);
    tree_item(1, "[TCP Segment Len: %u]", p->payload_len);
    tree_item(1, "Sequence Number: %u    (relative sequence number)", t->rel_seq);
    tree_item(1, "Sequence Number (raw): %u", t->seq);
    tree_item(1, "[Next Sequence Number: %u    (relative sequence number)]", tcp_next_rel_seq(p));
    tree_item(1, "Acknowledgment Number: %u    (relative ack number)", t->rel_ack);
    tree_item(1, "Acknowledgment number (raw): %u", t->ack);
    tree_item(1, "Header Length: %u bytes (%u)", t->hlen, t->hlen / 4);
    tree_item(1, "Flags: 0x%03x (%s)", t->flags, fl);
    tree_item(1, "Window: %u", t->win);
    if (t->wscale < 0 && !(t->flags & TCP_SYN))
        tree_item(1, "[Window size scaling factor: 협상 값은 SYN 세그먼트 참고]");
    tree_item(1, "Checksum: 0x%04x [unverified]", t->checksum);
    tree_item(1, "Urgent Pointer: %u", t->urg);
    if (t->hlen > 20) {
        tree_hdr(1, "Options: (%u bytes)", t->hlen - 20u);
        if (t->mss)
            tree_item(2, "Maximum segment size: %u bytes", t->mss);
        if (t->wscale >= 0)
            tree_item(2, "Window scale: %d (multiply by %u)%s", t->wscale, tcp_ws_mult(t->wscale),
                      t->wscale > 14 ? " [최대값 14 초과]" : "");
        if (t->sack_perm)
            tree_item(2, "SACK permitted");
        if (t->has_ts)
            tree_item(2, "Timestamps: TSval %u, TSecr %u", t->tsval, t->tsecr);
    }
    if (p->payload_len)
        tree_item(1, "TCP payload (%u bytes)", p->payload_len);
}
