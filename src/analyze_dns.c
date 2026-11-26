/*
 * analyze_dns.c - nslookup 명령어 ↔ DNS 질의/응답 연동 분석
 *
 * 1) (Transaction ID, 클라이언트 주소·포트, 서버 주소·포트) 로 질의와 응답을 짝짓고 응답 시간 계산
 * 2) 서버 주소로 구간 구분: 127.0.0.53 등 로컬 스텁(systemd-resolved) / 상위 DNS 서버
 *    스텁 질의 → (캐시에 없으면) 상위 질의 → 상위 응답 → 스텁 응답 순서를 같은 이름·타입으로 연결
 * 3) nslookup 출력의 Server, Name, Address, canonical name 줄과 응답 레코드 대조
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

typedef struct {
    uint16_t        id, qtype, flags;
    addr_t          cli, srv;
    uint16_t        cport, sport;
    char            qname[DNS_NAME_MAX];
    uint32_t        qno, rno;
    struct timespec qts, rts;
    int             stub;          /* 서버가 루프백 주소 */
    int             nans;
    char            ans[512];
    dns_t           resp;
} dnsx_t;

static int is_loopback(const addr_t *a)
{
    static const uint8_t v6lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    return (a->family == AF_INET && a->a[0] == 127) || (a->family == AF_INET6 && !memcmp(a->a, v6lo, 16));
}

static const char *rcode_str(int rc)
{
    static const char *r[] = { "No error", "Format error", "Server failure", "No such name", "Not implemented", "Refused" };
    return rc >= 0 && rc < 6 ? r[rc] : "?";
}

/* 응답 레코드 중 addr 문자열(A/AAAA 데이터) 또는 이름이 있는지 */
static int resp_has(const dnsx_t *x, size_t n, const char *val, int want_type)
{
    for (size_t i = 0; i < n; i++) {
        if (!x[i].rno)
            continue;
        for (int k = 0; k < x[i].resp.n_rr; k++) {
            const dns_rr_t *rr = &x[i].resp.rr[k];
            if (want_type && rr->type != want_type)
                continue;
            if (!strcasecmp(rr->data, val))
                return 1;
        }
    }
    return 0;
}

void analyze_nslookup(const pktstore_t *s, const runctx_t *ctx)
{
    static pkt_t p;
    dnsx_t *x = calloc(s->n + 1, sizeof(*x));
    size_t  nx = 0;
    struct timespec t0 = analysis_t0(s, ctx);

    if (!x)
        return;

    for (size_t i = 0; i < s->n; i++) {
        decode_packet(&s->v[i], &p);
        if (p.l7 != L7_DNS || p.l4 != L4_UDP)
            continue;
        if (!(p.dns.flags & 0x8000)) {                       /* 질의 */
            int dup = 0;
            /* any 수집 시 루프백 패킷은 송신·수신으로 두 번 잡히므로 같은 질의는 하나로 */
            for (size_t k = nx; k-- > 0 && !dup;)
                dup = !x[k].rno && x[k].id == p.dns.id && x[k].cport == p.udp.sport &&
                      x[k].sport == p.udp.dport && addr_eq(&x[k].srv, &p.ip.dst) && addr_eq(&x[k].cli, &p.ip.src);
            if (dup)
                continue;
            dnsx_t *q = &x[nx++];
            q->id = p.dns.id;
            q->qtype = p.dns.qtype;
            q->cli = p.ip.src;
            q->srv = p.ip.dst;
            q->cport = p.udp.sport;
            q->sport = p.udp.dport;
            snprintf(q->qname, sizeof(q->qname), "%s", p.dns.qname);
            q->qno = s->v[i].no;
            q->qts = s->v[i].ts;
            q->stub = is_loopback(&p.ip.dst);
        } else {                                              /* 응답 */
            for (size_t k = nx; k-- > 0;) {
                dnsx_t *q = &x[k];
                if (q->rno || q->id != p.dns.id || q->cport != p.udp.dport || q->sport != p.udp.sport ||
                    !addr_eq(&q->srv, &p.ip.src) || !addr_eq(&q->cli, &p.ip.dst))
                    continue;
                q->rno = s->v[i].no;
                q->rts = s->v[i].ts;
                q->flags = p.dns.flags;
                q->resp = p.dns;
                for (int r = 0; r < p.dns.n_rr; r++) {
                    const dns_rr_t *rr = &p.dns.rr[r];
                    size_t L = strlen(q->ans);
                    if (rr->section != 1)
                        continue;
                    q->nans++;
                    snprintf(q->ans + L, sizeof(q->ans) - L, "%s%s %s", L ? ", " : "", dns_type_name(rr->type), rr->data);
                }
                break;
            }
        }
    }
    if (nx == 0) {
        printf("DNS 질의가 수집되지 않음\n");
        free(x);
        return;
    }

    /* 1) 질의-응답 표 */
    printf("[1] DNS 질의-응답 짝짓기\n\n");
    put_col("질의No.", 9);
    put_col("응답No.", 9);
    put_col("구간", 10);
    put_col("서버", 28);
    put_col("ID", 8);
    put_col("질의", 34);
    put_col("시간(ms)", 10);
    printf("응답\n");
    for (size_t i = 0; i < nx; i++) {
        dnsx_t *q = &x[i];
        char qq[300], idb[8], rn[16], tm[16];
        snprintf(qq, sizeof(qq), "%s %s", dns_type_name(q->qtype), q->qname);
        snprintf(idb, sizeof(idb), "0x%04x", q->id);
        snprintf(rn, sizeof(rn), "%u", q->rno);
        snprintf(tm, sizeof(tm), "%.3f", q->rno ? ts_sub(&q->rts, &q->qts) * 1000.0 : 0);
        printf("%-9u", q->qno);
        put_col(q->rno ? rn : "-", 9);
        put_col(q->stub ? "로컬 스텁" : "상위 DNS", 10);
        put_col(addr_s(&q->srv), 28);
        put_col(idb, 8);
        put_col(qq, 34);
        put_col(q->rno ? tm : "-", 10);
        if (!q->rno)
            printf("응답 없음\n");
        else if (q->flags & 0x000f)
            printf("%s\n", rcode_str(q->flags & 0x000f));
        else
            printf("%s%s\n", q->nans ? q->ans : "(응답 레코드 없음)", (q->flags & 0x0400) ? "" : "  [비권한 응답]");
    }

    /* 2) 스텁 ↔ 상위 연결 */
    {
        int linked = 0, has_stub = 0;
        for (size_t i = 0; i < nx; i++)
            has_stub |= x[i].stub;
        if (has_stub) {
            printf("\n[2] 로컬 스텁(systemd-resolved) ↔ 상위 DNS 연결\n\n");
            for (size_t i = 0; i < nx; i++) {
                dnsx_t *a = &x[i];
                if (!a->stub)
                    continue;
                for (size_t k = 0; k < nx; k++) {
                    dnsx_t *b = &x[k];
                    if (b->stub || b->qtype != a->qtype || strcasecmp(b->qname, a->qname) ||
                        ts_sub(&b->qts, &a->qts) < 0 || (a->rno && ts_sub(&a->rts, &b->qts) < 0))
                        continue;
                    printf("- %s %s: 스텁 질의 No.%u → 상위 질의 No.%u (%s, ID 0x%04x) → 상위 응답 No.%u → 스텁 응답 No.%u\n",
                           dns_type_name(a->qtype), a->qname, a->qno, b->qno, addr_s(&b->srv), b->id, b->rno, a->rno);
                    linked = 1;
                    goto next;
                }
                printf("- %s %s: 스텁 질의 No.%u → 상위 질의 없음 → 스텁 응답 No.%u (resolved 캐시에서 응답)\n",
                       dns_type_name(a->qtype), a->qname, a->qno, a->rno);
            next:;
            }
            if (linked)
                printf("  스텁 구간과 상위 구간의 Transaction ID 가 다름: resolved 가 새 질의를 만들어 대신 물어봄\n");
        }
    }

    /* 3) nslookup 출력 대조 */
    if (ctx->output) {
        char line[512], server[64] = "";
        int  in_answer = 0, ok = 0, total = 0;

        printf("\n[3] nslookup 출력과 대조\n\n");
        for (const char *t = ctx->output; t && *t;) {
            char *v;
            t = next_line(t, line, sizeof(line));
            if (!strncmp(line, "Server:", 7)) {
                sscanf(line + 7, " %63s", server);
                int seen = 0;
                for (size_t i = 0; i < nx; i++)
                    seen |= !strcmp(addr_s(&x[i].srv), server);
                printf("%-44s ↔ %s\n", line, seen ? "질의 목적지와 일치 O" : "질의 목적지와 다름 X");
            } else if (strstr(line, "answer:")) {
                in_answer = 1;
                printf("%-44s ↔ %s\n", line, "응답 Flags 의 Authoritative 비트 = 0");
            } else if (in_answer && (v = strstr(line, "canonical name ="))) {
                char cname[256] = "";
                sscanf(v + 16, " %255s", cname);
                size_t L = strlen(cname);
                if (L && cname[L - 1] == '.')
                    cname[L - 1] = '\0';
                int hit = resp_has(x, nx, cname, 5);
                printf("%-44s ↔ CNAME 레코드 %s\n", line, hit ? "있음 O" : "없음 X");
                ok += hit;
                total++;
            } else if ((v = strstr(line, "name = "))) {          /* 역방향 조회(PTR) 결과 */
                char name[256] = "";
                sscanf(v + 7, " %255s", name);
                size_t L = strlen(name);
                if (L && name[L - 1] == '.')
                    name[L - 1] = '\0';
                int hit = resp_has(x, nx, name, 12);
                printf("%-44s ↔ PTR 레코드 %s\n", line, hit ? "있음 O" : "없음 X");
                ok += hit;
                total++;
            } else if (in_answer && !strncmp(line, "Address:", 8)) {
                char a[64] = "";
                sscanf(line + 8, " %63s", a);
                int hit = resp_has(x, nx, a, 0);
                printf("%-44s ↔ A/AAAA 레코드 %s\n", line, hit ? "있음 O" : "없음 X");
                ok += hit;
                total++;
            } else if (in_answer && !strncmp(line, "Name:", 5)) {
                printf("%s\n", line);
            } else if (strstr(line, "can't find") || strstr(line, "NXDOMAIN")) {
                printf("%-44s ↔ 응답 Reply code 확인\n", line);
            }
        }
        if (total)
            printf("\n출력 레코드 %d 개 중 %d 개가 수집한 DNS 응답과 일치\n", total, ok);
    }

    /* 4) 해석 */
    {
        int a = 0, aaaa = 0, ptr = 0;
        for (size_t i = 0; i < nx; i++) {
            a += x[i].qtype == 1;
            aaaa += x[i].qtype == 28;
            ptr += x[i].qtype == 12;
        }
        printf("\n[4] 해석\n\n");
        printf("- DNS 는 UDP 53 번 포트를 사용하며, 응답은 질의와 같은 Transaction ID 와 포트로 돌아옴\n");
        if (a && aaaa)
            printf("- nslookup 은 IPv4 주소(A)와 IPv6 주소(AAAA)를 각각 질의함 (A %d 회, AAAA %d 회)\n", a, aaaa);
        if (ptr)
            printf("- PTR 질의 %d 회: IP 주소로 이름을 찾는 역방향 조회 (in-addr.arpa)\n", ptr);
        printf("- 측정 시작 기준 첫 질의 시각: %.6f 초\n", ts_sub(&x[0].qts, &t0));
    }
    free(x);
}
