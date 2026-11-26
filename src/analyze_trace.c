/*
 * analyze_trace.c - traceroute 명령어 ↔ UDP 프로브 / ICMP 응답 연동 분석
 *
 * traceroute 동작 원리
 *   - TTL 을 1, 2, 3 ... 으로 늘려 가며 목적지의 사용하지 않는 UDP 포트(33434~)로 프로브를 보냄
 *   - TTL 이 0 이 되는 라우터는 패킷을 버리고 ICMP Time-to-live exceeded(11) 를 돌려줌
 *   - 목적지에 도착하면 해당 포트에 프로그램이 없으므로 ICMP Port unreachable(3/3) 을 돌려줌
 *   - ICMP 오류 메시지에는 원본 IP 헤더와 UDP 헤더 8바이트가 인용되어 있어,
 *     인용된 (출발지 포트, 목적지 포트) 로 어떤 프로브에 대한 응답인지 알 수 있음
 *
 * 분석 순서
 *   1) 목적지로 보낸 프로브 수집 (UDP 기본, -I 옵션의 ICMP Echo 도 처리)
 *   2) ICMP 오류/Echo reply 를 프로브와 짝지어 홉별 응답 라우터와 RTT 계산
 *   3) traceroute 출력의 각 줄(홉 번호, 주소, RTT)과 대조
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

#define MAX_HOP 64
#define MAX_PER 8

typedef struct {
    int             icmp_probe;        /* 1 = ICMP Echo 프로브 (traceroute -I) */
    uint16_t        sport, dport;      /* UDP 프로브 포트 또는 ICMP id/seq */
    uint8_t         ttl;
    uint32_t        no;
    struct timespec ts;
    uint32_t        resp_no;
    struct timespec resp_ts;
    addr_t          from;
    uint8_t         rtype, rcode;
    uint8_t         quoted_ttl;        /* 응답에 인용된 원본 IP 헤더의 TTL */
} probe_t;

typedef struct {
    int    n;
    addr_t ip[MAX_PER];
    int    nrtt;
    double rtt[MAX_PER];
    int    stars;
} outhop_t;

/* traceroute 출력 파싱: " 3  10.1.5.5 (10.1.5.5)  2.375 ms  2.362 ms *" */
static int parse_output(const char *text, outhop_t *hops, char *target, size_t tn)
{
    char line[512];
    int  maxhop = 0;

    target[0] = '\0';
    for (const char *s = text; s && *s;) {
        char *tok, *save, *t;
        int   hop;

        s = next_line(s, line, sizeof(line));
        if ((t = strstr(line, "traceroute to ")) && (t = strchr(t, '('))) {
            char *e = strchr(t, ')');
            if (e && (size_t)(e - t - 1) < tn) {
                memcpy(target, t + 1, (size_t)(e - t - 1));
                target[e - t - 1] = '\0';
            }
            continue;
        }
        tok = strtok_r(line, " \t", &save);
        if (!tok || (hop = atoi(tok)) <= 0 || hop >= MAX_HOP)
            continue;
        outhop_t *h = &hops[hop];
        while ((tok = strtok_r(NULL, " \t", &save))) {
            char  *end;
            double v;
            addr_t a;
            if (!strcmp(tok, "*")) {
                h->stars++;
                if (h->nrtt < MAX_PER)
                    h->rtt[h->nrtt++] = -1;     /* 출력 순서 유지 */
                continue;
            }
            if (tok[0] == '(') {
                tok++;
                if ((end = strchr(tok, ')')))
                    *end = '\0';
            }
            if (addr_parse(tok, &a) == 0) {
                int dup = 0;
                for (int i = 0; i < h->n; i++)
                    dup |= addr_eq(&h->ip[i], &a);
                if (!dup && h->n < MAX_PER)
                    h->ip[h->n++] = a;
                continue;
            }
            v = strtod(tok, &end);
            if (end != tok && *end == '\0' && h->nrtt < MAX_PER) {
                char *nx = strtok_r(NULL, " \t", &save);
                if (nx && !strcmp(nx, "ms"))
                    h->rtt[h->nrtt++] = v;
            }
        }
        if (hop > maxhop)
            maxhop = hop;
    }
    return maxhop;
}

static const char *resp_name(const probe_t *p)
{
    if (!p->resp_no)
        return "응답 없음";
    if (p->rtype == 11)
        return "TTL exceeded";
    if (p->rtype == 3 && p->rcode == 3)
        return "Port unreachable";
    if (p->rtype == 0)
        return "Echo reply";
    if (p->rtype == 3)
        return "Unreachable";
    return "기타";
}

void analyze_traceroute(const pktstore_t *s, const runctx_t *ctx)
{
    static pkt_t p;
    static outhop_t oh[MAX_HOP];
    probe_t *pr = calloc(s->n + 1, sizeof(*pr));
    size_t   np = 0;
    addr_t   target = { 0, { 0 } }, me = { 0, { 0 } };
    char     tstr[64] = "";
    int      maxttl = 0, out_max = 0, have_out = ctx->output != NULL;
    int      reached = 0, reached_hop = 0;

    if (!pr)
        return;
    memset(oh, 0, sizeof(oh));
    if (have_out)
        out_max = parse_output(ctx->output, oh, tstr, sizeof(tstr));
    if (tstr[0])
        addr_parse(tstr, &target);

    /* 1) 프로브 수집: 목적지를 모르면 가장 먼저 나오는 33434 포트 UDP 의 목적지 */
    for (size_t i = 0; i < s->n; i++) {
        decode_packet(&s->v[i], &p);
        if (!target.family && p.l4 == L4_UDP && p.udp.dport >= 33434 && p.udp.dport < 33434 + 1000)
            target = p.ip.dst;
        if (!target.family || !addr_eq(&p.ip.dst, &target))
            continue;
        if (p.l4 == L4_UDP && p.udp.dport >= 33434 && p.udp.dport < 33434 + 1000) {
            pr[np].sport = p.udp.sport;
            pr[np].dport = p.udp.dport;
        } else if (p.l4 == L4_ICMP && p.icmp.type == 8) {
            pr[np].icmp_probe = 1;
            pr[np].sport = p.icmp.id;
            pr[np].dport = p.icmp.seq;
        } else {
            continue;
        }
        me = p.ip.src;
        pr[np].ttl = p.ip.ttl;
        pr[np].no  = s->v[i].no;
        pr[np].ts  = s->v[i].ts;
        if (p.ip.ttl > maxttl)
            maxttl = p.ip.ttl;
        np++;
    }
    if (np == 0) {
        printf("traceroute 프로브(UDP 33434~ 또는 ICMP Echo)가 수집되지 않음\n");
        free(pr);
        return;
    }

    /* 2) 응답 짝짓기 */
    for (size_t i = 0; i < s->n; i++) {
        decode_packet(&s->v[i], &p);
        if (p.l4 != L4_ICMP || !addr_eq(&p.ip.dst, &me))
            continue;
        for (size_t k = 0; k < np; k++) {
            probe_t *x = &pr[k];
            int hit = 0;
            if (x->resp_no)
                continue;
            if (p.icmp.has_inner && addr_eq(&p.icmp.inner_ip.dst, &target)) {
                if (!x->icmp_probe && p.icmp.inner_has_ports && p.icmp.inner_proto == 17)
                    hit = p.icmp.inner_sport == x->sport && p.icmp.inner_dport == x->dport;
                else if (x->icmp_probe && p.icmp.inner_proto == 1)
                    hit = p.icmp.inner_id == x->sport && p.icmp.inner_seq == x->dport;
            } else if (x->icmp_probe && p.icmp.type == 0) {
                hit = p.icmp.id == x->sport && p.icmp.seq == x->dport && addr_eq(&p.ip.src, &target);
            }
            if (hit) {
                x->resp_no = s->v[i].no;
                x->resp_ts = s->v[i].ts;
                x->from    = p.ip.src;
                x->rtype   = p.icmp.type;
                x->rcode   = p.icmp.code;
                x->quoted_ttl = p.icmp.has_inner ? p.icmp.inner_ip.ttl : 0;
                break;
            }
        }
    }

    /* 3) 홉 표 */
    printf("[1] 홉별 프로브-응답 짝짓기 (목적지 %s, 프로브 %zu 개, %s)\n\n",
           addr_s(&target), np, pr[0].icmp_probe ? "ICMP Echo 프로브" : "UDP 프로브");
    put_col("홉", 4);
    put_col("프로브 No.(포트)", 26);
    put_col("응답 No.", 10);
    put_col("응답 라우터", 18);
    put_col("응답 종류", 18);
    printf("RTT(ms)\n");
    for (int ttl = 1; ttl <= maxttl; ttl++) {
        int first = 1;
        for (size_t k = 0; k < np; k++) {
            probe_t *x = &pr[k];
            char a[48], b[16];
            if (x->ttl != ttl)
                continue;
            snprintf(a, sizeof(a), "%u (%u→%u)", x->no, x->sport, x->dport);
            if (x->icmp_probe)
                snprintf(a, sizeof(a), "%u (seq %u)", x->no, x->dport);
            snprintf(b, sizeof(b), "%u", x->resp_no);
            if (first)
                printf("%-4d", ttl);
            else
                printf("    ");
            put_col(a, 26);
            put_col(x->resp_no ? b : "-", 10);
            put_col(x->resp_no ? addr_s(&x->from) : "*", 18);
            put_col(resp_name(x), 18);
            if (x->resp_no)
                printf("%.3f", ts_sub(&x->resp_ts, &x->ts) * 1000.0);
            printf("\n");
            first = 0;
            if (x->resp_no && (x->rtype == 0 || (x->rtype == 3 && x->rcode == 3)) && (!reached || ttl < reached_hop)) {
                reached = 1;
                reached_hop = ttl;
            }
        }
    }

    /* 4) traceroute 출력과 대조 */
    if (have_out && out_max > 0) {
        int match = 0, total = 0;
        printf("\n[2] traceroute 출력과 대조\n\n");
        put_col("홉", 4);
        put_col("traceroute 출력 주소", 34);
        put_col("패킷 분석 주소", 34);
        printf("일치\n");
        for (int h = 1; h <= out_max; h++) {
            char oa[128] = "", pa[128] = "";
            addr_t seen[MAX_PER];
            int    ns = 0, ok = 1;
            size_t k;

            for (int i = 0; i < oh[h].n; i++)
                snprintf(oa + strlen(oa), sizeof(oa) - strlen(oa), "%s%s", i ? ", " : "", addr_s(&oh[h].ip[i]));
            for (k = 0; k < np; k++) {
                int dup = 0;
                if (pr[k].ttl != h || !pr[k].resp_no)
                    continue;
                for (int i = 0; i < ns; i++)
                    dup |= addr_eq(&seen[i], &pr[k].from);
                if (!dup && ns < MAX_PER) {
                    seen[ns++] = pr[k].from;
                    snprintf(pa + strlen(pa), sizeof(pa) - strlen(pa), "%s%s", ns > 1 ? ", " : "", addr_s(&pr[k].from));
                }
            }
            if (ns != oh[h].n)
                ok = 0;
            for (int i = 0; ok && i < ns; i++) {
                int f = 0;
                for (int j = 0; j < oh[h].n; j++)
                    f |= addr_eq(&seen[i], &oh[h].ip[j]);
                ok = f;
            }
            printf("%-4d", h);
            put_col(oh[h].n ? oa : "* (응답 없음)", 34);
            put_col(ns ? pa : "* (응답 없음)", 34);
            printf("%s\n", ok ? "O" : "X");
            match += ok;
            total++;
        }
        printf("\n%d 개 홉 중 %d 개 일치\n", total, match);

        /* RTT 대조: traceroute 는 프로브를 보낸 순서대로 RTT 를 출력하므로 같은 순서로 비교 */
        printf("\n[2-2] RTT 대조 (ms, 프로브 순서대로, * = 응답 없음)\n\n");
        put_col("홉", 4);
        put_col("traceroute 출력", 30);
        printf("패킷 분석\n");
        for (int h = 1; h <= out_max; h++) {
            char oa[128] = "", pa[128] = "";
            for (int i = 0; i < oh[h].nrtt; i++) {
                if (oh[h].rtt[i] < 0)
                    snprintf(oa + strlen(oa), sizeof(oa) - strlen(oa), "%s*", i ? " " : "");
                else
                    snprintf(oa + strlen(oa), sizeof(oa) - strlen(oa), "%s%.3f", i ? " " : "", oh[h].rtt[i]);
            }
            for (size_t k = 0; k < np; k++) {
                if (pr[k].ttl != h)
                    continue;
                if (pr[k].resp_no)
                    snprintf(pa + strlen(pa), sizeof(pa) - strlen(pa), "%s%.3f", pa[0] ? " " : "",
                             ts_sub(&pr[k].resp_ts, &pr[k].ts) * 1000.0);
                else
                    snprintf(pa + strlen(pa), sizeof(pa) - strlen(pa), "%s*", pa[0] ? " " : "");
            }
            printf("%-4d", h);
            put_col(oa, 30);
            printf("%s\n", pa);
        }
        printf("\n(패킷 RTT 는 커널 수신 시각 기준이라 traceroute 가 잰 값보다 약간 작게 나옴)\n");
    }

    /* 5) 해석 */
    printf("\n[3] 해석\n\n");
    {
        unsigned ptr = 0;
        for (size_t i = 0; i < s->n; i++) {
            decode_packet(&s->v[i], &p);
            if (p.l7 == L7_DNS && !(p.dns.flags & 0x8000) && p.dns.qtype == 12)
                ptr++;
        }
        if (ptr)
            printf("- traceroute 는 각 홉 주소의 이름을 찾기 위해 DNS 역방향 질의(PTR)를 %u 번 보냄\n"
                   "  (패킷 목록에서는 제외함. -f \"dns\" 로 확인 가능, traceroute -n 으로 실행하면 생략됨)\n", ptr);
    }
    printf("- TTL 1~%d 까지 TTL 마다 프로브를 보냄. traceroute 는 여러 프로브를 한꺼번에 보내므로\n"
           "  응답 순서가 TTL 순서와 다를 수 있으며, 짝짓기는 인용된 원본 포트로 해야 정확함\n", maxttl);
    for (size_t k = 0; k < np; k++) {
        if (pr[k].resp_no && pr[k].rtype == 11) {
            printf("- 예) 프로브 No.%u (TTL %u) → %s 의 Time-to-live exceeded No.%u.\n"
                   "  응답 안에 인용된 원본 IP 헤더의 TTL 은 %u: 라우터에 도착했을 때 남은 TTL 이 %u 이었고,\n"
                   "  라우터가 1 감소시켜 0 이 되어 폐기하고 ICMP 를 돌려보냈음을 보여줌\n",
                   pr[k].no, pr[k].ttl, addr_s(&pr[k].from), pr[k].resp_no, pr[k].quoted_ttl, pr[k].quoted_ttl);
            break;
        }
    }
    if (reached)
        printf("- %d 번째 홉에서 목적지 %s 가 %s 로 응답 → 목적지 도달. 중간 라우터 %d 개 경유\n",
               reached_hop, addr_s(&target), pr[0].icmp_probe ? "Echo reply" : "Port unreachable", reached_hop - 1);
    if (reached && maxttl > reached_hop)
        printf("- TTL %d~%d 프로브는 미리 함께 보낸 것으로, 목적지까지 %d 홉이면 충분하므로 이들도 목적지에서 응답함.\n"
               "  traceroute 는 목적지에 도달한 홉(%d)까지만 출력함\n",
               reached_hop + 1, maxttl, reached_hop, reached_hop);
    if (!reached)
        printf("- 목적지의 Port unreachable 을 받지 못함: 목적지나 중간 방화벽이 UDP 프로브 또는 ICMP 응답을 차단했을 가능성\n");
    {
        int silent = 0;
        for (int ttl = 1; ttl <= (reached ? reached_hop : maxttl); ttl++) {
            int any = 0;
            for (size_t k = 0; k < np; k++)
                any |= pr[k].ttl == ttl && pr[k].resp_no;
            silent += !any;
        }
        if (silent)
            printf("- 응답이 없는 홉 %d 개(*): 해당 라우터가 ICMP 를 보내지 않도록 설정되었거나 응답을 제한함\n", silent);
    }
    free(pr);
}
