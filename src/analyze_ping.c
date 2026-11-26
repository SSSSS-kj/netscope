/*
 * analyze_ping.c - ping 명령어 ↔ ICMP Echo 연동 분석
 *
 * 1) Echo request 와 reply 를 (Identifier, Sequence, 주소 반대) 로 짝지음
 * 2) 패킷 타임스탬프로 RTT 계산 → ping 출력의 time= 값과 줄 단위 대조
 * 3) 송신/수신/손실률, rtt min/avg/max/mdev 를 ping 통계 줄과 대조
 * 4) 응답 TTL 로 경유 홉 수 추정
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

typedef struct {
    uint16_t        id, seq;
    addr_t          src, dst;
    uint32_t        req_no, rep_no;
    struct timespec req_ts, rep_ts;
    uint8_t         rep_ttl;
    int             replied;
} echo_t;

typedef struct {
    int    seq, ttl;
    double ms;
} outline_t;

typedef struct {
    int       n;
    outline_t line[1024];
    int       tx, rx;
    int       has_stat, has_rtt;
    double    rtt[4];            /* min, avg, max, mdev */
} pingout_t;

static void parse_ping_output(const char *text, pingout_t *po)
{
    const char *s = text;

    memset(po, 0, sizeof(*po));
    while (s && *s) {
        const char *e = strchr(s, '\n');
        size_t      len = e ? (size_t)(e - s) : strlen(s);
        char        line[512];
        char       *q;

        if (len >= sizeof(line))
            len = sizeof(line) - 1;
        memcpy(line, s, len);
        line[len] = '\0';

        if ((q = strstr(line, "icmp_seq=")) && po->n < 1024) {
            outline_t *o = &po->line[po->n];
            char *t;
            o->seq = atoi(q + 9);
            o->ttl = (t = strstr(line, "ttl=")) ? atoi(t + 4) : -1;
            o->ms  = (t = strstr(line, "time=")) ? strtod(t + 5, NULL) : -1;
            if (o->ms >= 0)
                po->n++;
        } else if ((q = strstr(line, "packets transmitted"))) {
            if (sscanf(line, "%d packets transmitted, %d", &po->tx, &po->rx) == 2)
                po->has_stat = 1;
        } else if ((q = strstr(line, "min/avg/max")) && (q = strchr(q, '='))) {
            if (sscanf(q + 1, " %lf/%lf/%lf/%lf", &po->rtt[0], &po->rtt[1], &po->rtt[2], &po->rtt[3]) == 4)
                po->has_rtt = 1;
        }
        s = e ? e + 1 : NULL;
    }
}

static const outline_t *find_line(const pingout_t *po, int seq)
{
    for (int i = 0; i < po->n; i++)
        if (po->line[i].seq == seq)
            return &po->line[i];
    return NULL;
}

void analyze_ping(const pktstore_t *s, const runctx_t *ctx)
{
    static pkt_t p;
    static pingout_t po;
    echo_t *e = calloc(s->n + 1, sizeof(*e));
    size_t  ne = 0;
    int     rx = 0, have_out = ctx->output != NULL;
    double  sum = 0, sum2 = 0, mn = 1e9, mx = 0;

    if (!e)
        return;
    if (have_out)
        parse_ping_output(ctx->output, &po);

    /* 1) Echo request/reply 짝짓기 */
    for (size_t i = 0; i < s->n; i++) {
        int v6;
        decode_packet(&s->v[i], &p);
        if (p.l4 != L4_ICMP && p.l4 != L4_ICMPV6)
            continue;
        v6 = p.l4 == L4_ICMPV6;
        if (p.icmp.type == (v6 ? 128 : 8)) {
            echo_t *x = &e[ne++];
            x->id = p.icmp.id;
            x->seq = p.icmp.seq;
            x->src = p.ip.src;
            x->dst = p.ip.dst;
            x->req_no = s->v[i].no;
            x->req_ts = s->v[i].ts;
        } else if (p.icmp.type == (v6 ? 129 : 0)) {
            for (size_t k = ne; k-- > 0;) {
                echo_t *x = &e[k];
                if (!x->replied && x->id == p.icmp.id && x->seq == p.icmp.seq &&
                    addr_eq(&x->dst, &p.ip.src) && addr_eq(&x->src, &p.ip.dst)) {
                    x->replied = 1;
                    x->rep_no = s->v[i].no;
                    x->rep_ts = s->v[i].ts;
                    x->rep_ttl = p.ip.ttl;
                    break;
                }
            }
        }
    }
    if (ne == 0) {
        printf("Echo request 패킷이 수집되지 않음\n");
        free(e);
        return;
    }

    /* 2) 줄 단위 대조 */
    printf("[1] Echo request/reply 짝짓기와 ping 출력 대조 (대상 %s, Identifier 0x%04x)\n\n",
           addr_s(&e[0].dst), e[0].id);
    put_col("  seq", 6);
    put_col("요청 No.", 10);
    put_col("응답 No.", 10);
    put_col("TTL", 6);
    put_col("RTT(패킷)", 13);
    put_col("RTT(ping)", 13);
    printf("차이(ms)\n");
    for (size_t k = 0; k < ne; k++) {
        echo_t *x = &e[k];
        const outline_t *ol = have_out ? find_line(&po, x->seq) : NULL;
        if (!x->replied) {
            printf("%5u %9u %9s %5s ", x->seq, x->req_no, "-", "-");
            put_col("응답 없음", 13);
            printf("%s\n", ol ? "?" : "-");
            continue;
        }
        double ms = ts_sub(&x->rep_ts, &x->req_ts) * 1000.0;
        rx++;
        sum += ms;
        sum2 += ms * ms;
        if (ms < mn) mn = ms;
        if (ms > mx) mx = ms;
        printf("%5u %9u %9u %5u %9.3f ms", x->seq, x->req_no, x->rep_no, x->rep_ttl, ms);
        if (ol)
            printf(" %9.3f ms %+9.3f\n", ol->ms, ol->ms - ms);
        else
            printf(" %12s\n", "-");
    }

    /* 3) 통계 대조 */
    double avg = rx ? sum / rx : 0, mdev = rx ? sqrt(fmax(0, sum2 / rx - avg * avg)) : 0;
    {
        int  st = have_out && po.has_stat;
        char a[64], b[64];

        printf("\n[2] 통계 대조\n\n");
        put_col("항목", 24);
        put_col("패킷 분석", 32);
        printf("%s\n", have_out ? "ping 출력" : "");

        snprintf(a, sizeof(a), "%zu", ne);
        snprintf(b, sizeof(b), "%d", po.tx);
        put_col("송신(transmitted)", 24); put_col(a, 32); printf("%s\n", st ? b : "");

        snprintf(a, sizeof(a), "%d", rx);
        snprintf(b, sizeof(b), "%d", po.rx);
        put_col("수신(received)", 24); put_col(a, 32); printf("%s\n", st ? b : "");

        snprintf(a, sizeof(a), "%.1f%%", 100.0 * (double)(ne - (size_t)rx) / (double)ne);
        snprintf(b, sizeof(b), "%.1f%%", po.tx ? 100.0 * (po.tx - po.rx) / po.tx : 0);
        put_col("손실률", 24); put_col(a, 32); printf("%s\n", st ? b : "");

        if (rx) {
            snprintf(a, sizeof(a), "%.3f/%.3f/%.3f/%.3f ms", mn, avg, mx, mdev);
            snprintf(b, sizeof(b), "%.3f/%.3f/%.3f/%.3f ms", po.rtt[0], po.rtt[1], po.rtt[2], po.rtt[3]);
            put_col("rtt min/avg/max/mdev", 24); put_col(a, 32); printf("%s\n", have_out && po.has_rtt ? b : "");
        }
    }

    /* 4) 해석 */
    printf("\n[3] 해석\n\n");
    printf("- 요청 %zu 개는 모두 Identifier 0x%04x 를 사용하고 Sequence 가 1씩 증가함 → ping 의 icmp_seq 와 일치\n",
           ne, e[0].id);
    if (rx) {
        int ttl = 0, init;
        for (size_t k = 0; k < ne; k++)
            if (e[k].replied) { ttl = e[k].rep_ttl; break; }
        init = ttl <= 64 ? 64 : ttl <= 128 ? 128 : 255;
        printf("- 응답 TTL %d: 초기 TTL 을 %d 로 가정하면 TTL 이 %d 번 감소함 (라우터를 지날 때마다 1 감소)\n", ttl, init, init - ttl);
        printf("  단, 방화벽·NAT 장비가 응답의 TTL 을 다시 쓰는 네트워크도 있으므로 실제 경로 길이는\n"
               "  traceroute 의 홉 수와 비교해서 판단해야 함\n");
        printf("- RTT(패킷)는 커널 수신 시각 기준, RTT(ping)는 ping 프로그램이 측정한 값이라 약간의 차이가 생김\n");
    }
    if ((size_t)rx < ne)
        printf("- 응답이 없는 요청 %zu 개: 상대 방화벽에서 ICMP 를 차단했거나 경로상 손실 가능성\n", ne - (size_t)rx);
    free(e);
}
