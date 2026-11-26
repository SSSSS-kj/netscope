/*
 * analyze_tcp.c - curl 명령어 ↔ TCP/HTTP 연동 분석
 *
 * 1) 스트림(4-튜플)별로 세그먼트를 모아 연결 설정 / 데이터 전송 / 연결 종료 단계로 나눠 출력
 * 2) 3-way handshake 의 초기 순서번호(ISN), MSS/WS 옵션, 핸드셰이크 RTT
 * 3) Seq/Ack 증가량으로 전송 바이트 수 확인, HTTP 요청·응답 위치
 * 4) 4-way 종료에서 먼저 FIN 을 보낸 쪽과 양쪽 소켓의 최종 상태 추정
 * 5) curl -v 출력("Connected to", "> 요청 줄", "< 상태 줄")과 대조
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

#define SWAP(T, a, b) do { T _t = (a); (a) = (b); (b) = _t; } while (0)

int tcp_collect(const pktstore_t *s, tcpconn_t **out)
{
    static pkt_t p;
    tcpconn_t *c = NULL;
    int       *cli_dir = NULL;
    uint32_t  *fin_next = NULL;   /* [conn*2 + dir] FIN 다음 상대 순서번호 */
    int        n = 0, cap = 0;

    for (size_t i = 0; i < s->n; i++) {
        tcpconn_t *x;
        int        k, d;
        const tcp_t *t;

        decode_packet(&s->v[i], &p);
        if (p.l4 != L4_TCP || p.truncated)
            continue;
        t = &p.tcp;
        for (k = 0; k < n && c[k].stream != t->stream; k++)
            ;
        if (k == n) {
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                c = realloc(c, (size_t)cap * sizeof(*c));
                cli_dir = realloc(cli_dir, (size_t)cap * sizeof(*cli_dir));
                fin_next = realloc(fin_next, (size_t)cap * 2 * sizeof(*fin_next));
                if (!c || !cli_dir || !fin_next)
                    return 0;
            }
            x = &c[n];
            memset(x, 0, sizeof(*x));
            x->stream = t->stream;
            x->first_fin = -1;
            x->rst_dir = -1;
            x->ws[0] = x->ws[1] = -1;
            x->first_no = s->v[i].no;
            /* dir 0 = 스트림 첫 세그먼트 송신 측 */
            if (t->dir == 0) {
                x->cli = p.ip.src; x->srv = p.ip.dst; x->cport = t->sport; x->sport = t->dport;
            } else {
                x->cli = p.ip.dst; x->srv = p.ip.src; x->cport = t->dport; x->sport = t->sport;
            }
            cli_dir[n] = 0;
            fin_next[2 * n] = fin_next[2 * n + 1] = 0;
            n++;
        }
        x = &c[k];
        d = t->dir;
        x->last_no = s->v[i].no;
        x->npkts++;

        if ((t->flags & TCP_SYN) && !(t->flags & TCP_ACK)) {
            if (!x->syn_no) {
                x->syn_no = s->v[i].no;
                x->syn_ts = s->v[i].ts;
            }
            cli_dir[k] = d;
            x->isn[d] = t->seq;
            x->mss[d] = t->mss;
            x->ws[d] = t->wscale;
        } else if ((t->flags & TCP_SYN) && (t->flags & TCP_ACK)) {
            if (!x->synack_no) {
                x->synack_no = s->v[i].no;
                x->synack_ts = s->v[i].ts;
            }
            x->isn[d] = t->seq;
            x->mss[d] = t->mss;
            x->ws[d] = t->wscale;
        } else if (x->synack_no && !x->ack3_no && d == cli_dir[k] && (t->flags & TCP_ACK)) {
            x->ack3_no = s->v[i].no;
            x->ack3_ts = s->v[i].ts;
        }
        if (p.payload_len) {
            x->bytes[d] += p.payload_len;
            x->segs[d]++;
        }
        if (p.l7 == L7_HTTP) {
            if (p.http.is_request && !x->req_no) {
                x->req_no = s->v[i].no;
                snprintf(x->req, sizeof(x->req), "%s", p.http.line);
            } else if (!p.http.is_request && !x->resp_no) {
                x->resp_no = s->v[i].no;
                snprintf(x->resp, sizeof(x->resp), "%s", p.http.line);
            }
        }
        if ((t->flags & TCP_ACK) && fin_next[2 * k + !d] && !x->finack_no[d] &&
            (int32_t)(t->rel_ack - fin_next[2 * k + !d]) >= 0)
            x->finack_no[d] = s->v[i].no;
        if ((t->flags & TCP_FIN) && !x->fin_no[d]) {
            x->fin_no[d] = s->v[i].no;
            x->fin_ts[d] = s->v[i].ts;
            fin_next[2 * k + d] = tcp_next_rel_seq(&p);
            if (x->first_fin < 0)
                x->first_fin = d;
        }
        if ((t->flags & TCP_RST) && !x->rst_no) {
            x->rst_no = s->v[i].no;
            x->rst_dir = d;
        }
    }

    /* SYN 을 보낸 쪽이 dir 1 이면 [0]=클라이언트 가 되도록 맞춤 */
    for (int k = 0; k < n; k++) {
        tcpconn_t *x = &c[k];
        if (cli_dir[k] != 1)
            continue;
        SWAP(addr_t, x->cli, x->srv);
        SWAP(uint16_t, x->cport, x->sport);
        SWAP(uint16_t, x->mss[0], x->mss[1]);
        SWAP(int, x->ws[0], x->ws[1]);
        SWAP(uint32_t, x->isn[0], x->isn[1]);
        SWAP(uint32_t, x->bytes[0], x->bytes[1]);
        SWAP(uint32_t, x->segs[0], x->segs[1]);
        SWAP(uint32_t, x->fin_no[0], x->fin_no[1]);
        SWAP(uint32_t, x->finack_no[0], x->finack_no[1]);
        SWAP(struct timespec, x->fin_ts[0], x->fin_ts[1]);
        if (x->first_fin >= 0)
            x->first_fin = !x->first_fin;
        if (x->rst_dir >= 0)
            x->rst_dir = !x->rst_dir;
    }
    /* 스트림의 dir 과 정규화된 방향의 관계를 stream 부호로 기록하지 않고, 호출 측이 주소로 판별 */
    free(cli_dir);
    free(fin_next);
    *out = c;
    return n;
}

const char *tcp_conn_state(const tcpconn_t *c, int side)
{
    int other = !side;

    if (c->rst_no)
        return "CLOSED (RST)";
    if (c->syn_no && !c->synack_no)
        return side == 0 ? "SYN_SENT" : "SYN_RECV";
    if (c->first_fin < 0)
        return "ESTABLISHED";
    if (c->first_fin == side) {                    /* 먼저 닫은 쪽 (active close) */
        if (c->fin_no[other])
            return c->finack_no[side] ? "TIME_WAIT" : "CLOSING";
        return c->finack_no[other] ? "FIN_WAIT2" : "FIN_WAIT1";
    }
    if (!c->fin_no[side])                          /* 나중에 닫는 쪽 (passive close) */
        return "CLOSE_WAIT";
    return c->finack_no[other] ? "CLOSED" : "LAST_ACK";
}

static int is_client_side(const tcpconn_t *c, const pkt_t *p)
{
    return p->tcp.sport == c->cport && addr_eq(&p->ip.src, &c->cli);
}

static void print_stream(const pktstore_t *s, const tcpconn_t *c, const struct timespec *t0)
{
    static pkt_t p;
    uint32_t last_ack[2] = { 0, 0 };
    int      phase = -1, shown = 0, fin_seen = 0;
    static const char *phase_name[] = { "연결 설정 (3-way handshake)", "데이터 전송", "연결 종료 (4-way handshake)" };

    printf("\n[TCP 스트림 %d] %s:%u (클라이언트) ↔ %s:%u (서버), 세그먼트 %u 개\n",
           c->stream, addr_s(&c->cli), c->cport, addr_s(&c->srv), c->sport, c->npkts);
    printf("  %-6s %-10s ", "No.", "Time");
    put_col("방향", 6);
    put_col("플래그", 14);
    printf("%8s %8s %6s  ", "Seq", "Ack", "Len");
    printf("설명\n");

    for (size_t i = 0; i < s->n; i++) {
        char fl[48], note[320] = "";
        int  cs, d, ph;

        decode_packet(&s->v[i], &p);
        if (p.l4 != L4_TCP || p.tcp.stream != c->stream)
            continue;
        cs = is_client_side(c, &p);
        d = cs ? 0 : 1;
        tcp_flags_str(p.tcp.flags, fl, sizeof(fl));

        if (p.tcp.flags & TCP_FIN)
            fin_seen = 1;
        ph = (p.tcp.flags & TCP_SYN) || s->v[i].no == c->ack3_no ? 0 : fin_seen ? 2 : 1;
        if (ph != phase) {
            printf("  ── %s\n", phase_name[ph]);
            phase = ph;
        }

        if ((p.tcp.flags & TCP_SYN) && !(p.tcp.flags & TCP_ACK))
            snprintf(note, sizeof(note), "연결 요청, ISN %u, MSS %u, WS %u", p.tcp.seq, p.tcp.mss, tcp_ws_mult(p.tcp.wscale));
        else if ((p.tcp.flags & TCP_SYN) && (p.tcp.flags & TCP_ACK))
            snprintf(note, sizeof(note), "연결 수락, ISN %u, Ack = 클라이언트 ISN + 1", p.tcp.seq);
        else if (s->v[i].no == c->ack3_no)
            snprintf(note, sizeof(note), "handshake 완료 → ESTABLISHED");
        else if (p.tcp.flags & TCP_RST)
            snprintf(note, sizeof(note), "연결 강제 종료(RST)");
        else if ((p.tcp.flags & TCP_FIN) && c->first_fin == d)
            snprintf(note, sizeof(note), "%s가 먼저 종료 요청 (active close)", cs ? "클라이언트" : "서버");
        else if (p.tcp.flags & TCP_FIN)
            snprintf(note, sizeof(note), "%s도 종료 요청", cs ? "클라이언트" : "서버");
        else if (p.l7 == L7_HTTP)
            snprintf(note, sizeof(note), "HTTP %s: %s", p.http.is_request ? "요청" : "응답", p.http.line);
        else if (p.payload_len)
            snprintf(note, sizeof(note), "데이터 %u 바이트%s", p.payload_len, c->sport == 443 ? " (TLS 암호화)" : "");
        else if ((p.tcp.flags & TCP_ACK) && last_ack[d] && p.tcp.rel_ack > last_ack[d])
            snprintf(note, sizeof(note), "상대 데이터 %u 바이트 수신 확인", p.tcp.rel_ack - last_ack[d] - (c->fin_no[!d] && s->v[i].no > c->fin_no[!d] ? 1 : 0));
        if (c->fin_no[!d] && s->v[i].no == c->finack_no[d] && !(p.tcp.flags & TCP_FIN))
            snprintf(note, sizeof(note), "상대 FIN 수신 확인%s", c->first_fin == d ? " → TIME_WAIT" : "");

        if ((p.tcp.flags & TCP_ACK))
            last_ack[d] = p.tcp.rel_ack;
        if (++shown > 80) {
            if (shown == 81)
                printf("  ... (이후 세그먼트 생략)\n");
            continue;
        }
        printf("  %-6u %-10.6f ", s->v[i].no, ts_sub(&s->v[i].ts, t0));
        put_col(cs ? "C→S" : "S→C", 6);
        put_col(fl, 14);
        printf("%8u ", p.tcp.rel_seq);
        if (p.tcp.flags & TCP_ACK)
            printf("%8u ", p.tcp.rel_ack);
        else
            printf("%8s ", "-");
        printf("%6u  %s\n", p.payload_len, note);
    }

    printf("\n  요약\n");
    if (c->syn_no && c->synack_no)
        printf("  - 핸드셰이크 RTT (SYN No.%u → SYN,ACK No.%u): %.3f ms\n",
               c->syn_no, c->synack_no, ts_sub(&c->synack_ts, &c->syn_ts) * 1000.0);
    if (c->mss[0] || c->mss[1])
        printf("  - MSS 협상: 클라이언트 %u, 서버 %u → 작은 값 기준으로 세그먼트 크기 결정\n", c->mss[0], c->mss[1]);
    printf("  - 전송량: 클라이언트→서버 %u 바이트(%u 세그먼트), 서버→클라이언트 %u 바이트(%u 세그먼트)\n",
           c->bytes[0], c->segs[0], c->bytes[1], c->segs[1]);
    if (c->first_fin >= 0)
        printf("  - %s가 먼저 FIN 을 보냄 → 추정 소켓 상태: 클라이언트 %s, 서버 %s\n",
               c->first_fin == 0 ? "클라이언트" : "서버", tcp_conn_state(c, 0), tcp_conn_state(c, 1));
    else
        printf("  - 종료 과정이 수집되지 않음 → 추정 소켓 상태: %s\n", tcp_conn_state(c, 0));
}

void analyze_curl(const pktstore_t *s, const runctx_t *ctx)
{
    static pkt_t p;
    tcpconn_t *c;
    struct timespec t0 = analysis_t0(s, ctx);
    int n = tcp_collect(s, &c), ndns = 0;

    /* 0) 이름 해석 */
    for (size_t i = 0; i < s->n; i++) {
        char info[512];
        decode_packet(&s->v[i], &p);
        if (p.l7 != L7_DNS)
            continue;
        if (!ndns++)
            printf("[0] 연결 전 이름 해석 (DNS)\n\n");
        info_string(&p, info, sizeof(info));
        printf("  No.%-5u %s\n", s->v[i].no, info);
    }

    if (n == 0) {
        printf("TCP 세그먼트가 수집되지 않음\n");
        free(c);
        return;
    }
    printf("%s[1] TCP 연결 단계별 분석 (스트림 %d 개)\n", ndns ? "\n" : "", n);
    for (int k = 0; k < n; k++)
        print_stream(s, &c[k], &t0);

    /* 2) curl 출력 대조 */
    if (ctx->output) {
        char line[512];
        int  verbose = 0;

        printf("\n[2] curl 출력과 대조\n\n");
        for (const char *t = ctx->output; t && *t;) {
            char *q;
            t = next_line(t, line, sizeof(line));
            if ((q = strstr(line, "Connected to "))) {
                char ip[64] = "";
                unsigned port = 0;
                char *l = strchr(q, '('), *r = l ? strchr(l, ')') : NULL;
                verbose = 1;
                if (l && r && (size_t)(r - l - 1) < sizeof(ip)) {
                    memcpy(ip, l + 1, (size_t)(r - l - 1));
                    ip[r - l - 1] = '\0';
                }
                if ((q = strstr(line, "port ")))
                    port = (unsigned)atoi(q + 5);
                int hit = -1;
                for (int k = 0; k < n; k++)
                    if (!strcmp(addr_s(&c[k].srv), ip) && c[k].sport == port)
                        hit = k;
                printf("%-60s ↔ ", line);
                if (hit >= 0)
                    printf("스트림 %d handshake No.%u~%u (주소·포트 일치 O)\n", hit, c[hit].syn_no, c[hit].ack3_no);
                else
                    printf("일치하는 TCP 연결 없음 X\n");
            } else if (!strncmp(line, "> ", 2) && line[2] >= 'A' && line[2] <= 'Z' && strstr(line, "HTTP/")) {
                int hit = -1;
                for (int k = 0; k < n; k++)
                    if (!strcmp(c[k].req, line + 2))
                        hit = k;
                printf("%-60s ↔ ", line);
                if (hit >= 0)
                    printf("HTTP 요청 No.%u (요청 줄 일치 O)\n", c[hit].req_no);
                else
                    printf("HTTP 요청 패킷 없음 (HTTPS 는 암호화되어 확인 불가)\n");
            } else if (!strncmp(line, "< HTTP/", 7)) {
                int hit = -1;
                for (int k = 0; k < n; k++)
                    if (!strcmp(c[k].resp, line + 2))
                        hit = k;
                printf("%-60s ↔ ", line);
                if (hit >= 0)
                    printf("HTTP 응답 No.%u (상태 줄 일치 O)\n", c[hit].resp_no);
                else
                    printf("HTTP 응답 패킷 없음 (HTTPS 는 암호화되어 확인 불가)\n");
            } else if (strstr(line, "Content-Length:") && line[0] == '<') {
                printf("%-60s ↔ 서버→클라이언트 페이로드 합계에는 응답 헤더 길이도 포함됨\n", line);
            } else if (strstr(line, "Closing connection") || strstr(line, "left intact")) {
                printf("%-60s ↔ ", line);
                if (c[0].first_fin >= 0)
                    printf("FIN No.%u (%s 먼저 종료)\n", c[0].fin_no[c[0].first_fin], c[0].first_fin == 0 ? "클라이언트" : "서버");
                else
                    printf("FIN 없음\n");
            }
        }
        if (!verbose)
            printf("curl -v 옵션으로 실행하면 연결·요청·응답 단계를 출력과 줄 단위로 대조할 수 있음\n");
    }
    free(c);
}
