/*
 * analyze_netstat.c - netstat 명령어 ↔ TCP 연결 상태 연동 분석
 *
 * netstat 은 패킷을 만들지 않고 커널 소켓 표(/proc/net/tcp)를 읽어 보여주는 명령어이다.
 * 그래서 TCP 연결을 만드는 명령어(curl)와 함께 실행해서 연계한다.
 *
 *   sudo ./netscope run -a netstat -S -- sh -c "curl -s -o /dev/null http://example.com; netstat -tn"
 *
 * 1) netstat 출력의 각 연결(Proto, Local, Foreign, State)을 파싱
 * 2) 같은 4-튜플의 TCP 스트림을 수집 패킷에서 찾아, 패킷 흐름으로 추정한 상태와 netstat 상태를 대조
 * 3) 상태별 의미 설명 (TIME_WAIT 은 먼저 FIN 을 보낸 쪽에 남음 등)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

static const struct { const char *st, *desc; } meanings[] = {
    { "LISTEN",      "연결 대기 중인 서버 소켓 (패킷 없음)" },
    { "SYN_SENT",    "SYN 을 보내고 SYN,ACK 를 기다리는 중" },
    { "SYN_RECV",    "SYN 을 받고 SYN,ACK 를 보낸 뒤 ACK 를 기다리는 중" },
    { "ESTABLISHED", "3-way handshake 완료, 데이터 송수신 가능" },
    { "FIN_WAIT1",   "먼저 FIN 을 보내고 ACK 를 기다리는 중" },
    { "FIN_WAIT2",   "내 FIN 에 대한 ACK 는 받았고 상대 FIN 을 기다리는 중" },
    { "TIME_WAIT",   "먼저 종료한 쪽이 상대 FIN 에 ACK 를 보낸 뒤 늦은 패킷에 대비해 잠시 대기" },
    { "CLOSE_WAIT",  "상대 FIN 을 받았고 내 프로그램이 아직 close 하지 않음" },
    { "LAST_ACK",    "나중에 FIN 을 보내고 마지막 ACK 를 기다리는 중" },
    { "CLOSING",     "양쪽이 동시에 FIN 을 보낸 상태" },
};

static const char *meaning(const char *st)
{
    for (size_t i = 0; i < sizeof(meanings) / sizeof(meanings[0]); i++)
        if (!strcmp(meanings[i].st, st))
            return meanings[i].desc;
    return "";
}

/* "10.0.2.15:22", ":::22", "0.0.0.0:*" → 주소, 포트 */
static int split_endpoint(const char *s, addr_t *a, unsigned *port)
{
    char  buf[80];
    char *c;

    snprintf(buf, sizeof(buf), "%s", s);
    c = strrchr(buf, ':');
    if (!c)
        return -1;
    *c = '\0';
    *port = c[1] == '*' ? 0 : (unsigned)atoi(c + 1);
    return addr_parse(buf, a);
}

void analyze_netstat(const pktstore_t *s, const runctx_t *ctx)
{
    tcpconn_t *c = NULL;
    int  n = tcp_collect(s, &c), lines = 0, matched = 0, agree = 0;
    char line[512];

    if (!ctx->output) {
        printf("netstat 출력이 없음 (run 모드 또는 .txt 출력 파일 필요)\n");
        free(c);
        return;
    }
    printf("[1] netstat 출력의 TCP 연결과 수집 패킷 대조 (수집된 TCP 스트림 %d 개)\n\n", n);

    for (const char *t = ctx->output; t && *t;) {
        char proto[16], local[80], foreign[80], state[32] = "";
        unsigned rq, sq, lp, fp;
        addr_t la, fa;

        t = next_line(t, line, sizeof(line));
        if (sscanf(line, "%15s %u %u %79s %79s %31s", proto, &rq, &sq, local, foreign, state) < 5 ||
            strncmp(proto, "tcp", 3))
            continue;
        lines++;
        printf("%s\n", line);
        printf("    → 상태 의미: %s\n", meaning(state));
        if (split_endpoint(local, &la, &lp) < 0 || split_endpoint(foreign, &fa, &fp) < 0 || !fp) {
            printf("\n");
            continue;
        }
        for (int k = 0; k < n; k++) {
            const tcpconn_t *x = &c[k];
            int side = -1;
            if (addr_eq(&x->cli, &la) && x->cport == lp && addr_eq(&x->srv, &fa) && x->sport == fp)
                side = 0;
            else if (addr_eq(&x->srv, &la) && x->sport == lp && addr_eq(&x->cli, &fa) && x->cport == fp)
                side = 1;
            if (side < 0)
                continue;
            const char *est = tcp_conn_state(x, side);
            int ok = !strcmp(est, state);
            matched++;
            agree += ok;
            printf("    → 수집 패킷: 스트림 %d (%s 쪽), SYN No.%u, SYN,ACK No.%u", x->stream,
                   side == 0 ? "클라이언트" : "서버", x->syn_no, x->synack_no);
            if (x->first_fin >= 0)
                printf(", 먼저 FIN No.%u (%s)", x->fin_no[x->first_fin], x->first_fin == 0 ? "클라이언트" : "서버");
            if (x->fin_no[!x->first_fin] && x->first_fin >= 0)
                printf(", 나중 FIN No.%u", x->fin_no[!x->first_fin]);
            printf("\n    → 패킷 흐름으로 추정한 상태 %s ↔ netstat 상태 %s: %s\n", est, state, ok ? "일치 O" : "다름 X");
            break;
        }
        printf("\n");
    }
    if (!lines) {
        printf("netstat 출력에서 TCP 연결 줄을 찾지 못함 (netstat -tn 형식 권장)\n");
        free(c);
        return;
    }

    printf("[2] 해석\n\n");
    printf("- netstat 의 TCP 연결 %d 개 중 %d 개가 수집 기간의 TCP 스트림과 대응, 그 중 %d 개는 상태까지 일치\n",
           lines, matched, agree);
    printf("- netstat 자체는 패킷을 보내지 않고 커널 소켓 표(/proc/net/tcp)를 읽어 보여줌\n");
    printf("- 패킷 흐름(SYN → SYN,ACK → ACK → ... → FIN)에 따라 커널이 소켓 상태를 바꾸고, netstat 은 그 결과를 보여줌\n");
    for (int k = 0; k < n; k++) {
        if (c[k].first_fin >= 0 && !strcmp(tcp_conn_state(&c[k], c[k].first_fin), "TIME_WAIT")) {
            printf("- 스트림 %d: %s가 먼저 FIN 을 보냈으므로 %s 쪽 소켓이 TIME_WAIT 로 남음\n", c[k].stream,
                   c[k].first_fin == 0 ? "클라이언트" : "서버", c[k].first_fin == 0 ? "클라이언트" : "서버");
            break;
        }
    }
    free(c);
}
