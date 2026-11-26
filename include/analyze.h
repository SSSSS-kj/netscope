/*
 * analyze.h - 명령어별 연동 분석기
 *
 * run 모드에서 명령어 실행이 끝나면, argv[0] 이름으로 분석기를 골라
 * (수집한 패킷, 명령어 출력) 을 함께 넘긴다. 분석기는 둘을 대조해
 * "명령어 동작 ↔ 프로토콜 동작" 연계 결과를 출력한다.
 */
#ifndef NETSCOPE_ANALYZE_H
#define NETSCOPE_ANALYZE_H

#include <stddef.h>
#include <time.h>
#include "packet.h"
#include "store.h"

typedef struct {
    char          **argv;        /* 실행한 명령어 (read 모드에서는 NULL) */
    const char     *cmdline;     /* 명령어 문자열 (read 모드에서는 .txt 에서 읽음) */
    const char     *output;      /* 명령어 출력 전체 (없으면 NULL) */
    size_t          output_len;
    int             exit_status;
    struct timespec t_start, t_end;
} runctx_t;

typedef struct {
    const char *cmd;              /* 명령어 이름 */
    const char *default_filter;   /* -f 가 없을 때 쓰는 표시 필터 */
    void (*analyze)(const pktstore_t *s, const runctx_t *ctx);
} analyzer_t;

const analyzer_t *analyzer_find(const char *cmd);   /* 없으면 일반 통계 분석기 */

void analyze_generic(const pktstore_t *s, const runctx_t *ctx);
void analyze_ping(const pktstore_t *s, const runctx_t *ctx);
void analyze_traceroute(const pktstore_t *s, const runctx_t *ctx);
void analyze_nslookup(const pktstore_t *s, const runctx_t *ctx);
void analyze_curl(const pktstore_t *s, const runctx_t *ctx);
void analyze_netstat(const pktstore_t *s, const runctx_t *ctx);

/* 분석기 공용: 시간 기준점, 출력 줄 순회 */
struct timespec analysis_t0(const pktstore_t *s, const runctx_t *ctx);
const char     *next_line(const char *s, char *line, size_t n);   /* 다음 줄 시작 또는 NULL */

/* TCP 연결 요약 (analyze_tcp.c) - curl, netstat 분석기에서 공용 */
typedef struct {
    int             stream;
    addr_t          cli, srv;            /* cli = 스트림을 처음 연 쪽 */
    uint16_t        cport, sport;
    uint32_t        first_no, last_no, npkts;
    uint32_t        syn_no, synack_no, ack3_no;
    struct timespec syn_ts, synack_ts, ack3_ts;
    uint16_t        mss[2];
    int             ws[2];
    uint32_t        isn[2];
    uint32_t        bytes[2], segs[2];   /* [0] cli→srv, [1] srv→cli 페이로드 */
    uint32_t        fin_no[2], finack_no[2];
    struct timespec fin_ts[2];
    int             first_fin;           /* 먼저 FIN 을 보낸 쪽 0/1, 없으면 -1 */
    uint32_t        rst_no;
    int             rst_dir;
    uint32_t        req_no, resp_no;
    char            req[256], resp[256];
} tcpconn_t;

int  tcp_collect(const pktstore_t *s, tcpconn_t **out);   /* 연결 수 반환, *out 은 free 필요 */
const char *tcp_conn_state(const tcpconn_t *c, int side);  /* 패킷으로 추정한 side 쪽 소켓 상태 */

/* sockwatch.c: run 모드 -S 옵션, /proc/net/tcp 주기 조회 */
void sockwatch_init(void);
void sockwatch_sample(void);
void sockwatch_report(const pktstore_t *s, const struct timespec *t0);

#endif
