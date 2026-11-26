/*
 * main.c - 명령행 처리와 capture / read 모드
 *
 *   netscope capture [-i IF] [-f FILTER] [-c N] [-w FILE] [-v] [-x]
 *   netscope run     [-i IF] [-f FILTER] [-w FILE] [-g MS] [-S] [-v] [-x] [--] COMMAND [ARGS...]
 *   netscope read    [-f FILTER] [-a ANALYZER] [-c N] [-w FILE] [-v] [-x] FILE
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analyze.h"
#include "capture.h"
#include "decode.h"
#include "filter.h"
#include "netscope.h"
#include "output.h"
#include "pcapfile.h"
#include "store.h"

volatile sig_atomic_t g_sigint = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_sigint++;
}

static void usage(FILE *fp)
{
    fprintf(fp,
        "netscope %s - 패킷 수집·분석 프로그램\n\n"
        "사용법:\n"
        "  sudo netscope capture [-i IF] [-f FILTER] [-c N] [-w FILE] [-v] [-x]\n"
        "      실시간 수집. -f 는 수집 필터로 동작 (일치하는 패킷만 표시·저장)\n\n"
        "  sudo netscope run [-i IF] [-f FILTER] [-w FILE] [-a NAME] [-g MS] [-S] [-v] [-x] [--] COMMAND [ARGS...]\n"
        "      수집을 켠 상태에서 COMMAND 실행 → 종료 후 패킷 목록과 명령어 연동 분석 출력\n"
        "      COMMAND 는 sudo 이전 사용자 권한으로 실행. -w 는 수집한 전체 패킷 저장 (+ FILE.txt 에 명령어 출력)\n"
        "      분석기: ping, traceroute, nslookup, curl, netstat (그 외 명령어는 프로토콜 통계)\n\n"
        "  netscope read [-f FILTER] [-a ANALYZER] [-c N] [-w FILE] [-v] [-x] FILE.pcap\n"
        "      저장한 pcap 파일 분석. run 모드가 만든 FILE.pcap.txt 가 있으면 같은 연동 분석을 다시 실행\n\n"
        "옵션:\n"
        "  -i IF       수집 인터페이스 (기본: 전체)\n"
        "  -f FILTER   필터 식. 예) \"icmp\", \"udp port 53\", \"host 1.1.1.1 and (udp or icmp)\", \"all\"(전체)\n"
        "  -c N        N 개 표시 후 종료\n"
        "  -w FILE     pcap 파일로 저장 (Wireshark 로 열어 검증)\n"
        "  -v          계층별 상세 트리 출력\n"
        "  -x          hex 덤프 출력\n"
        "  -g MS       run: 명령어 종료 후 추가 수집 시간 (기본 1000ms)\n"
        "  -S          run: 소켓 상태(/proc/net/tcp) 추적 (netstat 연계)\n"
        "  -a NAME     분석기 지정 (ping, traceroute, nslookup, curl, netstat)\n",
        NETSCOPE_VERSION);
}

static int parse_opts(int argc, char **argv, options_t *o, int stop_at_command)
{
    int c;

    optind = 1;
    while ((c = getopt(argc, argv, stop_at_command ? "+i:f:w:c:a:g:Svxh" : "i:f:w:c:a:vxh")) != -1) {
        switch (c) {
        case 'i': o->ifname = optarg; break;
        case 'f': o->filter_expr = optarg; break;
        case 'w': o->wfile = optarg; break;
        case 'c': o->count = atol(optarg); break;
        case 'a': o->analyzer = optarg; break;
        case 'g': o->grace_ms = atoi(optarg); break;
        case 'S': o->sockwatch = 1; break;
        case 'v': o->verbose = 1; break;
        case 'x': o->hex = 1; break;
        case 'h': usage(stdout); exit(0);
        default:  usage(stderr); exit(2);
        }
    }
    return optind;
}

static filter_t *compile_or_die(const char *expr)
{
    char err[256];
    filter_t *f;

    if (!expr)
        return NULL;
    f = filter_compile(expr, err, sizeof(err));
    if (!f) {
        fprintf(stderr, "필터 오류: %s\n", err);
        exit(2);
    }
    return f;
}

int cmd_capture(const options_t *o)
{
    static uint8_t buf[SNAPLEN];
    static pkt_t   p;
    capture_t      cap;
    pcap_writer_t  w = { 0 };
    filter_t      *f = compile_or_die(o->filter_expr);
    outopt_t       oo = { o->verbose, o->hex, { 0, 0 } };
    rawpkt_t       r;
    uint32_t       no = 0;
    char           err[256];

    if (capture_open(&cap, o->ifname, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        filter_free(f);
        return 1;
    }
    if (o->wfile && pcapw_open(&w, o->wfile) < 0) {
        perror(o->wfile);
        capture_close(&cap);
        filter_free(f);
        return 1;
    }
    fprintf(stderr, "[netscope] %s 인터페이스 수집 시작 (필터: %s). 중지: Ctrl+C\n",
            cap.ifname, o->filter_expr ? o->filter_expr : "없음");
    clock_gettime(CLOCK_REALTIME, &oo.t0);
    output_header();

    while (!g_sigint) {
        int rc = capture_next(&cap, &r, buf, sizeof(buf), 200);
        if (rc < 0) {
            perror("recvmsg");
            break;
        }
        if (rc == 0)
            continue;
        decode_packet(&r, &p);
        if (!filter_match(f, &p))
            continue;
        r.no = ++no;
        output_packet(&oo, &p);
        if (w.fp)
            pcapw_write(&w, &r);
        if (o->count && no >= (uint32_t)o->count)
            break;
    }

    fprintf(stderr, "\n[netscope] %u 개 패킷 수집", no);
    if (w.fp)
        fprintf(stderr, " → %s 저장", o->wfile);
    fprintf(stderr, "\n");
    pcapw_close(&w);
    capture_close(&cap);
    filter_free(f);
    return 0;
}

/* run 모드가 저장한 FILE.txt 읽기: 머리줄(# cmd, # analyzer, # start) + 명령어 출력 */
static char *load_output_file(const char *pcap, char *cmd, size_t cn, char *an, size_t ann, struct timespec *start)
{
    char   path[600], line[1024];
    FILE  *fp;
    char  *text = NULL;
    size_t len = 0, cap = 0;

    snprintf(path, sizeof(path), "%s.txt", pcap);
    fp = fopen(path, "r");
    if (!fp)
        return NULL;
    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        if (!len && !strncmp(line, "# ", 2)) {
            long long sec;
            long nsec;
            line[strcspn(line, "\n")] = '\0';
            if (!strncmp(line, "# cmd: ", 7))
                snprintf(cmd, cn, "%.*s", (int)cn - 1, line + 7);
            else if (!strncmp(line, "# analyzer: ", 12))
                snprintf(an, ann, "%.*s", (int)ann - 1, line + 12);
            else if (sscanf(line, "# start: %lld.%ld", &sec, &nsec) == 2) {
                start->tv_sec = (time_t)sec;
                start->tv_nsec = nsec;
            }
            continue;
        }
        if (len + l + 1 > cap) {
            cap = (cap + l + 1) * 2;
            char *n = realloc(text, cap);
            if (!n)
                break;
            text = n;
        }
        memcpy(text + len, line, l + 1);
        len += l;
    }
    fclose(fp);
    return text ? text : strdup("");
}

int cmd_read(const options_t *o, const char *path)
{
    static uint8_t    buf[SNAPLEN];
    static pkt_t      p;
    pcap_reader_t     rd;
    pcap_writer_t     w = { 0 };
    pktstore_t        st;
    char              saved_cmd[512] = "", saved_an[32] = "";
    struct timespec   saved_start = { 0, 0 };
    char             *saved_out = load_output_file(path, saved_cmd, sizeof(saved_cmd), saved_an, sizeof(saved_an), &saved_start);
    const analyzer_t *an = o->analyzer ? analyzer_find(o->analyzer) : saved_an[0] ? analyzer_find(saved_an) : NULL;
    const char       *fexpr = o->filter_expr ? o->filter_expr : an ? an->default_filter : NULL;
    filter_t         *f = compile_or_die(fexpr);
    outopt_t          oo = { o->verbose, o->hex, saved_start };
    rawpkt_t          r;
    uint32_t          no = 0, shown = 0;
    char              err[256];
    int               rc;

    if (pcapr_open(&rd, path, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        filter_free(f);
        free(saved_out);
        return 1;
    }
    if (o->wfile && pcapw_open(&w, o->wfile) < 0) {
        perror(o->wfile);
        pcapr_close(&rd);
        filter_free(f);
        free(saved_out);
        return 1;
    }
    store_init(&st);
    if (saved_cmd[0])
        printf("%s[netscope] %s.txt: 명령어 \"%s\" 의 출력을 함께 분석%s\n", C_DIM, path, saved_cmd, C_RESET);
    output_header();
    while ((rc = pcapr_next(&rd, &r, buf, sizeof(buf))) == 1) {
        r.no = ++no;                      /* Wireshark 와 같은 파일 내 순번 */
        if (no == 1 && !saved_start.tv_sec)
            oo.t0 = r.ts;
        if (an)
            store_add(&st, &r);
        decode_packet(&r, &p);
        if (!filter_match(f, &p))
            continue;
        if (!o->count || shown < (uint32_t)o->count) {
            output_packet(&oo, &p);
            shown++;
        }
        if (w.fp)
            pcapw_write(&w, &r);
    }
    if (rc < 0)
        fprintf(stderr, "pcap 파일이 중간에 잘려 있음\n");
    printf("\n전체 %u 개 중 %u 개 표시 (필터: %s)\n", no, shown, fexpr ? fexpr : "없음");

    if (an) {
        runctx_t ctx;
        char     title[64];
        memset(&ctx, 0, sizeof(ctx));
        ctx.t_start = oo.t0;
        if (saved_out) {
            ctx.cmdline = saved_cmd;
            ctx.output = saved_out;
            ctx.output_len = strlen(saved_out);
        }
        snprintf(title, sizeof(title), "명령어 연동 분석: %s", an->cmd);
        output_section(title);
        an->analyze(&st, &ctx);
    }
    store_free(&st);
    free(saved_out);
    pcapw_close(&w);
    pcapr_close(&rd);
    filter_free(f);
    return 0;
}

int main(int argc, char **argv)
{
    options_t        o;
    struct sigaction sa;
    int              idx;

    memset(&o, 0, sizeof(o));
    o.grace_ms = 1000;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;          /* SA_RESTART 없음: poll 이 EINTR 로 깨어나도록 */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (!strcmp(argv[1], "capture")) {
        parse_opts(argc - 1, argv + 1, &o, 0);
        return cmd_capture(&o);
    }
    if (!strcmp(argv[1], "run")) {
        idx = parse_opts(argc - 1, argv + 1, &o, 1);
        if (idx >= argc - 1) {
            fprintf(stderr, "실행할 명령어가 필요함. 예) sudo netscope run -- ping -c 5 1.1.1.1\n");
            return 2;
        }
        return cmd_run(&o, argv + 1 + idx);
    }
    if (!strcmp(argv[1], "read")) {
        idx = parse_opts(argc - 1, argv + 1, &o, 0);
        if (idx >= argc - 1) {
            fprintf(stderr, "pcap 파일 경로가 필요함\n");
            return 2;
        }
        return cmd_read(&o, argv[1 + idx]);
    }
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        usage(stdout);
        return 0;
    }
    fprintf(stderr, "알 수 없는 모드: %s\n\n", argv[1]);
    usage(stderr);
    return 2;
}
