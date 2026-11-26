/*
 * runcmd.c - run 모드: 수집 중에 명령어를 실행하고, 끝나면 연동 분석
 *
 *  1. raw socket 을 먼저 열어 둠 (명령어의 첫 패킷부터 놓치지 않도록)
 *  2. forkpty() 로 명령어 실행 (의사 터미널이라 ping 등이 줄 단위로 바로 출력함)
 *     자식은 sudo 이전 사용자 권한으로 내려가서 실행
 *  3. 부모는 poll() 로 [패킷 수신]과 [명령어 출력]을 동시에 처리
 *     - 패킷: 메모리 보관 + pcap 저장
 *     - 출력: 화면에 그대로 보여주고 분석용으로 보관
 *  4. 명령어 종료 후 grace_ms 동안 늦게 도착하는 응답을 더 수집
 *  5. 패킷 목록 출력 → 명령어별 분석기 실행
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "analyze.h"
#include "capture.h"
#include "decode.h"
#include "filter.h"
#include "netscope.h"
#include "output.h"
#include "pcapfile.h"
#include "store.h"
#include "util.h"

typedef struct {
    char  *s;
    size_t len, cap;
} strbuf_t;

/* 의사 터미널 출력의 \r 은 제거해서 보관 */
static void sb_append(strbuf_t *b, const char *s, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t nc = (b->cap ? b->cap * 2 : 4096);
        while (nc < b->len + n + 1)
            nc *= 2;
        char *ns = realloc(b->s, nc);
        if (!ns)
            return;
        b->s = ns;
        b->cap = nc;
    }
    for (size_t i = 0; i < n; i++)
        if (s[i] != '\r')
            b->s[b->len++] = s[i];
    b->s[b->len] = '\0';
}

static const char *base_name(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* pcap 옆에 명령어와 출력을 저장 (read 모드에서 같은 분석을 다시 할 수 있도록) */
static void save_output_file(const char *wfile, char **argv, const char *analyzer,
                             const struct timespec *t_start, const char *text)
{
    char  path[600];
    FILE *fp;

    snprintf(path, sizeof(path), "%s.txt", wfile);
    fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "# netscope run\n# cmd:");
    for (char **a = argv; *a; a++)
        fprintf(fp, " %s", *a);
    fprintf(fp, "\n# analyzer: %s\n# start: %lld.%09ld\n", analyzer, (long long)t_start->tv_sec, t_start->tv_nsec);
    fputs(text, fp);
    fclose(fp);
    chown_to_sudo_user(path);
}

int cmd_run(const options_t *o, char **argv)
{
    static uint8_t    buf[SNAPLEN];
    static pkt_t      p;
    const analyzer_t *an = analyzer_find(o->analyzer ? o->analyzer : base_name(argv[0]));
    const char       *fexpr = o->filter_expr ? o->filter_expr : an->default_filter;
    filter_t         *f = NULL;
    capture_t         cap;
    pcap_writer_t     w = { 0 };
    pktstore_t        st;
    strbuf_t          out = { 0 };
    runctx_t          ctx;
    outopt_t          oo = { o->verbose, o->hex, { 0, 0 } };
    struct winsize    ws, *wsp = NULL;
    rawpkt_t          r;
    uint32_t          no = 0, shown = 0;
    int               master, master_open = 1, child_done = 0, status = 0;
    sig_atomic_t      forwarded = 0;
    pid_t             pid;
    char              err[256];

    if (fexpr) {
        f = filter_compile(fexpr, err, sizeof(err));
        if (!f) {
            fprintf(stderr, "필터 오류: %s\n", err);
            return 2;
        }
    }
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
    store_init(&st);
    memset(&ctx, 0, sizeof(ctx));
    if (o->sockwatch)
        sockwatch_init();

    printf("%s[netscope] 수집 시작 (인터페이스: %s) → 명령어 실행:", C_DIM, cap.ifname);
    for (char **a = argv; *a; a++)
        printf(" %s", *a);
    printf("%s\n", C_RESET);
    fflush(stdout);

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0)
        wsp = &ws;
    clock_gettime(CLOCK_REALTIME, &ctx.t_start);
    oo.t0 = ctx.t_start;

    pid = forkpty(&master, NULL, NULL, wsp);
    if (pid < 0) {
        perror("forkpty");
        pcapw_close(&w);
        capture_close(&cap);
        filter_free(f);
        return 1;
    }
    if (pid == 0) {
        close(cap.fd);
        drop_privileges();
        execvp(argv[0], argv);
        fprintf(stderr, "명령어 실행 실패: %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    for (;;) {
        struct pollfd pf[2] = { { cap.fd, POLLIN, 0 }, { master, POLLIN, 0 } };
        struct timespec now;

        poll(pf, master_open ? 2 : 1, 50);

        while (capture_recv(&cap, &r, buf, sizeof(buf)) == 1) {
            r.no = ++no;
            store_add(&st, &r);
            if (w.fp)
                pcapw_write(&w, &r);
        }

        if (master_open && (pf[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            char    tmp[4096];
            ssize_t k = read(master, tmp, sizeof(tmp));
            if (k > 0) {
                fwrite(tmp, 1, (size_t)k, stdout);
                fflush(stdout);
                sb_append(&out, tmp, (size_t)k);
            } else if (k == 0 || errno != EINTR) {   /* 자식 종료 시 EIO */
                close(master);
                master_open = 0;
            }
        }

        /* 의사 터미널이라 Ctrl+C 는 부모만 받음 → 자식에게 전달 (ping 통계 출력) */
        if (!child_done && g_sigint != forwarded) {
            kill(pid, g_sigint >= 3 ? SIGKILL : SIGINT);
            forwarded = g_sigint;
        }
        if (!child_done && waitpid(pid, &status, WNOHANG) == pid) {
            child_done = 1;
            clock_gettime(CLOCK_REALTIME, &ctx.t_end);
        }
        if (o->sockwatch)
            sockwatch_sample();

        if (child_done) {
            double ms;
            clock_gettime(CLOCK_REALTIME, &now);
            ms = ts_sub(&now, &ctx.t_end) * 1000.0;
            if ((ms >= o->grace_ms && !master_open) || ms >= o->grace_ms + 2000)
                break;
        }
    }
    if (master_open)
        close(master);

    if (w.fp)
        save_output_file(o->wfile, argv, an->cmd, &ctx.t_start, out.s ? out.s : "");

    ctx.argv        = argv;
    ctx.output      = out.s ? out.s : "";
    ctx.output_len  = out.len;
    ctx.exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);

    /* execvp 실패 (명령어 미설치) → 분석하지 않고 설치 안내 */
    if (ctx.exit_status == 127 && out.s && strstr(out.s, "명령어 실행 실패")) {
        static const struct { const char *cmd, *pkg; } pk[] = {
            { "ping", "iputils-ping" }, { "traceroute", "traceroute" }, { "nslookup", "dnsutils" },
            { "dig", "dnsutils" }, { "curl", "curl" }, { "netstat", "net-tools" },
        };
        const char *pkg = NULL;
        for (size_t i = 0; i < sizeof(pk) / sizeof(pk[0]); i++)
            if (!strcmp(base_name(argv[0]), pk[i].cmd))
                pkg = pk[i].pkg;
        fprintf(stderr, "\n[netscope] '%s' 명령어가 설치되어 있지 않아 분석을 건너뜀.\n", argv[0]);
        if (pkg)
            fprintf(stderr, "[netscope] 설치: sudo apt install -y %s\n", pkg);
        pcapw_close(&w);
        capture_close(&cap);
        store_free(&st);
        filter_free(f);
        free(out.s);
        return 127;
    }

    output_section("수집 패킷 목록");
    output_header();
    for (size_t i = 0; i < st.n; i++) {
        decode_packet(&st.v[i], &p);
        if (!filter_match(f, &p))
            continue;
        output_packet(&oo, &p);
        shown++;
    }
    printf("\n전체 %zu 개 중 %u 개 표시 (표시 필터: %s)", st.n, shown, fexpr ? fexpr : "없음");
    if (w.fp)
        printf(", 전체 패킷을 %s 에, 명령어 출력을 %s.txt 에 저장", o->wfile, o->wfile);
    printf("\n");

    {
        char title[64];
        snprintf(title, sizeof(title), "명령어 연동 분석: %s", an->cmd);
        output_section(title);
        an->analyze(&st, &ctx);
    }
    if (o->sockwatch)
        sockwatch_report(&st, &oo.t0);

    pcapw_close(&w);
    capture_close(&cap);
    store_free(&st);
    filter_free(f);
    free(out.s);
    return ctx.exit_status;
}
