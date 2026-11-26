/*
 * sockwatch.c - TCP 소켓 상태 추적 (netstat 연계)
 *
 * netstat 은 커널 소켓 표(/proc/net/tcp, /proc/net/tcp6)를 읽어 보여주는 명령어이다.
 * run 모드에서 -S 옵션을 주면 수집하는 동안 같은 표를 주기적으로 읽어
 * 소켓 상태가 바뀐 시각을 기록하고, 그 시각을 SYN/FIN/RST 패킷 시각과 나란히 보여준다.
 *
 * /proc/net/tcp 한 줄 예:
 *   sl  local_address rem_address   st ...
 *    0: 0F02000A:D2F4 01010101:0050 01 ...
 *   주소는 커널 메모리의 4바이트를 16진수로 찍은 값(리틀 엔디언 호스트에서는 바이트가 뒤집혀 보임),
 *   포트는 16진수, st 는 상태 코드
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"
#include "util.h"

#define MAX_SOCK 1024

typedef struct {
    addr_t   l, r;
    uint16_t lp, rp;
    int      st;
} sock_t;

typedef struct {
    struct timespec ts;
    sock_t          s;
    int             from;   /* 0 = 표에 없던 소켓 */
} trans_t;

static sock_t   cur[MAX_SOCK];
static int      ncur, active;
static trans_t *tr;
static int      ntr, captr;
static struct timespec last;

static const char *st_name(int st)
{
    static const char *n[] = { "(없음)", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
                               "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING" };
    return st >= 0 && st < 12 ? n[st] : "?";
}

static void hex_addr(const char *h, addr_t *a)
{
    size_t len = strlen(h);

    memset(a, 0, sizeof(*a));
    a->family = len == 32 ? AF_INET6 : AF_INET;
    for (size_t w = 0; w * 8 < len && w < 4; w++) {
        char     part[9];
        uint32_t v;
        memcpy(part, h + w * 8, 8);
        part[8] = '\0';
        v = (uint32_t)strtoul(part, NULL, 16);
        memcpy(a->a + w * 4, &v, 4);      /* 커널 메모리 순서 그대로 = 네트워크 바이트 순서 */
    }
}

static int read_table(sock_t *out, int max)
{
    static const char *files[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    int n = 0;

    for (int f = 0; f < 2; f++) {
        FILE *fp = fopen(files[f], "r");
        char  line[512];
        if (!fp)
            continue;
        if (!fgets(line, sizeof(line), fp)) {   /* 머리줄 */
            fclose(fp);
            continue;
        }
        while (n < max && fgets(line, sizeof(line), fp)) {
            char la[40], ra[40];
            unsigned lp, rp, st;
            if (sscanf(line, " %*d: %39[0-9A-Fa-f]:%x %39[0-9A-Fa-f]:%x %x", la, &lp, ra, &rp, &st) != 5)
                continue;
            hex_addr(la, &out[n].l);
            hex_addr(ra, &out[n].r);
            out[n].lp = (uint16_t)lp;
            out[n].rp = (uint16_t)rp;
            out[n].st = (int)st;
            n++;
        }
        fclose(fp);
    }
    return n;
}

static int same(const sock_t *a, const sock_t *b)
{
    return a->lp == b->lp && a->rp == b->rp && addr_eq(&a->l, &b->l) && addr_eq(&a->r, &b->r);
}

static void add_tr(const struct timespec *ts, const sock_t *s, int from)
{
    if (s->st == 10 && from == 0)   /* LISTEN 소켓 생성은 제외 */
        return;
    if (ntr == captr) {
        captr = captr ? captr * 2 : 64;
        trans_t *n = realloc(tr, (size_t)captr * sizeof(*tr));
        if (!n)
            return;
        tr = n;
    }
    tr[ntr].ts = *ts;
    tr[ntr].s = *s;
    tr[ntr].from = from;
    ntr++;
}

void sockwatch_init(void)
{
    active = 1;
    ncur = read_table(cur, MAX_SOCK);
    clock_gettime(CLOCK_REALTIME, &last);
}

void sockwatch_sample(void)
{
    static sock_t nw[MAX_SOCK];
    struct timespec now;
    int nn;

    if (!active)
        return;
    clock_gettime(CLOCK_REALTIME, &now);
    if (ts_sub(&now, &last) < 0.002)   /* 2ms 보다 자주 읽지 않음 */
        return;
    last = now;
    nn = read_table(nw, MAX_SOCK);

    for (int i = 0; i < nn; i++) {
        int k;
        for (k = 0; k < ncur && !same(&cur[k], &nw[i]); k++)
            ;
        if (k == ncur)
            add_tr(&now, &nw[i], 0);
        else if (cur[k].st != nw[i].st)
            add_tr(&now, &nw[i], cur[k].st);
    }
    for (int k = 0; k < ncur; k++) {
        int i;
        for (i = 0; i < nn && !same(&cur[k], &nw[i]); i++)
            ;
        if (i == nn && cur[k].st != 10) {
            sock_t gone = cur[k];
            int    from = gone.st;
            gone.st = 0;
            add_tr(&now, &gone, from);
        }
    }
    memcpy(cur, nw, (size_t)nn * sizeof(*nw));
    ncur = nn;
}

typedef struct {
    struct timespec ts;
    int             kind;      /* 0 소켓, 1 패킷 */
    int             idx;
    uint32_t        no;
    char            text[200];
} ev_t;

static int ev_cmp(const void *a, const void *b)
{
    const ev_t *x = a, *y = b;
    double d = ts_sub(&x->ts, &y->ts);
    return d < 0 ? -1 : d > 0 ? 1 : x->kind - y->kind;
}

void sockwatch_report(const pktstore_t *s, const struct timespec *t0)
{
    static pkt_t p;
    ev_t *ev;
    int   ne = 0;

    output_section("소켓 상태 변화 (/proc/net/tcp 조회, netstat 연계)");
    if (ntr == 0) {
        printf("수집 중 TCP 소켓 상태 변화가 없음\n");
        return;
    }
    ev = calloc((size_t)ntr + s->n + 1, sizeof(*ev));
    if (!ev)
        return;
    for (int i = 0; i < ntr; i++) {
        ev[ne].ts = tr[i].ts;
        ev[ne].kind = 0;
        snprintf(ev[ne].text, sizeof(ev[ne].text), "[소켓] %s:%u ↔ %s:%u  %s → %s",
                 addr_s(&tr[i].s.l), tr[i].s.lp, addr_s(&tr[i].s.r), tr[i].s.rp,
                 st_name(tr[i].from), st_name(tr[i].s.st));
        ne++;
    }
    for (size_t i = 0; i < s->n; i++) {
        char fl[48];
        int  rel = 0;
        decode_packet(&s->v[i], &p);
        if (p.l4 != L4_TCP || !(p.tcp.flags & (TCP_SYN | TCP_FIN | TCP_RST)))
            continue;
        /* 상태 변화가 기록된 소켓과 관련된 패킷만 */
        for (int k = 0; k < ntr && !rel; k++) {
            const sock_t *so = &tr[k].s;
            rel = (so->lp == p.tcp.sport && so->rp == p.tcp.dport && addr_eq(&so->r, &p.ip.dst)) ||
                  (so->lp == p.tcp.dport && so->rp == p.tcp.sport && addr_eq(&so->r, &p.ip.src));
        }
        if (!rel)
            continue;
        tcp_flags_str(p.tcp.flags, fl, sizeof(fl));
        ev[ne].ts = s->v[i].ts;
        ev[ne].kind = 1;
        snprintf(ev[ne].text, sizeof(ev[ne].text), "  [패킷 No.%u] %s:%u → %s:%u [%s]",
                 s->v[i].no, addr_s(&p.ip.src), p.tcp.sport, addr_s(&p.ip.dst), p.tcp.dport, fl);
        ne++;
    }
    qsort(ev, (size_t)ne, sizeof(*ev), ev_cmp);
    for (int i = 0; i < ne; i++)
        printf("%10.6f  %s\n", ts_sub(&ev[i].ts, t0), ev[i].text);
    printf("\n- 소켓 상태는 약 2~50ms 간격으로 읽으므로 짧게 지나가는 상태(SYN_SENT 등)는 보이지 않을 수 있음\n");
    printf("- 먼저 FIN 을 보낸 쪽의 소켓은 TIME_WAIT 로 남아 일정 시간 후 사라짐 (netstat -tn 으로 확인 가능)\n");
    free(ev);
}
