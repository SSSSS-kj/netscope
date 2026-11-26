/*
 * analyze.c - 명령어 이름으로 분석기 선택, 일반 통계 분석기
 */
#include <stdio.h>
#include <string.h>

#include "analyze.h"
#include "decode.h"
#include "output.h"

static const analyzer_t table[] = {
    { "ping",       "icmp or icmpv6",        analyze_ping },
    { "ping6",      "icmpv6",                analyze_ping },
    { "traceroute", "(udp and not dns) or icmp or icmpv6", analyze_traceroute },
    { "nslookup",   "dns",                   analyze_nslookup },
    { "dig",        "dns",                   analyze_nslookup },
    { "host",       "dns",                   analyze_nslookup },
    { "curl",       "tcp or dns",            analyze_curl },
    { "netstat",    "tcp",                   analyze_netstat },
    { "ss",         "tcp",                   analyze_netstat },
};

static const analyzer_t generic = { "generic", NULL, analyze_generic };

const analyzer_t *analyzer_find(const char *cmd)
{
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        if (!strcmp(cmd, table[i].cmd))
            return &table[i];
    return &generic;
}

struct timespec analysis_t0(const pktstore_t *s, const runctx_t *ctx)
{
    struct timespec z = { 0, 0 };

    if (ctx->t_start.tv_sec)
        return ctx->t_start;
    return s->n ? s->v[0].ts : z;
}

const char *next_line(const char *s, char *line, size_t n)
{
    const char *e = strchr(s, '\n');
    size_t      len = e ? (size_t)(e - s) : strlen(s);

    if (len >= n)
        len = n - 1;
    memcpy(line, s, len);
    line[len] = '\0';
    return e ? e + 1 : s + strlen(s);
}

/* 분석기가 없는 명령어: 프로토콜별 패킷 수 */
void analyze_generic(const pktstore_t *s, const runctx_t *ctx)
{
    static pkt_t p;
    struct { char name[16]; unsigned cnt, bytes; } stat[32];
    int n = 0;

    (void)ctx;
    for (size_t i = 0; i < s->n; i++) {
        const char *name;
        int k;
        decode_packet(&s->v[i], &p);
        name = proto_name(&p);
        for (k = 0; k < n && strcmp(stat[k].name, name); k++)
            ;
        if (k == n) {
            if (n == 32)
                continue;
            snprintf(stat[n].name, sizeof(stat[n].name), "%s", name);
            stat[n].cnt = stat[n].bytes = 0;
            n++;
        }
        stat[k].cnt++;
        stat[k].bytes += s->v[i].origlen;
    }
    printf("%-10s %8s %10s\n", "Protocol", "Packets", "Bytes");
    for (int k = 0; k < n; k++)
        printf("%-10s %8u %10u\n", stat[k].name, stat[k].cnt, stat[k].bytes);
}
