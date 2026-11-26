/*
 * util.c - 공용 함수
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

uint32_t cksum_add(uint32_t sum, const uint8_t *d, uint32_t n)
{
    while (n > 1) {
        sum += (uint32_t)((d[0] << 8) | d[1]);
        d += 2;
        n -= 2;
    }
    if (n)
        sum += (uint32_t)(d[0] << 8);
    return sum;
}

uint16_t cksum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t inet_cksum(const uint8_t *d, uint32_t n)
{
    return cksum_fold(cksum_add(0, d, n));
}

const char *addr_s(const addr_t *a)
{
    static char bufs[8][INET6_ADDRSTRLEN];
    static int  idx;
    char *b = bufs[idx++ & 7];

    if (a->family == AF_INET || a->family == AF_INET6)
        inet_ntop(a->family, a->a, b, INET6_ADDRSTRLEN);
    else
        strcpy(b, "-");
    return b;
}

const char *mac_s(const uint8_t m[6])
{
    static char bufs[8][18];
    static int  idx;
    char *b = bufs[idx++ & 7];

    snprintf(b, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}

int addr_eq(const addr_t *a, const addr_t *b)
{
    if (a->family != b->family || a->family == 0)
        return 0;
    return memcmp(a->a, b->a, a->family == AF_INET ? 4 : 16) == 0;
}

int addr_parse(const char *s, addr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, s, out->a) == 1) {
        out->family = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, s, out->a) == 1) {
        out->family = AF_INET6;
        return 0;
    }
    return -1;
}

double ts_sub(const struct timespec *a, const struct timespec *b)
{
    return (double)(a->tv_sec - b->tv_sec) + (double)(a->tv_nsec - b->tv_nsec) / 1e9;
}

void fmt_localtime(const struct timespec *ts, char *buf, size_t n)
{
    struct tm tm;
    char tmp[64];

    localtime_r(&ts->tv_sec, &tm);
    strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(buf, n, "%s.%09ld", tmp, (long)ts->tv_nsec);
}

int str_width(const char *s)
{
    int w = 0;

    const unsigned char *u = (const unsigned char *)s;

    while (*u) {
        uint32_t cp;
        int      len;

        if (*u < 0x80)      { cp = *u;        len = 1; }
        else if (*u < 0xe0) { cp = *u & 0x1f; len = 2; }
        else if (*u < 0xf0) { cp = *u & 0x0f; len = 3; }
        else                { cp = *u & 0x07; len = 4; }
        for (int i = 1; i < len && u[i]; i++)
            cp = (cp << 6) | (u[i] & 0x3f);
        /* 한글 음절·자모, CJK 는 터미널에서 폭 2 */
        w += ((cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x3130 && cp <= 0x318f) ||
              (cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0xac00 && cp <= 0xd7a3)) ? 2 : 1;
        for (int i = 0; i < len && *u; i++)
            u++;
    }
    return w;
}

void put_col(const char *s, int width)
{
    int w = str_width(s);

    fputs(s, stdout);
    if (w >= width)              /* 넘치면 최소 한 칸 띄움 */
        putchar(' ');
    for (; w < width; w++)
        putchar(' ');
}

int use_color(void)
{
    static int c = -1;

    if (c < 0)
        c = isatty(STDOUT_FILENO) && getenv("NO_COLOR") == NULL;
    return c;
}

/* sudo 로 실행했을 때 만든 파일의 소유자를 원래 사용자로 돌려놓음 */
void chown_to_sudo_user(const char *path)
{
    const char *su = getenv("SUDO_UID"), *sg = getenv("SUDO_GID");

    if (geteuid() != 0 || !su || !sg)
        return;
    if (chown(path, (uid_t)atoi(su), (gid_t)atoi(sg)) != 0)
        perror("chown");
}

/* run 모드: 분석 대상 명령어는 root 가 아닌 원래 사용자 권한으로 실행 */
void drop_privileges(void)
{
    const char *su = getenv("SUDO_UID"), *sg = getenv("SUDO_GID"), *user = getenv("SUDO_USER");
    gid_t gid;
    uid_t uid;

    if (geteuid() != 0 || !su || !sg)
        return;
    uid = (uid_t)atoi(su);
    gid = (gid_t)atoi(sg);
    if (user)
        initgroups(user, gid);
    else
        setgroups(0, NULL);
    if (setgid(gid) != 0 || setuid(uid) != 0) {
        perror("drop_privileges");
        _exit(126);
    }
}
