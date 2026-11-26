/*
 * netscope.h - 실행 옵션과 모드별 진입 함수
 */
#ifndef NETSCOPE_H
#define NETSCOPE_H

#include <signal.h>

#define NETSCOPE_VERSION "0.1.0"

typedef struct {
    const char *ifname;       /* -i */
    const char *filter_expr;  /* -f */
    const char *wfile;        /* -w */
    const char *analyzer;     /* -a (read 모드) */
    long        count;        /* -c, 0 = 무제한 */
    int         verbose;      /* -v */
    int         hex;          /* -x */
    int         grace_ms;     /* -g, 명령어 종료 후 추가 수집 시간 */
    int         sockwatch;    /* -S */
} options_t;

extern volatile sig_atomic_t g_sigint;

int cmd_capture(const options_t *o);
int cmd_run(const options_t *o, char **argv);
int cmd_read(const options_t *o, const char *path);

#endif
