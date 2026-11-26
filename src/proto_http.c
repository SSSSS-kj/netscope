/*
 * proto_http.c - HTTP/1.x 요청·응답
 *
 * 현재 구현: 세그먼트가 요청 줄/상태 줄로 시작하면 HTTP 로 판정하고 헤더를 출력
 * TODO:
 *   - 여러 세그먼트에 걸친 응답 재조립 (Content-Length 기준)
 *   - 요청과 응답 짝짓기
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "decode.h"
#include "output.h"
#include "util.h"

static int starts_with(const uint8_t *d, uint32_t n, const char *s)
{
    size_t l = strlen(s);
    return n >= l && memcmp(d, s, l) == 0;
}

void decode_http(pkt_t *p, const uint8_t *d, uint32_t n)
{
    static const char *methods[] = { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", NULL };
    http_t *h = &p->http;
    uint32_t i, k;
    int ok = starts_with(d, n, "HTTP/1.");

    for (int m = 0; !ok && methods[m]; m++)
        ok = starts_with(d, n, methods[m]);
    if (!ok)
        return;

    p->l7 = L7_HTTP;
    h->is_request = !starts_with(d, n, "HTTP/");
    for (i = 0; i < n && i < sizeof(h->line) - 1 && d[i] != '\r' && d[i] != '\n'; i++)
        h->line[i] = (d[i] >= 0x20 && d[i] < 0x7f) ? (char)d[i] : '.';   /* 출력 가능한 ASCII 만 */
    h->line[i] = '\0';
    if (!h->is_request && strlen(h->line) >= 12)
        h->status = atoi(h->line + 9);

    /* 헤더 영역: 빈 줄(\r\n\r\n) 전까지 */
    h->hdr = d;
    h->hdr_len = n;
    for (k = 0; k + 3 < n; k++) {
        if (d[k] == '\r' && d[k + 1] == '\n' && d[k + 2] == '\r' && d[k + 3] == '\n') {
            h->hdr_len = k + 2;
            break;
        }
    }
    for (k = 0; k + 6 < h->hdr_len; k++) {
        if (d[k] == '\n' && strncasecmp((const char *)d + k + 1, "Host:", 5) == 0) {
            uint32_t s = k + 6, j = 0;
            while (s < h->hdr_len && d[s] == ' ')
                s++;
            while (s < h->hdr_len && d[s] != '\r' && d[s] != '\n' && j < sizeof(h->host) - 1) {
                h->host[j++] = (d[s] >= 0x20 && d[s] < 0x7f) ? (char)d[s] : '.';
                s++;
            }
            h->host[j] = '\0';
            break;
        }
    }
}

void info_http(const pkt_t *p, char *b, size_t n)
{
    snprintf(b, n, "%s", p->http.line);
}

void detail_http(const pkt_t *p)
{
    const http_t *h = &p->http;
    uint32_t s = 0;
    char line[256];

    tree_hdr(0, "Hypertext Transfer Protocol");
    while (s < h->hdr_len) {
        uint32_t e = s, j = 0;
        while (e < h->hdr_len && h->hdr[e] != '\r' && h->hdr[e] != '\n')
            e++;
        if (e == s)
            break;
        for (uint32_t i = s; i < e && j < sizeof(line) - 1; i++)
            line[j++] = isprint(h->hdr[i]) ? (char)h->hdr[i] : '.';
        line[j] = '\0';
        tree_item(1, "%s\\r\\n", line);
        s = e;
        while (s < h->hdr_len && (h->hdr[s] == '\r' || h->hdr[s] == '\n'))
            s++;
    }
    if (p->payload_len > h->hdr_len + 2)
        tree_item(1, "File Data: %u bytes", p->payload_len - h->hdr_len - 2);
}
