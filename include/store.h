/*
 * store.h - 수집한 패킷을 메모리에 보관 (명령어별 분석기에서 사용)
 */
#ifndef NETSCOPE_STORE_H
#define NETSCOPE_STORE_H

#include <stddef.h>
#include "packet.h"

typedef struct {
    rawpkt_t *v;
    size_t    n, cap;
} pktstore_t;

void store_init(pktstore_t *s);
int  store_add(pktstore_t *s, const rawpkt_t *r);   /* 데이터를 복사해서 보관 */
void store_free(pktstore_t *s);

#endif
