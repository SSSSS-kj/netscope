/*
 * store.c - 패킷 보관소
 */
#include <stdlib.h>
#include <string.h>

#include "store.h"

void store_init(pktstore_t *s)
{
    memset(s, 0, sizeof(*s));
}

int store_add(pktstore_t *s, const rawpkt_t *r)
{
    rawpkt_t *e;

    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 256;
        rawpkt_t *nv = realloc(s->v, ncap * sizeof(*nv));
        if (!nv)
            return -1;
        s->v = nv;
        s->cap = ncap;
    }
    e = &s->v[s->n];
    *e = *r;
    e->data = malloc(r->caplen ? r->caplen : 1);
    if (!e->data)
        return -1;
    memcpy(e->data, r->data, r->caplen);
    s->n++;
    return 0;
}

void store_free(pktstore_t *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i].data);
    free(s->v);
    memset(s, 0, sizeof(*s));
}
