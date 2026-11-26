/*
 * filter.c - 필터 식 파서(재귀 하강)와 판정
 *
 * 문법은 filter.h 참고. 식을 트리(node)로 만든 뒤 패킷마다 트리를 평가한다.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"
#include "util.h"

enum { N_AND, N_OR, N_NOT, N_PROTO, N_HOST, N_SRC, N_DST, N_PORT };
enum { P_IP, P_IP6, P_ARP, P_ICMP, P_ICMPV6, P_UDP, P_TCP, P_DNS, P_HTTP, P_ALL };

struct node {
    int          type;
    int          proto;
    addr_t       addr;
    uint16_t     port;
    struct node *l, *r;
};

struct filter {
    struct node *root;
};

typedef struct {
    const char *s;
    char        tok[128];
    char       *err;
    size_t      errlen;
    int         failed;
} lexer_t;

static const struct { const char *name; int proto; } protos[] = {
    { "ip", P_IP }, { "ip6", P_IP6 }, { "arp", P_ARP }, { "icmp", P_ICMP }, { "icmpv6", P_ICMPV6 },
    { "udp", P_UDP }, { "tcp", P_TCP }, { "dns", P_DNS }, { "http", P_HTTP }, { "all", P_ALL },
};

static void lex_next(lexer_t *L)
{
    size_t k = 0;

    while (*L->s == ' ' || *L->s == '\t')
        L->s++;
    if (!*L->s) {
        L->tok[0] = '\0';
        return;
    }
    if (*L->s == '(' || *L->s == ')' || (*L->s == '!' && L->s[1] != '=')) {
        L->tok[0] = *L->s++;
        L->tok[1] = '\0';
        return;
    }
    if ((L->s[0] == '&' && L->s[1] == '&') || (L->s[0] == '|' && L->s[1] == '|')) {
        L->tok[0] = L->s[0];
        L->tok[1] = L->s[1];
        L->tok[2] = '\0';
        L->s += 2;
        return;
    }
    while (*L->s && *L->s != ' ' && *L->s != '\t' && *L->s != '(' && *L->s != ')' && k < sizeof(L->tok) - 1)
        L->tok[k++] = *L->s++;
    L->tok[k] = '\0';
}

static struct node *mknode(int type, struct node *l, struct node *r)
{
    struct node *n = calloc(1, sizeof(*n));
    if (n) {
        n->type = type;
        n->l = l;
        n->r = r;
    }
    return n;
}

static void fail(lexer_t *L, const char *msg)
{
    if (!L->failed)
        snprintf(L->err, L->errlen, "%s (위치: '%s')", msg, L->tok[0] ? L->tok : "끝");
    L->failed = 1;
}

static void free_node(struct node *n)
{
    if (!n)
        return;
    free_node(n->l);
    free_node(n->r);
    free(n);
}

static struct node *parse_expr(lexer_t *L);

static struct node *parse_prim(lexer_t *L)
{
    struct node *n;

    for (size_t i = 0; i < sizeof(protos) / sizeof(protos[0]); i++) {
        if (strcmp(L->tok, protos[i].name) == 0) {
            n = mknode(N_PROTO, NULL, NULL);
            n->proto = protos[i].proto;
            lex_next(L);
            return n;
        }
    }
    if (!strcmp(L->tok, "host") || !strcmp(L->tok, "src") || !strcmp(L->tok, "dst")) {
        int type = L->tok[0] == 'h' ? N_HOST : L->tok[0] == 's' ? N_SRC : N_DST;
        lex_next(L);
        if (type != N_HOST && !strcmp(L->tok, "host"))   /* "src host X" 형태 허용 */
            lex_next(L);
        n = mknode(type, NULL, NULL);
        if (addr_parse(L->tok, &n->addr) < 0) {
            fail(L, "IP 주소 형식 오류");
            free(n);
            return NULL;
        }
        lex_next(L);
        return n;
    }
    if (!strcmp(L->tok, "port")) {
        char *end;
        long  v;
        lex_next(L);
        v = strtol(L->tok, &end, 10);
        if (!L->tok[0] || *end || v < 0 || v > 65535) {
            fail(L, "포트 번호 오류");
            return NULL;
        }
        n = mknode(N_PORT, NULL, NULL);
        n->port = (uint16_t)v;
        lex_next(L);
        return n;
    }
    fail(L, "알 수 없는 필터 항목");
    return NULL;
}

static struct node *parse_factor(lexer_t *L)
{
    if (!strcmp(L->tok, "not") || !strcmp(L->tok, "!")) {
        lex_next(L);
        struct node *c = parse_factor(L);
        return c ? mknode(N_NOT, c, NULL) : NULL;
    }
    if (!strcmp(L->tok, "(")) {
        lex_next(L);
        struct node *e = parse_expr(L);
        if (!e)
            return NULL;
        if (strcmp(L->tok, ")")) {
            fail(L, "')' 가 필요함");
            free_node(e);
            return NULL;
        }
        lex_next(L);
        return e;
    }
    return parse_prim(L);
}

static struct node *parse_term(lexer_t *L)
{
    struct node *l = parse_factor(L);

    while (l && (!strcmp(L->tok, "and") || !strcmp(L->tok, "&&"))) {
        lex_next(L);
        struct node *r = parse_factor(L);
        if (!r) {
            free_node(l);
            return NULL;
        }
        l = mknode(N_AND, l, r);
    }
    return l;
}

static struct node *parse_expr(lexer_t *L)
{
    struct node *l = parse_term(L);

    while (l && (!strcmp(L->tok, "or") || !strcmp(L->tok, "||"))) {
        lex_next(L);
        struct node *r = parse_term(L);
        if (!r) {
            free_node(l);
            return NULL;
        }
        l = mknode(N_OR, l, r);
    }
    return l;
}

filter_t *filter_compile(const char *expr, char *err, size_t errlen)
{
    lexer_t   L = { expr, "", err, errlen, 0 };
    filter_t *f;

    lex_next(&L);
    if (!L.tok[0]) {
        snprintf(err, errlen, "빈 필터");
        return NULL;
    }
    struct node *root = parse_expr(&L);
    if (root && L.tok[0]) {
        fail(&L, "필터 끝에 해석할 수 없는 내용");
        free_node(root);
        root = NULL;
    }
    if (!root)
        return NULL;
    f = calloc(1, sizeof(*f));
    f->root = root;
    return f;
}

static int is_icmp_err_with_inner(const pkt_t *p)
{
    return (p->l4 == L4_ICMP || p->l4 == L4_ICMPV6) && p->icmp.has_inner;
}

static int match_addr(const pkt_t *p, const addr_t *a, int want_src, int want_dst)
{
    if (p->l3 == L3_IPV4 || p->l3 == L3_IPV6) {
        if ((want_src && addr_eq(&p->ip.src, a)) || (want_dst && addr_eq(&p->ip.dst, a)))
            return 1;
        /* ICMP 오류 메시지 안의 원본 IP 주소도 포함 (Wireshark ip.addr 와 동일) */
        if (is_icmp_err_with_inner(p) &&
            ((want_src && addr_eq(&p->icmp.inner_ip.src, a)) || (want_dst && addr_eq(&p->icmp.inner_ip.dst, a))))
            return 1;
    } else if (p->l3 == L3_ARP) {
        return (want_src && addr_eq(&p->arp.spa, a)) || (want_dst && addr_eq(&p->arp.tpa, a));
    }
    return 0;
}

static int match_port(const pkt_t *p, uint16_t port)
{
    if (p->l4 == L4_UDP)
        return p->udp.sport == port || p->udp.dport == port;
    if (p->l4 == L4_TCP)
        return p->tcp.sport == port || p->tcp.dport == port;
    if (is_icmp_err_with_inner(p) && p->icmp.inner_has_ports)   /* Wireshark udp.port 와 동일 */
        return p->icmp.inner_sport == port || p->icmp.inner_dport == port;
    return 0;
}

static int match_proto(const pkt_t *p, int proto)
{
    switch (proto) {
    case P_IP:     return p->l3 == L3_IPV4;
    case P_IP6:    return p->l3 == L3_IPV6;
    case P_ARP:    return p->l3 == L3_ARP;
    case P_ICMP:   return p->l4 == L4_ICMP;
    case P_ICMPV6: return p->l4 == L4_ICMPV6;
    case P_UDP:    return p->l4 == L4_UDP || (is_icmp_err_with_inner(p) && p->icmp.inner_proto == 17);
    case P_TCP:    return p->l4 == L4_TCP || (is_icmp_err_with_inner(p) && p->icmp.inner_proto == 6);
    case P_DNS:    return p->l7 == L7_DNS;
    case P_HTTP:   return p->l7 == L7_HTTP;
    case P_ALL:    return 1;
    }
    return 0;
}

static int eval(const struct node *n, const pkt_t *p)
{
    switch (n->type) {
    case N_AND:   return eval(n->l, p) && eval(n->r, p);
    case N_OR:    return eval(n->l, p) || eval(n->r, p);
    case N_NOT:   return !eval(n->l, p);
    case N_PROTO: return match_proto(p, n->proto);
    case N_HOST:  return match_addr(p, &n->addr, 1, 1);
    case N_SRC:   return match_addr(p, &n->addr, 1, 0);
    case N_DST:   return match_addr(p, &n->addr, 0, 1);
    case N_PORT:  return match_port(p, n->port);
    }
    return 0;
}

int filter_match(const filter_t *f, const pkt_t *p)
{
    return f ? eval(f->root, p) : 1;
}

void filter_free(filter_t *f)
{
    if (!f)
        return;
    free_node(f->root);
    free(f);
}
