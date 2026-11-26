/*
 * packet.h - 캡처 원본(rawpkt_t)과 디코딩 결과(pkt_t) 자료구조
 *
 * 처리 흐름: capture/pcapfile 이 rawpkt_t 를 만들고,
 *            decode_packet() 이 rawpkt_t 를 계층별로 해석해 pkt_t 를 채운다.
 */
#ifndef NETSCOPE_PACKET_H
#define NETSCOPE_PACKET_H

#include <stdint.h>
#include <time.h>

#define SNAPLEN 65535

#define LINKTYPE_ETHERNET  1    /* pcap 링크 타입: Ethernet */
#define LINKTYPE_LINUX_SLL 113  /* pcap 링크 타입: Linux cooked capture v1 (Wireshark 'any') */

/* IPv4/IPv6 공용 주소 */
typedef struct {
    int     family;   /* AF_INET, AF_INET6, 0 = 없음 */
    uint8_t a[16];    /* IPv4 는 앞 4바이트만 사용 */
} addr_t;

/* 캡처된 프레임 원본 */
typedef struct {
    uint32_t        no;        /* 프레임 번호 (1부터) */
    struct timespec ts;        /* 커널 수신 시각 (SO_TIMESTAMPNS) */
    uint32_t        caplen;    /* 저장된 길이 */
    uint32_t        origlen;   /* 실제 길이 */
    int             linktype;  /* LINKTYPE_* */
    int             ifindex;   /* 수신 인터페이스 (pcap 에서 읽으면 -1) */
    int             pkttype;   /* PACKET_HOST/OUTGOING 등 (모르면 -1) */
    uint8_t        *data;
} rawpkt_t;

enum { L3_NONE, L3_ARP, L3_IPV4, L3_IPV6, L3_OTHER };
enum { L4_NONE, L4_ICMP, L4_ICMPV6, L4_UDP, L4_TCP, L4_OTHER };
enum { L7_NONE, L7_DNS, L7_HTTP };

typedef struct {
    uint16_t htype, ptype, op;
    uint8_t  sha[6], tha[6];
    addr_t   spa, tpa;
} arp_t;

typedef struct {
    uint8_t  version;
    uint8_t  hlen;        /* 헤더 길이(바이트). IPv6 는 확장 헤더 포함 */
    uint8_t  tos;         /* IPv4 DSCP/ECN, IPv6 Traffic Class */
    uint8_t  ttl;         /* IPv4 TTL, IPv6 Hop Limit */
    uint8_t  proto;       /* 상위 프로토콜 (IPv6 는 최종 Next Header) */
    uint16_t total_len;   /* IPv4 Total Length, IPv6 Payload Length */
    uint16_t id;
    uint16_t frag;        /* 플래그 3비트 + 오프셋 13비트 */
    uint16_t checksum;
    int      checksum_ok; /* 1 정상, 0 오류 (IPv6 는 해당 없음) */
    uint32_t flow_label;
    addr_t   src, dst;
} ip_t;

typedef struct {
    uint8_t  type, code;
    uint16_t checksum;
    int      checksum_ok;          /* 1 정상, 0 오류, -1 검증 불가 */
    uint16_t id, seq;              /* Echo request/reply */
    /* 오류 메시지(Destination unreachable, Time exceeded)에 인용된 원본 데이터그램 */
    int      has_inner;
    ip_t     inner_ip;
    uint8_t  inner_proto;
    int      inner_has_ports;
    uint16_t inner_sport, inner_dport;   /* 인용된 UDP/TCP 포트 */
    uint8_t  inner_icmp_type;            /* 인용된 ICMP (traceroute -I) */
    uint16_t inner_id, inner_seq;
    addr_t   nd_target;                  /* ICMPv6 Neighbor Solicitation/Advertisement 대상 */
} icmp_t;

typedef struct {
    uint16_t sport, dport, len, checksum;
} udp_t;

typedef struct {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  hlen, flags;
    uint16_t win, checksum, urg;
    /* 옵션 */
    uint16_t mss;          /* 0 = 없음 */
    int      wscale;       /* -1 = 없음 */
    int      sack_perm;
    int      has_ts;
    uint32_t tsval, tsecr;
    /* 스트림 추적 결과 (Wireshark tcp.stream, 상대 순서번호와 같은 기준) */
    int      stream;       /* 0 부터 */
    int      dir;          /* 0 = 스트림을 처음 연 쪽에서 보낸 세그먼트, 1 = 반대쪽 */
    uint32_t rel_seq, rel_ack;
} tcp_t;

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

#define DNS_NAME_MAX 256
#define DNS_RR_MAX   16

typedef struct {
    int      section;      /* 1 Answer, 2 Authority, 3 Additional */
    char     name[DNS_NAME_MAX];
    uint16_t type, cls;
    uint32_t ttl;
    char     data[DNS_NAME_MAX];
} dns_rr_t;

typedef struct {
    uint16_t id, flags;
    uint16_t qdcount, ancount, nscount, arcount;
    char     qname[DNS_NAME_MAX];
    uint16_t qtype, qclass;
    int      n_rr;
    dns_rr_t rr[DNS_RR_MAX];
} dns_t;

typedef struct {
    int  is_request;
    char line[256];      /* 요청 줄 또는 상태 줄 */
    char host[128];
    int  status;         /* 응답 상태 코드 */
    const uint8_t *hdr;  /* 헤더 시작 위치 (상세 출력용) */
    uint32_t hdr_len;
} http_t;

/* 디코딩 결과 */
typedef struct {
    const rawpkt_t *raw;
    int      truncated;

    /* L2 */
    int      has_eth, has_sll;
    uint16_t sll_pkttype;
    uint8_t  eth_src[6], eth_dst[6];
    uint16_t ethertype;

    /* L3 */
    int   l3;
    arp_t arp;
    ip_t  ip;

    /* L4 */
    int    l4;
    icmp_t icmp;
    udp_t  udp;
    tcp_t  tcp;
    const uint8_t *payload;   /* L4 페이로드 */
    uint32_t payload_len;

    /* L7 */
    int    l7;
    dns_t  dns;
    http_t http;
} pkt_t;

#endif
