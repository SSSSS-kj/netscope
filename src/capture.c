/*
 * capture.c - AF_PACKET raw socket 으로 링크 계층 프레임을 그대로 수신
 *
 * socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) 은 커널이 해당 인터페이스로
 * 주고받는 모든 프레임(송신 포함)의 복사본을 Ethernet 헤더부터 전달한다.
 * libpcap 없이 Wireshark(dumpcap)와 같은 지점에서 패킷을 수집하는 방식이다.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "capture.h"

int capture_open(capture_t *c, const char *ifname, char *err, size_t errlen)
{
    int on = 1, rcvbuf = 4 * 1024 * 1024;

    memset(c, 0, sizeof(*c));
    c->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (c->fd < 0) {
        snprintf(err, errlen, "socket(AF_PACKET) 실패: %s (root 권한 필요: sudo 로 실행)", strerror(errno));
        return -1;
    }

    if (ifname) {
        struct sockaddr_ll sll;

        c->ifindex = (int)if_nametoindex(ifname);
        if (c->ifindex == 0) {
            snprintf(err, errlen, "인터페이스 '%s' 를 찾을 수 없음", ifname);
            close(c->fd);
            return -1;
        }
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = c->ifindex;
        if (bind(c->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            snprintf(err, errlen, "bind(%s) 실패: %s", ifname, strerror(errno));
            close(c->fd);
            return -1;
        }
        snprintf(c->ifname, sizeof(c->ifname), "%s", ifname);
    } else {
        snprintf(c->ifname, sizeof(c->ifname), "any");
    }

    /* 커널이 패킷을 받은 시각(나노초)을 함께 받음 */
    setsockopt(c->fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on));
    setsockopt(c->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL) | O_NONBLOCK);

    /* bind 이전에 다른 인터페이스에서 들어온 프레임은 버림 */
    if (ifname) {
        uint8_t tmp[64];
        while (recv(c->fd, tmp, sizeof(tmp), 0) > 0)
            ;
    }
    return 0;
}

int capture_recv(capture_t *c, rawpkt_t *r, uint8_t *buf, size_t buflen)
{
    struct sockaddr_ll sll;
    struct iovec       iov = { buf, buflen };
    char               ctrl[256];
    struct msghdr      msg;
    struct cmsghdr    *cm;
    ssize_t            n;
    int                got_ts = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &sll;
    msg.msg_namelen    = sizeof(sll);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    n = recvmsg(c->fd, &msg, MSG_TRUNC);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }

    /* Ethernet 형식 헤더를 가진 링크만 처리 (lo 도 14바이트 Ethernet 헤더를 가짐) */
    if (sll.sll_hatype != ARPHRD_ETHER && sll.sll_hatype != ARPHRD_LOOPBACK)
        return 0;

    memset(r, 0, sizeof(*r));
    r->origlen  = (uint32_t)n;
    r->caplen   = (size_t)n > buflen ? (uint32_t)buflen : (uint32_t)n;
    r->linktype = LINKTYPE_ETHERNET;
    r->ifindex  = sll.sll_ifindex;
    r->pkttype  = sll.sll_pkttype;
    r->data     = buf;

    for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPNS) {
            memcpy(&r->ts, CMSG_DATA(cm), sizeof(r->ts));
            got_ts = 1;
        }
    }
    if (!got_ts)
        clock_gettime(CLOCK_REALTIME, &r->ts);
    return 1;
}

int capture_next(capture_t *c, rawpkt_t *r, uint8_t *buf, size_t buflen, int timeout_ms)
{
    struct pollfd pfd = { c->fd, POLLIN, 0 };
    int rc = capture_recv(c, r, buf, buflen);

    if (rc != 0)
        return rc;
    if (poll(&pfd, 1, timeout_ms) <= 0)
        return 0;
    return capture_recv(c, r, buf, buflen);
}

void capture_close(capture_t *c)
{
    if (c->fd > 0)
        close(c->fd);
    c->fd = -1;
}
