/*
 * pcapfile.c - pcap 파일 형식 쓰기/읽기
 *
 * 전역 헤더(24바이트) + [레코드 헤더(16바이트) + 프레임 데이터] 반복
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pcapfile.h"
#include "util.h"

#define PCAP_MAGIC_US      0xa1b2c3d4u
#define PCAP_MAGIC_NS      0xa1b23c4du
#define PCAP_MAGIC_US_SWAP 0xd4c3b2a1u
#define PCAP_MAGIC_NS_SWAP 0x4d3cb2a1u

struct pcap_hdr {
    uint32_t magic;
    uint16_t ver_major, ver_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, linktype;
};

struct pcap_rec {
    uint32_t ts_sec, ts_frac, incl_len, orig_len;
};

static uint32_t sw32(uint32_t v)
{
    return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24);
}

int pcapw_open(pcap_writer_t *w, const char *path)
{
    struct pcap_hdr h = { PCAP_MAGIC_NS, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET };

    memset(w, 0, sizeof(*w));
    w->fp = fopen(path, "wb");
    if (!w->fp)
        return -1;
    snprintf(w->path, sizeof(w->path), "%s", path);
    if (fwrite(&h, sizeof(h), 1, w->fp) != 1) {
        fclose(w->fp);
        w->fp = NULL;
        return -1;
    }
    return 0;
}

int pcapw_write(pcap_writer_t *w, const rawpkt_t *r)
{
    struct pcap_rec rec;

    if (!w->fp)
        return -1;
    rec.ts_sec   = (uint32_t)r->ts.tv_sec;
    rec.ts_frac  = (uint32_t)r->ts.tv_nsec;
    rec.incl_len = r->caplen;
    rec.orig_len = r->origlen;
    if (fwrite(&rec, sizeof(rec), 1, w->fp) != 1 || fwrite(r->data, 1, r->caplen, w->fp) != r->caplen)
        return -1;
    w->count++;
    return 0;
}

void pcapw_close(pcap_writer_t *w)
{
    if (!w->fp)
        return;
    fclose(w->fp);
    w->fp = NULL;
    chown_to_sudo_user(w->path);
}

int pcapr_open(pcap_reader_t *rd, const char *path, char *err, size_t errlen)
{
    struct pcap_hdr h;

    memset(rd, 0, sizeof(*rd));
    rd->fp = fopen(path, "rb");
    if (!rd->fp) {
        snprintf(err, errlen, "%s 열기 실패: %s", path, strerror(errno));
        return -1;
    }
    if (fread(&h, sizeof(h), 1, rd->fp) != 1) {
        snprintf(err, errlen, "pcap 헤더를 읽을 수 없음");
        goto fail;
    }
    switch (h.magic) {
    case PCAP_MAGIC_US:      break;
    case PCAP_MAGIC_NS:      rd->nsec = 1; break;
    case PCAP_MAGIC_US_SWAP: rd->swapped = 1; break;
    case PCAP_MAGIC_NS_SWAP: rd->swapped = 1; rd->nsec = 1; break;
    default:
        snprintf(err, errlen, "pcap 형식이 아님 (pcapng 는 Wireshark 에서 pcap 으로 다시 저장 필요)");
        goto fail;
    }
    rd->linktype = (int)(rd->swapped ? sw32(h.linktype) : h.linktype);
    if (rd->linktype != LINKTYPE_ETHERNET && rd->linktype != LINKTYPE_LINUX_SLL) {
        snprintf(err, errlen, "지원하지 않는 링크 타입 %d (Ethernet, Linux cooked 만 지원)", rd->linktype);
        goto fail;
    }
    return 0;
fail:
    fclose(rd->fp);
    rd->fp = NULL;
    return -1;
}

int pcapr_next(pcap_reader_t *rd, rawpkt_t *r, uint8_t *buf, size_t buflen)
{
    struct pcap_rec rec;
    uint32_t keep;

    if (fread(&rec, sizeof(rec), 1, rd->fp) != 1)
        return 0;
    if (rd->swapped) {
        rec.ts_sec = sw32(rec.ts_sec);
        rec.ts_frac = sw32(rec.ts_frac);
        rec.incl_len = sw32(rec.incl_len);
        rec.orig_len = sw32(rec.orig_len);
    }
    keep = rec.incl_len > buflen ? (uint32_t)buflen : rec.incl_len;
    if (fread(buf, 1, keep, rd->fp) != keep)
        return -1;
    if (rec.incl_len > keep)
        fseek(rd->fp, (long)(rec.incl_len - keep), SEEK_CUR);

    memset(r, 0, sizeof(*r));
    r->ts.tv_sec  = rec.ts_sec;
    r->ts.tv_nsec = rd->nsec ? (long)rec.ts_frac : (long)rec.ts_frac * 1000;
    r->caplen     = keep;
    r->origlen    = rec.orig_len;
    r->linktype   = rd->linktype;
    r->ifindex    = -1;
    r->pkttype    = -1;
    r->data       = buf;
    return 1;
}

void pcapr_close(pcap_reader_t *rd)
{
    if (rd->fp)
        fclose(rd->fp);
    rd->fp = NULL;
}
