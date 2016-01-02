#ifndef __RLITE_BUFS_H__
#define __RLITE_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>
#include <asm/atomic.h>

#include "rlite/common.h"


#define RLITE_DEFAULT_LAYERS    3

/* PDU type definitions. */
#define PDU_T_MGMT          0x40    /* Management PDU */
#define PDU_T_DT            0x80    /* Data Transfer PDU */
#define PDU_T_CTRL_MASK     0xC0
#define PDU_T_ACK_BIT       0x04
#define PDU_T_FC_BIT        0x08
#define PDU_T_ACK_MASK      0x03
#define PDU_T_ACK           0   /* Conventional ACK */
#define PDU_T_NACK          1   /* Force PDU retransmission */
#define PDU_T_SACK          2   /* Selective ACK */
#define PDU_T_SNACK         3   /* Selective NACK */


/* PCI header to be used for transfer PDUs. */
struct rlite_pci {
    /* We miss the version field. */
    uint32_t dst_addr;
    uint32_t src_addr;
    struct {
        uint32_t qos_id;
        uint32_t dst_cep;
        uint32_t src_cep;
    } conn_id;
    uint8_t pdu_type;
    uint8_t pdu_flags;
    uint16_t pdu_len;
    uint64_t seqnum;
} __attribute__((packed));

/* PCI header to be used for control PDUs. */
struct rlite_pci_ctrl {
    struct rlite_pci base;
    uint64_t last_ctrl_seq_num_rcvd;
    uint64_t ack_nack_seq_num;
    uint64_t new_rwe;
    uint64_t new_lwe;
    uint64_t my_lwe;
    uint64_t my_rwe;
} __attribute__((packed));

struct rina_rawbuf {
    size_t size;
    atomic_t refcnt;
    uint8_t buf[0];
};

struct rlite_buf {
    struct rina_rawbuf  *raw;
    struct rlite_pci    *pci;
    size_t              len;

    unsigned long       rtx_jiffies;

    struct list_head    node;
};

struct rlite_buf *rlite_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

struct rlite_buf * rlite_buf_alloc_ctrl(size_t num_pci, gfp_t gfp);

struct rlite_buf * rlite_buf_clone(struct rlite_buf *rb, gfp_t gfp);

void rlite_buf_free(struct rlite_buf *rb);

static inline int
rlite_buf_pci_pop(struct rlite_buf *rb)
{
    if (unlikely(rb->len < sizeof(struct rlite_pci))) {
        RPD(5, "No enough data to pop another PCI\n");
        return -1;
    }

    rb->pci++;
    rb->len -= sizeof(struct rlite_pci);

    return 0;
}

static inline int
rlite_buf_pci_push(struct rlite_buf *rb)
{
    if (unlikely((uint8_t *)(rb->pci-1) < &rb->raw->buf[0])) {
        RPD(5, "No space to push another PCI\n");
        return -1;
    }

    rb->pci--;
    rb->len += sizeof(struct rlite_pci);

    return 0;
}

static inline int rlite_buf_custom_push(struct rlite_buf *rb, size_t len)
{
    if (unlikely((uint8_t *)(rb->pci) - len < &rb->raw->buf[0])) {
        RPD(5, "No space to push custom header\n");
        return -1;
    }

    rb->pci = (struct rlite_pci *)(((uint8_t *)rb->pci) - len);
    rb->len += len;

    return 0;
}

void rlite_pci_dump(struct rlite_pci *pci);

#define RLITE_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RLITE_BUF_PCI(rb) rb->pci
#define RLITE_BUF_PCI_CTRL(rb) ((struct rlite_pci_ctrl *)rb->pci)

#endif  /* __RLITE_BUFS_H__ */
