#ifndef __RINA_BUFS_H__
#define __RINA_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>


enum {
    PDU_TYPE_DT             = 0x80, /* Data Transfer PDU */
    PDU_TYPE_CC             = 0xC3, /* Common Control PDU */
    PDU_TYPE_ACK            = 0xC4, /* ACK only */
    PDU_TYPE_NACK           = 0xC5, /* Forced Retransmission PDU (NACK) */
    PDU_TYPE_SACK           = 0xC6, /* Selective ACK */
    PDU_TYPE_SNACK          = 0xC7, /* Selective NACK */
    PDU_TYPE_FC             = 0xC8, /* Flow Control only */
    PDU_TYPE_ACK_AND_FC     = 0xCC, /* ACK and Flow Control */
    PDU_TYPE_NACK_AND_FC    = 0xCD, /* NACK and Flow Control */
    PDU_TYPE_SACK_AND_FC    = 0xCE, /* Selective ACK and Flow Control */
    PDU_TYPE_SNACK_AND_FC   = 0xCF, /* Selective NACK and Flow Control */
    PDU_TYPE_MGMT           = 0x40, /* Management PDU */
};

/* PCI header to be used for transfer PDUs. */
struct rina_pci {
    uint32_t dst_addr;
    uint32_t src_addr;
    struct {
        uint32_t qos_id;
        uint32_t dst_cep;
        uint32_t src_cep;
    } conn_id;
    uint8_t pdu_type;
    uint8_t pdu_flags;
    uint64_t seqnum;
} __attribute__((packed));

/* PCI header to be used for control PDUs. */
struct rina_pci_ctrl {
    struct rina_pci base;
    uint64_t last_ctrl_seq_num_rcvd;
    uint64_t ack_nack_seq_num;
    uint64_t new_rwe;
    uint64_t new_lwe;
    uint64_t my_lwe;
    uint64_t my_rwe;
} __attribute__((packed));

struct rina_buf {
    uint8_t    *ptr;
    struct rina_pci *pci;
    size_t     size;
    size_t     len;

    struct list_head node;
};

struct rina_buf *rina_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

struct rina_buf * rina_buf_alloc_ctrl(size_t num_pci, gfp_t gfp);

void rina_buf_free(struct rina_buf *rb);

static inline void rina_buf_pci_pop(struct rina_buf *rb)
{
    rb->pci++;
    rb->len -= sizeof(struct rina_pci);
}

static inline void rina_buf_pci_push(struct rina_buf *rb)
{
    rb->pci--;
    rb->len += sizeof(struct rina_pci);
}

static inline void rina_buf_custom_push(struct rina_buf *rb, size_t len)
{
    rb->pci = (struct rina_pci *)(((void *)rb->pci) - len);
    rb->len += len;
}

void rina_pci_dump(struct rina_pci *pci);

#define RINA_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RINA_BUF_PCI(rb) rb->pci

#endif  /* __RINA_BUFS_H__ */
