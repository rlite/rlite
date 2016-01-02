#ifndef __RINA_BUFS_H__
#define __RINA_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>
#include <asm/atomic.h>


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

struct rina_rawbuf {
    size_t size;
    atomic_t refcnt;
    uint8_t buf[0];
};

struct rina_buf {
    struct rina_rawbuf  *raw;
    struct rina_pci     *pci;
    size_t              len;

    struct list_head    node;
};

struct rina_buf *rina_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

struct rina_buf * rina_buf_alloc_ctrl(size_t num_pci, gfp_t gfp);

struct rina_buf * rina_buf_clone(struct rina_buf *rb, gfp_t gfp);

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
#define RINA_BUF_PCI_CTRL(rb) ((struct rina_pci_ctrl *)rb->pci)

#endif  /* __RINA_BUFS_H__ */
