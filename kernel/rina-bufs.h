#ifndef __RINA_BUFS_H__
#define __RINA_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>

enum {
    PDU_TYPE_MGMT = 0x12,
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
    uint64_t new_rt_wind_edge;
    uint64_t new_lf_wind_edge;
    uint64_t my_lf_wind_edge;
    uint64_t my_rt_wind_edge;
} __attribute__((packed));

struct rina_buf {
    uint8_t    *ptr;
    struct rina_pci *pci;
    size_t     size;
    size_t     len;

    struct list_head node;
};

struct rina_buf *rina_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

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

#define RINA_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RINA_BUF_PCI(rb) rb->pci

#endif  /* __RINA_BUFS_H__ */
