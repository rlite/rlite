#ifndef __RINA_BUFS_H__
#define __RINA_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>

typedef uint8_t pdu_type_t;

enum {
    PDU_TYPE_MGMT = 0x12,
};

struct rina_pci {
    pdu_type_t type;
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
