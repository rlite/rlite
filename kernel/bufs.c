#include <linux/types.h>
#include <linux/slab.h>
#include "rlite-bufs.h"
#include <rlite/common.h>


struct rlite_buf *
rlite_buf_alloc(size_t size, size_t num_pci, gfp_t gfp)
{
    struct rlite_buf *rb;
    size_t real_size = size + num_pci * sizeof(struct rlite_pci);
    uint8_t *kbuf;

    rb = kmalloc(sizeof(*rb), gfp);
    if (unlikely(!rb)) {
        PE("Out of memory\n");
        return NULL;
    }

    kbuf = kmalloc(sizeof(*rb->raw) + real_size, gfp);
    if (unlikely(!kbuf)) {
        kfree(rb);
        PE("Out of memory\n");
        return NULL;
    }

    rb->raw = (struct rina_rawbuf *)kbuf;
    rb->raw->size = real_size;
    atomic_set(&rb->raw->refcnt, 1);
    rb->pci = (struct rlite_pci *)(rb->raw->buf + num_pci * sizeof(struct rlite_pci));
    rb->len = size;

    return rb;
}
EXPORT_SYMBOL_GPL(rlite_buf_alloc);

struct rlite_buf *
rlite_buf_alloc_ctrl(size_t num_pci, gfp_t gfp)
{
    return rlite_buf_alloc(sizeof(struct rlite_pci_ctrl), num_pci, gfp);
}
EXPORT_SYMBOL_GPL(rlite_buf_alloc_ctrl);

struct rlite_buf *
rlite_buf_clone(struct rlite_buf *rb, gfp_t gfp)
{
    struct rlite_buf *crb;

    crb = kmalloc(sizeof(*crb), gfp);
    if (unlikely(!crb)) {
        PE("Out of memory\n");
        return NULL;
    }

    /* Increment the raw buffer reference counter. */
    atomic_inc(&rb->raw->refcnt);

    /* Normal copy - includes pointer copy. */
    memcpy(crb, rb, sizeof(*rb));

    INIT_LIST_HEAD(&crb->node);

    return crb;
}
EXPORT_SYMBOL_GPL(rlite_buf_clone);

void
rlite_buf_free(struct rlite_buf *rb)
{
    if (atomic_dec_and_test(&rb->raw->refcnt)) {
        kfree(rb->raw);
    }
    kfree(rb);
}
EXPORT_SYMBOL_GPL(rlite_buf_free);

void
rlite_pci_dump(struct rlite_pci *pci)
{
    PD("PCI: dst=%lu,src=%lu,qos=%u,dcep=%u,scep=%u,type=%x,flags=%x,"
        "seq=%lu\n", (long unsigned)pci->dst_addr,
        (long unsigned)pci->src_addr, pci->conn_id.qos_id,
        pci->conn_id.dst_cep, pci->conn_id.src_cep,
        pci->pdu_type, pci->pdu_flags, (long unsigned)pci->seqnum);
}
EXPORT_SYMBOL_GPL(rlite_pci_dump);
