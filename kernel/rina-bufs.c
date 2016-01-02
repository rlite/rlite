#include <linux/types.h>
#include <linux/slab.h>
#include "rina-bufs.h"
#include <rina/rinalite-common.h>


struct rina_buf *
rina_buf_alloc(size_t size, size_t num_pci, gfp_t gfp)
{
    struct rina_buf *rb;
    size_t real_size = size + num_pci * sizeof(struct rina_pci);
    uint8_t *kbuf;

    rb = kmalloc(sizeof(*rb), gfp);
    if (unlikely(!rb)) {
        PE("%s: Out of memory\n", __func__);
        return NULL;
    }

    kbuf = kmalloc(sizeof(*rb->raw) + real_size, gfp);
    if (unlikely(!kbuf)) {
        kfree(rb);
        PE("%s: Out of memory\n", __func__);
        return NULL;
    }

    rb->raw = (struct rina_rawbuf *)kbuf;
    rb->raw->size = real_size;
    atomic_set(&rb->raw->refcnt, 1);
    rb->pci = (struct rina_pci *)(rb->raw->buf + num_pci * sizeof(struct rina_pci));
    rb->len = size;

    return rb;
}
EXPORT_SYMBOL_GPL(rina_buf_alloc);

struct rina_buf *
rina_buf_alloc_ctrl(size_t num_pci, gfp_t gfp)
{
    return rina_buf_alloc(sizeof(struct rina_pci_ctrl), num_pci, gfp);
}
EXPORT_SYMBOL_GPL(rina_buf_alloc_ctrl);

struct rina_buf *
rina_buf_clone(struct rina_buf *rb, gfp_t gfp)
{
    struct rina_buf *crb;

    crb = kmalloc(sizeof(*crb), gfp);
    if (unlikely(!crb)) {
        PE("%s: Out of memory\n", __func__);
        return NULL;
    }

    /* Increment the raw buffer reference counter. */
    atomic_inc(&rb->raw->refcnt);

    /* Normal copy - includes pointer copy. */
    memcpy(crb, rb, sizeof(*rb));

    INIT_LIST_HEAD(&crb->node);

    return crb;
}
EXPORT_SYMBOL_GPL(rina_buf_clone);

void
rina_buf_free(struct rina_buf *rb)
{
    if (atomic_dec_and_test(&rb->raw->refcnt)) {
        kfree(rb->raw);
    }
    kfree(rb);
}
EXPORT_SYMBOL_GPL(rina_buf_free);

void
rina_pci_dump(struct rina_pci *pci)
{
    PD("PCI: dst=%lu,src=%lu,qos=%u,dcep=%u,scep=%u,type=%x,flags=%x,"
        "seq=%lu\n", (long unsigned)pci->dst_addr,
        (long unsigned)pci->src_addr, pci->conn_id.qos_id,
        pci->conn_id.dst_cep, pci->conn_id.src_cep,
        pci->pdu_type, pci->pdu_flags, (long unsigned)pci->seqnum);
}
EXPORT_SYMBOL_GPL(rina_pci_dump);
