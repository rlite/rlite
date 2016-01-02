#include <linux/types.h>
#include <linux/slab.h>
#include "rina-bufs.h"


struct rina_buf *
rina_buf_alloc(size_t size, size_t num_pci, gfp_t gfp)
{
    struct rina_buf *rb = NULL;
    size_t real_size = size + num_pci * sizeof(struct rina_pci);
    uint8_t *kbuf;

    rb = kmalloc(sizeof(*rb), gfp);
    if (unlikely(!rb)) {
        printk("%s: Out of memory\n", __func__);
        return NULL;
    }

    kbuf = kmalloc(sizeof(*rb->raw) + real_size, gfp);
    if (unlikely(!kbuf)) {
        kfree(rb);
        printk("%s: Out of memory\n", __func__);
        return NULL;
    }

    rb->raw = (struct rina_rawbuf *)kbuf;
    rb->raw->size = real_size;
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

void
rina_buf_free(struct rina_buf *rb)
{
    kfree(rb->raw);
    kfree(rb);
}
EXPORT_SYMBOL_GPL(rina_buf_free);

void
rina_pci_dump(struct rina_pci *pci)
{
    printk("PCI: dst=%lu,src=%lu,qos=%u,dcep=%u,scep=%u,type=%x,flags=%x,"
            "seq=%lu\n", (long unsigned)pci->dst_addr,
            (long unsigned)pci->src_addr, pci->conn_id.qos_id,
            pci->conn_id.dst_cep, pci->conn_id.src_cep,
            pci->pdu_type, pci->pdu_flags, (long unsigned)pci->seqnum);
}
EXPORT_SYMBOL_GPL(rina_pci_dump);
