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

    kbuf = kmalloc(real_size, GFP_KERNEL);
    if (unlikely(!kbuf)) {
        kfree(rb);
        printk("%s: Out of memory\n", __func__);
        return NULL;
    }

    rb->ptr = kbuf;
    rb->size = real_size;
    rb->pci = (struct rina_pci *)(kbuf + num_pci * sizeof(struct rina_pci));
    rb->len = size;

    return rb;
}
EXPORT_SYMBOL_GPL(rina_buf_alloc);

void
rina_buf_free(struct rina_buf *rb)
{
    kfree(rb->ptr);
    kfree(rb);
}
EXPORT_SYMBOL_GPL(rina_buf_free);
