#include <linux/types.h>
#include <linux/slab.h>
#include "rina-bufs.h"


struct rina_buf *
rina_buf_alloc(size_t size, gfp_t gfp)
{
    struct rina_buf *rb = NULL;
    uint8_t *kbuf;

    rb = kmalloc(sizeof(*rb), gfp);
    if (unlikely(!rb)) {
        printk("%s: Out of memory\n", __func__);
        return NULL;
    }

    kbuf = kmalloc(size, GFP_KERNEL);
    if (unlikely(!kbuf)) {
        kfree(rb);
        printk("%s: Out of memory\n", __func__);
        return NULL;
    }

    rb->ptr = kbuf;
    rb->size = size;

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
