#ifndef __RINA_BUFS_H__
#define __RINA_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>


struct rina_buf {
    uint8_t *ptr;
    size_t size;

    struct list_head node;
};

struct rina_buf *rina_buf_alloc(size_t size, gfp_t gfp);

void rina_buf_free(struct rina_buf *rb);

#endif  /* __RINA_BUFS_H__ */
