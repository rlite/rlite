#ifndef __VMPI_BUFS_H__
#define __VMPI_BUFS_H__

#include <linux/uio.h>
#include <linux/list.h>
#include "../rlite-bufs.h"


#define vmpi_buf            rl_buf
#define vmpi_buf_alloc      rl_buf_alloc
#define vmpi_buf_clone      rl_buf_clone
#define vmpi_buf_free       rl_buf_free
#define vmpi_buf_data(_vb)  RLITE_BUF_DATA(_vb)


static inline size_t vmpi_buf_size(struct vmpi_buf *vb)
{
    return vb->raw->size;
}

static inline size_t vmpi_buf_len(struct vmpi_buf *vb)
{
    return vb->len;
}

static inline void vmpi_buf_set_len(struct vmpi_buf *vb, size_t len)
{
    vb->len = len;
}

#endif /* __VMPI_BUFS_H__ */
