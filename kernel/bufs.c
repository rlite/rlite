/*
 * Packet buffers for the rlite stack.
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include "rlite-bufs.h"
#include "rlite/common.h"


struct rlite_buf *
rlite_buf_alloc(size_t size, size_t num_pci, gfp_t gfp)
{
    struct rlite_buf *rb;
    size_t real_size = size + num_pci * sizeof(struct rina_pci);
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

    rb->raw = (struct rlite_rawbuf *)kbuf;
    rb->raw->size = real_size;
    atomic_set(&rb->raw->refcnt, 1);
    rb->pci = (struct rina_pci *)(rb->raw->buf + num_pci * sizeof(struct rina_pci));
    rb->len = size;
    rb->tx_compl_flow = NULL;

    return rb;
}
EXPORT_SYMBOL(rlite_buf_alloc);

struct rlite_buf *
rlite_buf_alloc_ctrl(size_t num_pci, gfp_t gfp)
{
    return rlite_buf_alloc(sizeof(struct rina_pci_ctrl), num_pci, gfp);
}
EXPORT_SYMBOL(rlite_buf_alloc_ctrl);

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
EXPORT_SYMBOL(rlite_buf_clone);

void
rlite_buf_free(struct rlite_buf *rb)
{
    if (atomic_dec_and_test(&rb->raw->refcnt)) {
        kfree(rb->raw);
    }
    kfree(rb);
}
EXPORT_SYMBOL(rlite_buf_free);

void
rina_pci_dump(struct rina_pci *pci)
{
    PD("PCI: dst=%lx,src=%lx,qos=%u,dcep=%u,scep=%u,type=%x,flags=%x,"
        "seq=%lu\n", (long unsigned)pci->dst_addr,
        (long unsigned)pci->src_addr, pci->conn_id.qos_id,
        pci->conn_id.dst_cep, pci->conn_id.src_cep,
        pci->pdu_type, pci->pdu_flags, (long unsigned)pci->seqnum);
}
EXPORT_SYMBOL(rina_pci_dump);
