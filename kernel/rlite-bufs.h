/*
 * Packet buffers for the rlite stack.
 *
 * Copyright (C) 2016 Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_BUFS_H__
#define __RLITE_BUFS_H__

#include <linux/types.h>
#include <linux/list.h>
#include <asm/atomic.h>

#include "rlite/common.h"


#define RLITE_DEFAULT_LAYERS    3

/* PDU type definitions. */
#define PDU_T_MGMT          0x40    /* Management PDU */
#define PDU_T_DT            0x80    /* Data Transfer PDU */
#define PDU_T_CTRL_MASK     0xC0
#define PDU_T_ACK_BIT       0x04
#define PDU_T_FC_BIT        0x08
#define PDU_T_ACK_MASK      0x03
#define PDU_T_ACK           0   /* Conventional ACK */
#define PDU_T_NACK          1   /* Force PDU retransmission */
#define PDU_T_SACK          2   /* Selective ACK */
#define PDU_T_SNACK         3   /* Selective NACK */


/* PCI header to be used for transfer PDUs. */
struct rina_pci {
    /* We miss the version field. */
    rl_addr_t dst_addr;
    rl_addr_t src_addr;
    struct {
        uint32_t qos_id;
        uint32_t dst_cep;
        uint32_t src_cep;
    } conn_id;
    uint8_t pdu_type;
    uint8_t pdu_flags;
    uint16_t pdu_len;
    rl_seq_t seqnum;
} __attribute__((packed));

/* PCI header to be used for control PDUs. */
struct rina_pci_ctrl {
    struct rina_pci base;
    rl_seq_t last_ctrl_seq_num_rcvd;
    rl_seq_t ack_nack_seq_num;
    rl_seq_t new_rwe;
    rl_seq_t new_lwe;
    rl_seq_t my_lwe;
    rl_seq_t my_rwe;
} __attribute__((packed));

struct rl_rawbuf {
    size_t size;
    atomic_t refcnt;
    uint8_t buf[0];
};

struct rl_buf {
    struct rl_rawbuf  *raw;
    struct rina_pci    *pci;
    size_t              len;

    unsigned long       rtx_jiffies;

    struct flow_entry   *tx_compl_flow;
    struct list_head    node;
};

struct rl_buf *rl_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

struct rl_buf * rl_buf_alloc_ctrl(size_t num_pci, gfp_t gfp);

struct rl_buf * rl_buf_clone(struct rl_buf *rb, gfp_t gfp);

void rl_buf_free(struct rl_buf *rb);

static inline int
rl_buf_pci_pop(struct rl_buf *rb)
{
    if (unlikely(rb->len < sizeof(struct rina_pci))) {
        RPD(5, "No enough data to pop another PCI\n");
        return -1;
    }

    rb->pci++;
    rb->len -= sizeof(struct rina_pci);

    return 0;
}

static inline int
rl_buf_pci_push(struct rl_buf *rb)
{
    if (unlikely((uint8_t *)(rb->pci-1) < &rb->raw->buf[0])) {
        RPD(5, "No space to push another PCI\n");
        return -1;
    }

    rb->pci--;
    rb->len += sizeof(struct rina_pci);

    return 0;
}

static inline int rl_buf_custom_push(struct rl_buf *rb, size_t len)
{
    if (unlikely((uint8_t *)(rb->pci) - len < &rb->raw->buf[0])) {
        RPD(5, "No space to push custom header\n");
        return -1;
    }

    rb->pci = (struct rina_pci *)(((uint8_t *)rb->pci) - len);
    rb->len += len;

    return 0;
}

void rina_pci_dump(struct rina_pci *pci);

#define RLITE_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RLITE_BUF_PCI(rb) rb->pci
#define RLITE_BUF_PCI_CTRL(rb) ((struct rina_pci_ctrl *)rb->pci)

#endif  /* __RLITE_BUFS_H__ */
