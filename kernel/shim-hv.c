/*
 * Shim IPCP over VMPI.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
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
#include <linux/string.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"
#include <vmpi.h>
#include "shim-hv-msg.h"

#include <linux/module.h>
#include <linux/uio.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>


struct rl_shim_hv {
    struct ipcp_entry *ipcp;
    struct vmpi_ops vmpi_ops;
    unsigned int vmpi_id;
};

static int
shim_hv_send_ctrl_msg(struct ipcp_entry *ipcp,
                      struct rl_msg_base *msg)
{
    struct rl_shim_hv *priv = (struct rl_shim_hv *)ipcp->priv;
    struct rl_buf *rb;
    unsigned int serlen;
    int ret;

    serlen = rl_msg_serlen(rl_shim_hv_numtables, RLITE_SHIM_HV_MSG_MAX,
                             msg);
    rb = rl_buf_alloc(serlen, 1, GFP_ATOMIC);
    if (!rb) {
        PE("Out of memory\n");
        return -ENOMEM;
    }

    ret = serialize_rlite_msg(rl_shim_hv_numtables, RLITE_SHIM_HV_MSG_MAX,
                              RLITE_BUF_DATA(rb), msg);
    if (ret != serlen) {
        PE("Error while serializing\n");
        return -EINVAL;
    }
    rb->len = serlen;

    ret = priv->vmpi_ops.write(&priv->vmpi_ops, 0, rb);

    rl_msg_free(rl_shim_hv_numtables, RLITE_SHIM_HV_MSG_MAX, msg);

    return !(ret == serlen);
}

static void
shim_hv_handle_ctrl_message(struct rl_shim_hv *priv,
                            struct rl_buf *rb)
{
    int ret = 0;

    rl_msg_t ty = *((const rl_msg_t *)RLITE_BUF_DATA(rb));

    if (ty == RLITE_SHIM_HV_FA_REQ) {
        struct rl_hmsg_fa_req req;

        ret = deserialize_rlite_msg(rl_shim_hv_numtables,
                                    RLITE_SHIM_HV_MSG_MAX,
                                    RLITE_BUF_DATA(rb), rb->len,
                                    &req, sizeof(req));
        if (ret) {
            PE("failed to deserialize msg type %u\n", ty);
            goto des_fail;
        }

        ret = rl_fa_req_arrived(priv->ipcp, 0, req.src_port, 0, 0,
                    req.dst_appl, req.src_appl, NULL, NULL, false);
        if (ret) {
            PE("failed to report flow allocation request\n");
        }

    } else if (ty == RLITE_SHIM_HV_FA_RESP) {
        struct rl_hmsg_fa_resp resp;

        ret = deserialize_rlite_msg(rl_shim_hv_numtables,
                                   RLITE_SHIM_HV_MSG_MAX,
                                   RLITE_BUF_DATA(rb), rb->len,
                                   &resp, sizeof(resp));
        if (ret) {
            PE("failed to deserialize msg type %u\n", ty);
            goto des_fail;
        }

        ret = rl_fa_resp_arrived(priv->ipcp, resp.src_port,
                                    resp.dst_port, 0, 0, resp.response,
                                    NULL, false);
        if (ret) {
            PE("failed to report flow allocation response\n");
        }

    } else {
        PE("unknown ctrl msg type %u\n", ty);
    }

des_fail:
    rl_buf_free(rb);
}

static void
shim_hv_read_cb(void *opaque, unsigned int channel,
                struct rl_buf *rb)
{
    struct rl_shim_hv *priv = (struct rl_shim_hv *)opaque;

    if (unlikely(channel == 0)) {
        /* Control message. */
        shim_hv_handle_ctrl_message(priv, rb);
        return;
    }

    /* TODO priv->ipcp->depth */
    rl_sdu_rx(priv->ipcp, rb, channel - 1);
}

static void
shim_hv_write_restart_cb(void *opaque)
{
    struct rl_shim_hv *priv = (struct rl_shim_hv *)opaque;

    rl_write_restart_flows(priv->ipcp);
}

static void *
rl_shim_hv_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_hv *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    priv->vmpi_id = ~0U;

    ipcp->max_sdu_size = PAGE_SIZE - 64; /* 64 to stay safe */

    PD("New IPC created [%p]\n", priv);

    return priv;
}

static void
rl_shim_hv_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_hv *priv = ipcp->priv;

    kfree(priv);

    PD("IPC [%p] destroyed\n", priv);
}

static int
rl_shim_hv_fa_req(struct ipcp_entry *ipcp, struct flow_entry *flow,
                  struct rina_flow_spec *spec)
{
    struct rl_hmsg_fa_req req;

    if (!rina_flow_spec_best_effort(spec)) {
        /* We don't support this QoS request. */
        return -EINVAL;
    }

    rl_flow_share_tx_wqh(flow);

    req.msg_type = RLITE_SHIM_HV_FA_REQ;
    req.event_id = 0;
    req.src_appl = kstrdup(flow->local_appl, GFP_KERNEL);
    req.dst_appl = kstrdup(flow->remote_appl, GFP_KERNEL);
    req.src_port = flow->local_port;

    return shim_hv_send_ctrl_msg(ipcp, RLITE_MB(&req));
}

static int
rl_shim_hv_fa_resp(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      uint8_t response)
{
    struct rl_hmsg_fa_resp resp;

    rl_flow_share_tx_wqh(flow);

    resp.msg_type = RLITE_SHIM_HV_FA_RESP;
    resp.event_id = 0;
    resp.dst_port = flow->local_port;
    resp.src_port = flow->remote_port;
    resp.response = response;

    return shim_hv_send_ctrl_msg(ipcp, RLITE_MB(&resp));
}

static int
rl_shim_hv_sdu_write(struct ipcp_entry *ipcp,
                     struct flow_entry *flow,
                     struct rl_buf *rb, bool maysleep)
{
    struct rl_shim_hv *priv = (struct rl_shim_hv *)ipcp->priv;
    struct vmpi_ops *vmpi_ops = &priv->vmpi_ops;
    int len = rb->len;
    ssize_t ret;

    if (unlikely(!vmpi_ops->write)) {
        return -ENXIO;
    }

    ret = vmpi_ops->write(vmpi_ops, flow->remote_port + 1, rb);

    if (unlikely(ret != len)) {
        return ret < 0 ? ret : -ENOBUFS;
    }

    return 0;
}

static int
rl_shim_hv_config(struct ipcp_entry *ipcp, const char *param_name,
                  const char *param_value, int *notify)
{
    struct rl_shim_hv *priv = (struct rl_shim_hv *)ipcp->priv;
    int ret = -ENOSYS;

    if (strcmp(param_name, "vmpi-id") == 0) {
        unsigned int provider = VMPI_PROVIDER_AUTO;

        ret = kstrtouint(param_value, 10, &priv->vmpi_id);
        if (ret == 0) {
            PI("vmpi id set to %u\n", priv->vmpi_id);
        }

        ret = vmpi_provider_find_instance(provider, priv->vmpi_id,
                                          &priv->vmpi_ops);
        if (ret) {
            PE("vmpi_provider_find(%u, %u) failed\n", provider, priv->vmpi_id);
            return ret;
        }

        ret = priv->vmpi_ops.register_cbs(&priv->vmpi_ops,
                                          shim_hv_read_cb,
                                          shim_hv_write_restart_cb,
                                          priv);
        if (ret) {
            PE("register_read_callback() failed\n");
            return ret;
        }
    } else if (strcmp(param_name, "mss") == 0) {
        /* Deny. */
        return -EPERM;
    }

    return ret;
}

#define SHIM_DIF_TYPE   "shim-hv"

static struct ipcp_factory shim_hv_factory = {
    .owner                      = THIS_MODULE,
    .dif_type                   = SHIM_DIF_TYPE,
    .use_cep_ids                = false,
    .create                     = rl_shim_hv_create,
    .ops.destroy                = rl_shim_hv_destroy,
    .ops.flow_allocate_req      = rl_shim_hv_fa_req,
    .ops.flow_allocate_resp     = rl_shim_hv_fa_resp,
    .ops.sdu_write              = rl_shim_hv_sdu_write,
    .ops.config                 = rl_shim_hv_config,
};

static int __init
rl_shim_hv_init(void)
{
    return rl_ipcp_factory_register(&shim_hv_factory);
}

static void __exit
rl_shim_hv_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rl_shim_hv_init);
module_exit(rl_shim_hv_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
