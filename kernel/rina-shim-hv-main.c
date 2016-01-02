/*
 * RINA shim DIF for HV
 *
 *    Vincenzo Maffione <v.maffione@gmail.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/types.h>
#include <rina/rina-utils.h>
#include <rina/rina-ipcp-types.h>
#include <vmpi-provider.h>
#include "rina-ipcp.h"
#include "rina-shim-hv-msg.h"

#include <linux/module.h>
#include <linux/uio.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>


struct rina_shim_hv {
    struct ipcp_entry *ipcp;
    struct vmpi_ops vmpi_ops;
    unsigned int vmpi_id;
};

static int
shim_hv_send_ctrl_msg(struct ipcp_entry *ipcp,
                      struct rina_msg_base *msg)
{
    struct rina_shim_hv *priv = (struct rina_shim_hv *)ipcp->priv;
    struct iovec iov;
    unsigned int serlen;
    int ret;
    uint8_t *serbuf;

    serlen = rina_msg_serlen(rina_shim_hv_numtables, msg);
    serbuf = kmalloc(serlen, GFP_ATOMIC);
    if (!serbuf) {
        printk("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    iov.iov_base = serbuf;
    iov.iov_len = serlen;
    ret = priv->vmpi_ops.write(&priv->vmpi_ops, 0, &iov, 1);

    kfree(serbuf);

    return !(ret == serlen);
}

static void
shim_hv_handle_ctrl_message(struct rina_shim_hv *priv,
                            const char *serbuf, int serlen)
{
    int ret;

    rina_msg_t ty = *((const rina_msg_t *)serbuf);

    if (ty == RINA_SHIM_HV_FLOW_ALLOCATE_REQ) {
        struct rina_hmsg_flow_allocate_req req;

        ret = deserialize_rina_msg(rina_shim_hv_numtables, serbuf, serlen,
                                   &req, sizeof(req));
        if (ret) {
            goto des_fail;
        }
    } else if (ty == RINA_SHIM_HV_FLOW_ALLOCATE_RESP) {
        struct rina_hmsg_flow_allocate_resp resp;

        ret = deserialize_rina_msg(rina_shim_hv_numtables, serbuf, serlen,
                                   &resp, sizeof(resp));
        if (ret) {
            goto des_fail;
        }
    } else {
        printk("%s: unknown ctrl msg type %u\n", __func__, ty);
    }

    return;

des_fail:
    if (ret) {
        printk("%s: failed to deserialize msg type %u\n", __func__, ty);
    }
}

static void
shim_hv_read_callback(void *opaque, unsigned int channel,
                      const char *buf, int len)
{
    struct rina_shim_hv *priv = (struct rina_shim_hv *)opaque;
    struct rina_buf *rb;

    if (unlikely(channel == 0)) {
        /* Control message. */
        shim_hv_handle_ctrl_message(priv, buf, len);
        return;
    }

    rb = rina_buf_alloc(len, GFP_ATOMIC);
    if (!rb) {
        printk("%s: Out of memory\n", __func__);
        return;
    }

    rina_sdu_rx(priv->ipcp, rb, channel - 1);
}

static void *
rina_shim_hv_create(struct ipcp_entry *ipcp)
{
    struct rina_shim_hv *priv;
    unsigned int provider = VMPI_PROVIDER_AUTO;
    unsigned int id = 0; // XXX
    int ret;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    ret = vmpi_provider_find_instance(provider, id, &priv->vmpi_ops);
    if (ret) {
        printk("vmpi_provider_find(%u, %u) failed\n", provider, id);
        return NULL;
    }

    ret = priv->vmpi_ops.register_read_callback(&priv->vmpi_ops,
            shim_hv_read_callback, priv);
    if (ret) {
        printk("register_read_callback() failed\n");
        return NULL;
    }

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_hv_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_hv *priv = ipcp->priv;

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static int
rina_shim_hv_application_register(struct ipcp_entry *ipcp,
                                     struct rina_name *application_name)
{
    return 0;
}

static int
rina_shim_hv_application_unregister(struct ipcp_entry *ipcp,
                                       struct rina_name *application_name)
{
    return 0;
}

static int
rina_shim_hv_assign_to_dif(struct ipcp_entry *ipcp,
                           struct rina_name *dif_name)
{
    return 0;
}

static int
rina_shim_hv_flow_allocate_req(struct ipcp_entry *ipcp,
                               struct flow_entry *flow)
{
    struct rina_hmsg_flow_allocate_req req;

    req.msg_type = RINA_SHIM_HV_FLOW_ALLOCATE_REQ;
    req.event_id = 0;
    rina_name_copy(&req.local_application, &flow->local_application);
    rina_name_copy(&req.remote_application, &flow->remote_application);
    req.local_port = flow->local_port;

    return shim_hv_send_ctrl_msg(ipcp, (struct rina_msg_base *)&req);
}

static int
rina_shim_hv_flow_allocate_resp(struct ipcp_entry *ipcp,
                                   struct flow_entry *flow,
                                   uint8_t response)
{
    return -1;
}

static int
rina_shim_hv_sdu_write(struct ipcp_entry *ipcp,
                       struct flow_entry *flow,
                       struct rina_buf *rb)
{
    struct iovec iov;
    struct rina_shim_hv *priv = (struct rina_shim_hv *)ipcp->priv;
    struct vmpi_ops *vmpi_ops = &priv->vmpi_ops;

    iov.iov_base = rb->ptr;
    iov.iov_len = rb->size;

    return vmpi_ops->write(vmpi_ops, flow->remote_port + 1,
                           &iov, 1);
}

static int __init
rina_shim_hv_init(void)
{
    struct ipcp_factory factory;
    int ret;

    memset(&factory, 0, sizeof(factory));
    factory.owner = THIS_MODULE;
    factory.dif_type = DIF_TYPE_SHIM_HV;
    factory.create = rina_shim_hv_create;
    factory.ops.destroy = rina_shim_hv_destroy;
    factory.ops.application_register = rina_shim_hv_application_register;
    factory.ops.application_unregister = rina_shim_hv_application_unregister;
    factory.ops.assign_to_dif = rina_shim_hv_assign_to_dif;
    factory.ops.flow_allocate_req = rina_shim_hv_flow_allocate_req;
    factory.ops.flow_allocate_resp = rina_shim_hv_flow_allocate_resp;
    factory.ops.sdu_write = rina_shim_hv_sdu_write;

    ret = rina_ipcp_factory_register(&factory);

    return ret;
}

static void __exit
rina_shim_hv_fini(void)
{
    rina_ipcp_factory_unregister(DIF_TYPE_SHIM_DUMMY);
}

module_init(rina_shim_hv_init);
module_exit(rina_shim_hv_fini);
MODULE_LICENSE("GPL");
