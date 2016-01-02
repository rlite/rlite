#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "rinalite/rinalite-utils.h"
#include "rinalite/rina-conf-msg.h"

#include "uipcp-container.h"


#define MGMTBUF_SIZE_MAX 4096

static int
mgmt_write(struct uipcp *uipcp, const struct rina_mgmt_hdr *mhdr,
           void *buf, size_t buflen)
{
    void *mgmtbuf;
    int n;
    int ret = 0;

    if (buflen > MGMTBUF_SIZE_MAX) {
        PE("Dropping oversized mgmt message %d/%d\n",
            (int)buflen, MGMTBUF_SIZE_MAX);
    }

    mgmtbuf = malloc(sizeof(*mhdr) + buflen);
    if (!mgmtbuf) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memcpy(mgmtbuf, mhdr, sizeof(*mhdr));
    memcpy(mgmtbuf + sizeof(*mhdr), buf, buflen);
    buflen += sizeof(*mhdr);

    n = write(uipcp->mgmtfd, mgmtbuf, buflen);
    if (n < 0) {
        PE("write(): %d\n", n);
        ret = n;
    } else if (n != buflen) {
        PE("partial write %d/%d\n", n, (int)buflen);
        ret = -1;
    }

    free(mgmtbuf);

    return ret;
}

int
mgmt_write_to_local_port(struct uipcp *uipcp, uint32_t local_port,
                         void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_T_OUT_LOCAL_PORT;
    mhdr.local_port = local_port;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

int
mgmt_write_to_dst_addr(struct uipcp *uipcp, uint64_t dst_addr,
                       void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_T_OUT_DST_ADDR;
    mhdr.remote_addr = dst_addr;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

int
uipcp_pduft_set(struct uipcp *uipcp, uint16_t ipcp_id,
                uint64_t dest_addr, uint32_t local_port)
{
    struct rina_kmsg_ipcp_pduft_set *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_PDUFT_SET;
    req->ipcp_id = ipcp_id;
    req->dest_addr = dest_addr;
    req->local_port = local_port;

    PD("Requesting IPCP pdu forwarding table set...\n");

    resp = rinalite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_pduft_flush(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rina_kmsg_ipcp_pduft_flush *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_PDUFT_FLUSH;
    req->ipcp_id = ipcp_id;

    PD("Requesting IPCP pdu forwarding table flush...\n");

    resp = rinalite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req),
                                  sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_fa_req_arrived(struct uipcp *uipcp, uint32_t remote_port,
                     uint64_t remote_addr,
                     const struct rina_name *local_application,
                     const struct rina_name *remote_application,
                     const struct rina_flow_config *flowcfg)
{
    struct rina_kmsg_uipcp_fa_req_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FA_REQ_ARRIVED;
    req->ipcp_id = uipcp->ipcp_id;
    req->remote_port = remote_port;
    req->remote_addr = remote_addr;
    memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    rina_name_copy(&req->local_application, local_application);
    rina_name_copy(&req->remote_application, remote_application);

    PD("[uipcp %u] Issuing UIPCP_FA_REQ_ARRIVED message...\n",
        uipcp->ipcp_id);

    resp = rinalite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_fa_resp_arrived(struct uipcp *uipcp, uint32_t local_port,
                      uint32_t remote_port, uint64_t remote_addr,
                      uint8_t response)
{
    struct rina_kmsg_uipcp_fa_resp_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FA_RESP_ARRIVED;
    req->ipcp_id = uipcp->ipcp_id;
    req->local_port = local_port;
    req->remote_port = remote_port;
    req->remote_addr = remote_addr;
    req->response = response;

    PD("[uipcp %u] Issuing UIPCP_FA_RESP_ARRIVED message...\n",
        uipcp->ipcp_id);

    resp = rinalite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

static void
mgmt_fd_ready(struct rinalite_evloop *loop, int fd)
{
    struct rinalite_appl *appl = container_of(loop, struct rinalite_appl, loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    struct rina_mgmt_hdr *mhdr;
    int n;

    assert(fd == uipcp->mgmtfd);

    /* Read a buffer that contains a management header followed by
     * a management SDU. */
    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        PE("Error: read() failed [%d]\n", n);
        goto out;

    } else if (n < sizeof(*mhdr)) {
        PE("Error: read() does not contain mgmt header, %d<%d\n",
                n, (int)sizeof(*mhdr));
        goto out;
    }

    /* Grab the management header. */
    mhdr = (struct rina_mgmt_hdr *)mgmtbuf;
    assert(mhdr->type == RINA_MGMT_HDR_T_IN);

    rib_msg_rcvd(uipcp->rib, mhdr, ((char *)(mhdr + 1)),
                  n - sizeof(*mhdr));
out:
    fflush(stdout);
}

static int
uipcp_fa_req(struct rinalite_evloop *loop,
             const struct rina_msg_base_resp *b_resp,
             const struct rina_msg_base *b_req)
{
    struct rinalite_appl *application = container_of(loop, struct rinalite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_req *req = (struct rina_kmsg_fa_req *)b_resp;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    return rib_fa_req(uipcp->rib, req);
}

static int
uipcp_fa_resp(struct rinalite_evloop *loop,
              const struct rina_msg_base_resp *b_resp,
              const struct rina_msg_base *b_req)
{
    struct rinalite_appl *application = container_of(loop, struct rinalite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_resp *resp =
                (struct rina_kmsg_fa_resp *)b_resp;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    return rib_fa_resp(uipcp->rib, resp);
}

static int
uipcp_application_register(struct rinalite_evloop *loop,
                           const struct rina_msg_base_resp *b_resp,
                           const struct rina_msg_base *b_req)
{
    struct rinalite_appl *application = container_of(loop, struct rinalite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_application_register *req =
                (struct rina_kmsg_application_register *)b_resp;

    rib_application_register(uipcp->rib, req->reg, &req->application_name);

    return 0;
}

void *
uipcp_server(void *arg)
{
    struct uipcp *uipcp = arg;

    for (;;) {
        struct rinalite_pending_flow_req *pfr;
        unsigned int port_id;
        int flow_fd;
        int result;
        int ret;

        pfr = rinalite_flow_req_wait(&uipcp->appl);
        port_id = pfr->port_id;
        PD("flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
                pfr->ipcp_id, pfr->port_id);

        result = rinalite_flow_allocate_resp(&uipcp->appl, pfr->ipcp_id,
                                    uipcp->ipcp_id, pfr->port_id, 0);

        if (result) {
            rinalite_pending_flow_req_free(pfr);
            continue;
        }

        flow_fd = rinalite_open_appl_port(port_id);
        if (flow_fd < 0) {
            rinalite_pending_flow_req_free(pfr);
            continue;
        }

        ret = rib_neighbor_flow(uipcp->rib, &pfr->remote_appl,
                                flow_fd, port_id);
        rinalite_pending_flow_req_free(pfr);
        if (ret) {
            PE("rib_neighbor_flow() failed\n");
        }

        fflush(stdout);
    }

    return NULL;
}

static int
uipcp_evloop_set(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rina_kmsg_ipcp_uipcp_set *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_UIPCP_SET;
    req->ipcp_id = ipcp_id;

    PD("Requesting IPCP uipcp set...\n");

    resp = rinalite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

struct uipcp *
uipcp_lookup(struct uipcps *uipcps, uint16_t ipcp_id)
{
    struct uipcp *cur;

    list_for_each_entry(cur, &uipcps->uipcps, node) {
        if (cur->ipcp_id == ipcp_id) {
            return cur;
        }
    }

    return NULL;
}

int
uipcp_add(struct uipcps *uipcps, uint16_t ipcp_id)
{
    struct uipcp *uipcp;
    int ret;

    uipcp = malloc(sizeof(*uipcp));
    if (!uipcp) {
        PE("Out of memory\n");
        return ENOMEM;
    }
    memset(uipcp, 0, sizeof(*uipcp));

    uipcp->ipcp_id = ipcp_id;
    uipcp->uipcps = uipcps;

    uipcp->rib = rib_create(uipcp);
    if (!uipcp->rib) {
        goto err0;
    }

    list_add_tail(&uipcp->node, &uipcps->uipcps);

    ret = rinalite_appl_init(&uipcp->appl);
    if (ret) {
        goto err1;
    }

    /* Set the evloop handlers for flow allocation request/response and
     * registration reflected messages. */
    ret = rinalite_evloop_set_handler(&uipcp->appl.loop, RINA_KERN_FA_REQ,
                                      uipcp_fa_req);
    if (ret) {
        goto err2;
    }

    ret = rinalite_evloop_set_handler(&uipcp->appl.loop, RINA_KERN_FA_RESP,
                                      uipcp_fa_resp);
    if (ret) {
        goto err2;
    }

    ret = rinalite_evloop_set_handler(&uipcp->appl.loop,
                                      RINA_KERN_APPLICATION_REGISTER,
                                      uipcp_application_register);
    if (ret) {
        goto err2;
    }

    /* Tell the kernel what is the event loop to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_evloop_set(uipcp, ipcp_id);
    if (ret) {
        goto err2;
    }

    uipcp->mgmtfd = rinalite_open_mgmt_port(ipcp_id);
    if (uipcp->mgmtfd < 0) {
        ret = uipcp->mgmtfd;
        goto err2;
    }

    rinalite_evloop_fdcb_add(&uipcp->appl.loop, uipcp->mgmtfd, mgmt_fd_ready);

    ret = pthread_create(&uipcp->server_th, NULL, uipcp_server, uipcp);
    if (ret) {
        goto err3;
    }

    PD("userspace IPCP %u created\n", ipcp_id);

    return 0;

err3:
    close(uipcp->mgmtfd);
err2:
    rinalite_appl_fini(&uipcp->appl);
err1:
    list_del(&uipcp->node);
err0:
    rib_destroy(uipcp->rib);
    free(uipcp);

    return ret;
}

int
uipcp_del(struct uipcps *uipcps, uint16_t ipcp_id)
{
    struct uipcp *uipcp;
    int ret;

    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        /* The specified IPCP is a Shim IPCP. */
        return 0;
    }

    rinalite_evloop_fdcb_del(&uipcp->appl.loop, uipcp->mgmtfd);

    close(uipcp->mgmtfd);

    rinalite_evloop_stop(&uipcp->appl.loop);

    ret = rinalite_appl_fini(&uipcp->appl);

    list_del(&uipcp->node);

    rib_destroy(uipcp->rib);

    free(uipcp);

    if (ret == 0) {
        PD("userspace IPCP %u destroyed\n", ipcp_id);
    }

    return ret;
}

int
uipcps_fetch(struct uipcps *uipcps)
{
    struct uipcp *uipcp;
    int ret;
    int first = 1;

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        ret = rinalite_ipcps_fetch(&uipcp->appl.loop);
        if (ret) {
            return ret;
        }

        if (first) {
            /* This is just for debugging purposes. */
            first = 0;
            rinalite_ipcps_print(&uipcp->appl.loop);
            fflush(stdout);
        }
    }

    return 0;
}

