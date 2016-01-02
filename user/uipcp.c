#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <rina/rina-utils.h>
#include "ipcm.h"


#define MGMTBUF_SIZE_MAX 2048

static int
mgmt_write(struct uipcp *uipcp, const struct rina_mgmt_hdr *mhdr,
           void *buf, size_t buflen)
{
    void *mgmtbuf;
    int n;
    int ret = 0;

    if (buflen > MGMTBUF_SIZE_MAX) {
        PE("%s: Dropping oversized mgmt message %d/%d\n", __func__,
            (int)buflen, MGMTBUF_SIZE_MAX);
    }

    mgmtbuf = malloc(sizeof(*mhdr) + buflen);
    if (!mgmtbuf) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memcpy(mgmtbuf, mhdr, sizeof(*mhdr));
    memcpy(mgmtbuf + sizeof(*mhdr), buf, buflen);
    buflen += sizeof(*mhdr);

    n = write(uipcp->mgmtfd, mgmtbuf, buflen);
    if (n < 0) {
        PE("%s: write(): %d\n", __func__, n);
        ret = n;
    } else if (n != buflen) {
        PE("%s: partial write %d/%d\n", __func__, n, (int)buflen);
        ret = -1;
    }

    free(mgmtbuf);

    return ret;
}

static int
mgmt_write_to_local_port(struct uipcp *uipcp, uint32_t local_port,
                         void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_T_OUT_LOCAL_PORT;
    mhdr.local_port = local_port;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

static int
mgmt_write_to_dst_addr(struct uipcp *uipcp, uint64_t dst_addr,
                       void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_T_OUT_DST_ADDR;
    mhdr.remote_addr = dst_addr;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

static int
uipcp_enroll_send_mgmtsdu(struct uipcp *uipcp, unsigned int port_id)
{
    int ret;
    uint64_t local_addr;
    uint8_t cmd = IPCP_MGMT_ENROLL;
    uint8_t mgmtsdu[sizeof(cmd) + sizeof(local_addr)];

    /* Exchange IPCP addresses. */
    ret = lookup_ipcp_addr_by_id(&uipcp->appl.loop, uipcp->ipcp_id,
                                 &local_addr);
    assert(!ret);
    local_addr = htole64(local_addr);

    mgmtsdu[0] = cmd;
    memcpy(mgmtsdu + 1, &local_addr, sizeof(local_addr));

    ret = mgmt_write_to_local_port(uipcp, port_id, mgmtsdu, sizeof(mgmtsdu));

    return ret;
}

struct enrolled_neighbor {
    struct rina_name ipcp_name;
    int flow_fd;

    struct list_head node;
};

int uipcp_enroll(struct uipcp *uipcp, struct rina_amsg_ipcp_enroll *req)
{
    struct enrolled_neighbor *neigh;
    unsigned int port_id;
    int ret;

    list_for_each_entry(neigh, &uipcp->enrolled_neighbors, node) {
        if (rina_name_cmp(&neigh->ipcp_name, &req->neigh_ipcp_name) == 0) {
            char *ipcp_s = rina_name_to_string(&req->neigh_ipcp_name);

            PI("[uipcp %u] Already enrolled to %s", uipcp->ipcp_id, ipcp_s);
            if (ipcp_s) {
                free(ipcp_s);
            }

            return -1;
        }
    }

    neigh = malloc(sizeof(*neigh));
    if (!neigh) {
        PE("%s: Out of memory\n", __func__);
        return -1;
    }
    memset(neigh, 0, sizeof(*neigh));
    rina_name_copy(&neigh->ipcp_name, &req->neigh_ipcp_name);
    list_add_tail(&neigh->node, &uipcp->enrolled_neighbors);

    /* Allocate a flow for the enrollment. */
    ret = flow_allocate(&uipcp->appl, &req->supp_dif_name, 0, NULL,
                         &req->ipcp_name, &req->neigh_ipcp_name, NULL,
                         &port_id, 2000);
    if (ret) {
        goto err;
    }

    neigh->flow_fd = open_port_ipcp(port_id, uipcp->ipcp_id);
    if (neigh->flow_fd < 0) {
        goto err;
    }

    /* Request an enrollment. */

    return uipcp_enroll_send_mgmtsdu(uipcp, port_id);

err:
    rina_name_free(&neigh->ipcp_name);
    free(neigh);

    return -1;
}

static int
uipcp_mgmt_sdu_enroll(struct uipcp *uipcp, struct rina_mgmt_hdr *mhdr,
                      uint8_t *buf, size_t buflen)
{
    uint64_t remote_addr;

    remote_addr = le64toh(*((uint64_t *)(buf)));

    PD("%s: [uipcp %u] Received enrollment management SDU from IPCP addr %lu\n",
            __func__, uipcp->ipcp_id, (long unsigned)remote_addr);

    ipcp_pduft_set(uipcp->ipcm, uipcp->ipcp_id, remote_addr,
                   mhdr->local_port);

    return 0;
}

static int
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
        PE("%s: Out of memory\n", __func__);
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

    resp = issue_request(&uipcp->appl.loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

static int
uipcp_mgmt_sdu_fa_req(struct uipcp *uipcp, struct rina_mgmt_hdr *mhdr,
                      uint8_t *buf, size_t buflen)
{
    struct rina_name local_application, remote_application;
    const void *ptr = buf;
    uint32_t remote_port;
    struct rina_flow_config flowcfg;
    int ret;

    PD("%s: [uipcp %u] Received fa req management SDU from IPCP addr %lu\n",
            __func__, uipcp->ipcp_id, (long unsigned)mhdr->remote_addr);

    remote_port = le32toh(*((uint32_t *)ptr));
    ptr += sizeof(uint32_t);

    memcpy(&flowcfg, ptr, sizeof(flowcfg)); /* unsafe... */
    ptr += sizeof(flowcfg);

    ret = deserialize_rina_name(&ptr, &remote_application);
    if (ret) {
        PE("%s: deserialization error\n", __func__);
    }

    ret = deserialize_rina_name(&ptr, &local_application);
    if (ret) {
        PE("%s: deserialization error\n", __func__);
    }

    uipcp_fa_req_arrived(uipcp, remote_port, mhdr->remote_addr,
                         &local_application, &remote_application,
                         &flowcfg);

    return 0;
}

static int
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
        PE("%s: Out of memory\n", __func__);
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

    resp = issue_request(&uipcp->appl.loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

static int
uipcp_mgmt_sdu_fa_resp(struct uipcp *uipcp, struct rina_mgmt_hdr *mhdr,
                       uint8_t *buf, size_t buflen)
{
    const void *ptr = buf;
    uint32_t remote_port, local_port;
    uint8_t response;

    PD("%s: [uipcp %u] Received fa resp management SDU from IPCP addr %lu\n",
            __func__, uipcp->ipcp_id, (long unsigned)mhdr->remote_addr);

    remote_port = le32toh(*((uint32_t *)ptr));
    ptr += sizeof(uint32_t);
    local_port = le32toh(*((uint32_t *)ptr));
    ptr += sizeof(uint32_t);
    response = *((uint8_t *)ptr);
    ptr += sizeof(uint8_t);

    uipcp_fa_resp_arrived(uipcp, local_port, remote_port,
                          mhdr->remote_addr, response);

    return 0;
}

static void
mgmt_fd_ready(struct rina_evloop *loop, int fd)
{
    struct application *appl = container_of(loop, struct application, loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    struct rina_mgmt_hdr *mhdr;
    uint8_t *buf;
    size_t buflen;
    uint8_t cmd;
    int n;

    assert(fd == uipcp->mgmtfd);

    /* Read a buffer that contains a management header followed by
     * a management SDU. */
    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        PE("%s: Error: read() failed [%d]\n", __func__, n);
        return;
    } else if (n < sizeof(*mhdr)) {
        PE("%s: Error: read() does not contain mgmt header, %d<%d\n",
                __func__, n, (int)sizeof(*mhdr));
        return;
    }

    /* Grab the management header. */
    mhdr = (struct rina_mgmt_hdr *)mgmtbuf;
    assert(mhdr->type == RINA_MGMT_HDR_T_IN);

    /* Grab the management command (this and the following will be replaced
     * by CDAP). */
    cmd = *((uint8_t *)(mhdr + 1));
    buf = ((uint8_t *)(mhdr + 1)) + 1;
    buflen = n - sizeof(*mhdr) - 1;

    switch (cmd) {
        case IPCP_MGMT_ENROLL:
            uipcp_mgmt_sdu_enroll(uipcp, mhdr, buf, buflen);
            break;

        case IPCP_MGMT_FA_REQ:
            uipcp_mgmt_sdu_fa_req(uipcp, mhdr, buf, buflen);
            break;

        case IPCP_MGMT_FA_RESP:
            uipcp_mgmt_sdu_fa_resp(uipcp, mhdr, buf, buflen);
            break;

        default:
            PI("%s: Unknown cmd %u received\n", __func__, cmd);
            break;
    }
}

struct dft_entry {
    struct rina_name appl_name;
    uint64_t remote_addr;

    struct list_head node;
};

static struct dft_entry *
dft_lookup(struct uipcp *uipcp, const struct rina_name *appl_name)
{
    struct dft_entry *entry;

    list_for_each_entry(entry, &uipcp->dft, node) {
        if (rina_name_cmp(&entry->appl_name, appl_name) == 0) {
            return entry;
        }
    }

    return NULL;
}

int
uipcp_dft_set(struct uipcp *uipcp, const struct rina_name *appl_name,
              uint64_t remote_addr)
{
    struct dft_entry *entry;
    char *appl_s;

    entry = dft_lookup(uipcp, appl_name);
    if (!entry) {
        entry = malloc(sizeof(*entry));
        if (!entry) {
            return -1;
        }
        memset(entry, 0, sizeof(*entry));
        rina_name_copy(&entry->appl_name, appl_name);
        list_add_tail(&entry->node, &uipcp->dft);
    }
    entry->remote_addr = remote_addr;

    appl_s = rina_name_to_string(appl_name);
    PD("%s: [uipcp %u] '%s' --> %llu\n", __func__, uipcp->ipcp_id,
        appl_s, (long long unsigned)remote_addr);
    if (appl_s) {
        free(appl_s);
    }

    return 0;
}

static int
uipcp_fa_req(struct rina_evloop *loop,
             const struct rina_msg_base_resp *b_resp,
             const struct rina_msg_base *b_req)
{
    struct application *application = container_of(loop, struct application,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_req *req = (struct rina_kmsg_fa_req *)b_resp;
    struct dft_entry *dft_entry;
    uint8_t *mgmtsdu;
    void *cur;
    size_t len;

    PD("%s: [uipcp %u] Got reflected message\n", __func__, uipcp->ipcp_id);

    assert(b_req == NULL);

    dft_entry = dft_lookup(uipcp, &req->remote_application);
    if (!dft_entry) {
        /* TODO send a RINA_KERN_UIPCP_FA_RESP_ARRIVED ? */
        PI("%s: No DFT matching entry\n", __func__);
        return 0;
    }

    len = 1 + sizeof(req->local_port) +
            sizeof(req->flowcfg) +
            rina_name_serlen(&req->local_application) +
            rina_name_serlen(&req->remote_application);
    mgmtsdu = malloc(len);
    if (!mgmtsdu) {
        PE("%s: Out of memory\n", __func__);
        return 0;
    }

    mgmtsdu[0] = IPCP_MGMT_FA_REQ;
    cur = mgmtsdu + 1;
    *((uint32_t *)cur) = htole32(req->local_port);
    cur += sizeof(req->local_port);
    memcpy(cur, &req->flowcfg, sizeof(req->flowcfg)); /* unsafe */
    cur += sizeof(req->flowcfg);
    serialize_rina_name(&cur, &req->local_application);
    serialize_rina_name(&cur, &req->remote_application);

    mgmt_write_to_dst_addr(uipcp, dft_entry->remote_addr,
                           mgmtsdu, len);

    free(mgmtsdu);

    return 0;
}

static int
uipcp_fa_resp(struct rina_evloop *loop,
              const struct rina_msg_base_resp *b_resp,
              const struct rina_msg_base *b_req)
{
    struct application *application = container_of(loop, struct application,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_resp *resp =
                (struct rina_kmsg_fa_resp *)b_resp;
    uint8_t *mgmtsdu;
    void *cur;
    size_t len;

    PD("%s: [uipcp %u] Got reflected message\n", __func__, uipcp->ipcp_id);

    assert(b_req == NULL);
    (void)uipcp;
    (void)resp;

    len = 1 + sizeof(resp->port_id) + sizeof(resp->remote_port)
            + sizeof(resp->response);

    mgmtsdu = malloc(len);
    if (!mgmtsdu) {
        PE("%s: Out of memory\n", __func__);
        return 0;
    }

    mgmtsdu[0] = IPCP_MGMT_FA_RESP;
    cur = mgmtsdu + 1;
    *((uint32_t *)cur) = htole32(resp->port_id);
    cur += sizeof(resp->port_id);
    *((uint32_t *)cur) = htole32(resp->remote_port);
    cur += sizeof(resp->remote_port);
    *((uint8_t *)cur) = resp->response;
    cur += sizeof(resp->response);

    mgmt_write_to_dst_addr(uipcp, resp->remote_addr,
                           mgmtsdu, len);
    free(mgmtsdu);

    return 0;
}

void *
uipcp_server(void *arg)
{
    struct uipcp *uipcp = arg;

    for (;;) {
        struct enrolled_neighbor *neigh;
        struct pending_flow_req *pfr;
        unsigned int port_id;
        int result;

        neigh = malloc(sizeof(*neigh));
        if (!neigh) {
            usleep(200000);
            continue;
        }
        memset(neigh, 0, sizeof(*neigh));

        pfr = flow_request_wait(&uipcp->appl);
        port_id = pfr->port_id;
        PD("%s: flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
                __func__, pfr->ipcp_id, pfr->port_id);

        result = flow_allocate_resp(&uipcp->appl, pfr->ipcp_id,
                                    pfr->port_id, 0);

        if (result) {
            pfr_free(pfr);
            free(neigh);
            continue;
        }

        neigh->flow_fd = open_port_ipcp(port_id, uipcp->ipcp_id);
        if (neigh->flow_fd < 0) {
            pfr_free(pfr);
            free(neigh);
            continue;
        }
        rina_name_copy(&neigh->ipcp_name, &pfr->remote_appl);
        list_add_tail(&neigh->node, &uipcp->enrolled_neighbors);
        pfr_free(pfr);

        /* XXX This usleep() is a temporary hack to make sure that the
         * flow allocation response has the time to be processed by the neighbor,
         * so that the flow 'port_id' is setup properly and can receive the
         * enrollment management sdu. */
        usleep(100000);
        uipcp_enroll_send_mgmtsdu(uipcp, port_id);
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
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_UIPCP_SET;
    req->ipcp_id = ipcp_id;

    PD("Requesting IPCP uipcp set...\n");

    resp = issue_request(&uipcp->appl.loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

struct uipcp *
uipcp_lookup(struct ipcm *ipcm, uint16_t ipcp_id)
{
    struct uipcp *cur;

    list_for_each_entry(cur, &ipcm->uipcps, node) {
        if (cur->ipcp_id == ipcp_id) {
            return cur;
        }
    }

    return NULL;
}

int
uipcp_add(struct ipcm *ipcm, uint16_t ipcp_id)
{
    struct uipcp *uipcp;
    int ret;

    uipcp = malloc(sizeof(*uipcp));
    if (!uipcp) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }
    memset(uipcp, 0, sizeof(*uipcp));

    uipcp->ipcp_id = ipcp_id;
    uipcp->ipcm = ipcm;
    list_init(&uipcp->dft);
    list_init(&uipcp->enrolled_neighbors);

    list_add_tail(&uipcp->node, &ipcm->uipcps);

    ret = rina_application_init(&uipcp->appl);
    if (ret) {
        goto err1;
    }

    /* Set the evloop handlers for flow allocation request/response
     * reflected messages. */
    ret = rina_evloop_set_handler(&uipcp->appl.loop,
                                  RINA_KERN_FA_REQ,
                                  uipcp_fa_req);
    if (ret) {
        goto err2;
    }

    ret = rina_evloop_set_handler(&uipcp->appl.loop,
                                  RINA_KERN_FA_RESP,
                                  uipcp_fa_resp);
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

    uipcp->mgmtfd = open_ipcp_mgmt(ipcp_id);
    if (uipcp->mgmtfd < 0) {
        ret = uipcp->mgmtfd;
        goto err2;
    }

    rina_evloop_fdcb_add(&uipcp->appl.loop, uipcp->mgmtfd, mgmt_fd_ready);

    ret = pthread_create(&uipcp->server_th, NULL, uipcp_server, uipcp);
    if (ret) {
        goto err3;
    }

    PD("userspace IPCP %u created\n", ipcp_id);

    return 0;

err3:
    close(uipcp->mgmtfd);
err2:
    rina_application_fini(&uipcp->appl);
err1:
    list_del(&uipcp->node);

    return ret;
}

int
uipcp_del(struct ipcm *ipcm, uint16_t ipcp_id)
{
    struct enrolled_neighbor *neigh;
    struct uipcp *uipcp;
    int ret;

    uipcp = uipcp_lookup(ipcm, ipcp_id);
    if (!uipcp) {
        /* The specified IPCP is a Shim IPCP. */
        return 0;
    }

    /* Unenroll from all the neighbors. */
    list_for_each_entry(neigh, &uipcp->enrolled_neighbors, node) {
        close(neigh->flow_fd);
        rina_name_free(&neigh->ipcp_name);
        // TODO empty the list
    }

    rina_evloop_fdcb_del(&uipcp->appl.loop, uipcp->mgmtfd);

    close(uipcp->mgmtfd);

    evloop_stop(&uipcp->appl.loop);

    ret = rina_application_fini(&uipcp->appl);

    list_del(&uipcp->node);

    free(uipcp);

    if (ret == 0) {
        PD("userspace IPCP %u destroyed\n", ipcp_id);
    }

    return ret;
}

int
uipcps_fetch(struct ipcm *ipcm)
{
    struct uipcp *uipcp;
    int ret;

    list_for_each_entry(uipcp, &ipcm->uipcps, node) {
        ret = ipcps_fetch(&uipcp->appl.loop);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

int
uipcps_update(struct ipcm *ipcm)
{
    struct ipcp *ipcp;
    int ret = 0;

    /* Create an userspace IPCP for each existing IPCP. */
    list_for_each_entry(ipcp, &ipcm->loop.ipcps, node) {
        if (ipcp->dif_type == DIF_TYPE_NORMAL) {
            ret = uipcp_add(ipcm, ipcp->ipcp_id);
            if (ret) {
                return ret;
            }
        }
    }

    /* Perform a fetch operation on the evloops of
     * all the userspace IPCPs. */
    uipcps_fetch(ipcm);

    if (1) {
        /* Read the persistent IPCP registration file into
         * the ipcps_registrations list. */
        FILE *fpreg = fopen(RINA_PERSISTENT_REG_FILE, "r");
        char line[4096];

        if (fpreg) {
            while (fgets(line, sizeof(line), fpreg)) {
                char *s1 = NULL;
                char *s2 = NULL;
                struct rina_name dif_name;
                struct rina_name ipcp_name;
                uint8_t reg_result;

                s1 = strchr(line, '\n');
                if (s1) {
                    *s1 = '\0';
                }

                s1 = strtok(line, " ");
                s2 = strtok(0, " ");

                if (s1 && s2 && rina_name_from_string(s1, &dif_name) == 0
                        && rina_name_from_string(s2, &ipcp_name) == 0) {
                    reg_result = rina_ipcp_register(ipcm, 1, &dif_name,
                                                    &ipcp_name);
                    PI("%s: Automatic re-registration for %s --> %s\n",
                        __func__, s2, (reg_result == 0) ? "DONE" : "FAILED");
                }
            }

            fclose(fpreg);
        }
    }

    return 0;
}

