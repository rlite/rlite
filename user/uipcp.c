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

/*static */int
mgmt_write_to_local_port(struct uipcp *uipcp, uint32_t local_port,
                         void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_TYPE_LOCAL_PORT;
    mhdr.u.local_port = local_port;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

/*static */int
mgmt_write_to_dst_addr(struct uipcp *uipcp, uint64_t dst_addr,
                       void *buf, size_t buflen)
{
    struct rina_mgmt_hdr mhdr;

    mhdr.type = RINA_MGMT_HDR_TYPE_DST_ADDR;
    mhdr.u.dst_addr = dst_addr;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

int uipcp_enroll(struct uipcp *uipcp, struct rina_amsg_ipcp_enroll *req)
{
    uint64_t remote_addr, local_addr;
    unsigned int port_id;
    uint8_t cmd;
    int fd = -1;
    int ret;
    ssize_t n;

    /* Allocate a flow for the enrollment. */
    ret = flow_allocate(&uipcp->appl, &req->supp_dif_name, 0,
                         &req->ipcp_name, &req->neigh_ipcp_name,
                         &port_id, 2000);
    if (ret) {
        return -1;
    }

    fd = open_port_ipcp(port_id, uipcp->ipcp_id);
    if (fd < 0) {
        return -1;
    }

    /* Request an enrollment. */
    PD("%s: Enrollment phase (client)\n", __func__);
    cmd = IPCP_MGMT_ENROLL;
    if (write(fd, &cmd, sizeof(cmd)) != 1) {
        PE("%s: write(cmd) failed\n", __func__);
        return -1;
    }

    /* Exchange IPCP addresses. */
    ret = lookup_ipcp_addr_by_id(&uipcp->appl.loop, uipcp->ipcp_id,
                                 &local_addr);
    assert(!ret);
    local_addr = htole64(local_addr);
    n = write(fd, &local_addr, sizeof(local_addr));
    if (n != sizeof(local_addr)) {
        PE("%s: write(localaddr) failed\n", __func__);
        return -1;
    }

    n = read(fd, &remote_addr, sizeof(remote_addr));
    if (n != sizeof(remote_addr)) {
        PE("%s: read(remoteaddr) failed\n", __func__);
        return -1;
    }
    remote_addr = le64toh(remote_addr);

    ipcp_pduft_set(uipcp->ipcm, uipcp->ipcp_id, remote_addr, port_id);

    /* Don't dellocate the flow. */

    return 0;
}

static int
uipcp_server_enroll(struct uipcp *uipcp, unsigned int port_id,  int fd)
{
    uint64_t remote_addr, local_addr;
    ssize_t n;
    int ret;

    /* Do enrollment here. */
    PD("%s: Enrollment phase (server)\n", __func__);

    (void)uipcp;
    (void)fd;

    /* Exchange IPCP addresses. */
    n = read(fd, &remote_addr, sizeof(remote_addr));
    if (n != sizeof(remote_addr)) {
        goto fail;
    }

    remote_addr = le64toh(remote_addr);

    ret = lookup_ipcp_addr_by_id(&uipcp->appl.loop, uipcp->ipcp_id,
                                 &local_addr);
    assert(!ret);
    local_addr = htole64(local_addr);
    n = write(fd, &local_addr, sizeof(local_addr));
    if (n != sizeof(local_addr)) {
        goto fail;
    }

    ipcp_pduft_set(uipcp->ipcm, uipcp->ipcp_id, remote_addr, port_id);

    /* Do not deallocate the flow. */

    return 0;
fail:
    PE("%s: Enrollment failed\n", __func__);

    return -1;
}

static void
mgmt_fd_ready(struct rina_evloop *loop, int fd)
{
    struct application *appl = container_of(loop, struct application, loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    uint8_t cmd;
    int n;

    PD("%s: fd %d ready!\n", __func__, fd);

    assert(fd == uipcp->mgmtfd);

    n = read(fd, &cmd, 1);
    if (n != 1) {
        PE("%s: read(cmd) failed [ret=%d]\n", __func__, n);
        return;
    }

    switch (cmd) {
        case IPCP_MGMT_ENROLL:
            //uipcp_server_enroll(uipcp, port_id, fd);
            break;
        default:
            PI("%s: Unknown cmd %u received\n", __func__, cmd);
            break;
    }

/*
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    int n;

    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        PE("%s: Error: read() failed [%d]\n", __func__, n);
        return;
    }
*/
}

/*static */int
uipcp_flow_allocate_req_arrived(struct uipcp *uipcp, uint32_t remote_port,
                                const struct rina_name *local_application,
                                const struct rina_name *remote_application)
{
    struct rina_kmsg_uipcp_flow_allocate_req_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FLOW_ALLOCATE_REQ_ARRIVED;
    req->ipcp_id = uipcp->ipcp_id;
    req->remote_port = remote_port;
    rina_name_copy(&req->local_application, local_application);
    rina_name_copy(&req->remote_application, remote_application);

    PD("Issuing UIPCP_FLOW_ALLOCATE_REQ_ARRIVED message...\n");

    resp = issue_request(&uipcp->appl.loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

/*static */int
uipcp_flow_allocate_resp_arrived(struct uipcp *uipcp, uint32_t local_port,
                                 uint32_t remote_port, uint8_t response)
{
    struct rina_kmsg_uipcp_flow_allocate_resp_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FLOW_ALLOCATE_RESP_ARRIVED;
    req->ipcp_id = uipcp->ipcp_id;
    req->local_port = local_port;
    req->remote_port = remote_port;
    req->response = response;

    PD("Issuing UIPCP_FLOW_ALLOCATE_RESP_ARRIVED message...\n");

    resp = issue_request(&uipcp->appl.loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
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
    PD("%s: '%s' --> %llu\n", __func__, appl_s,
            (long long unsigned)remote_addr);
    if (appl_s) {
        free(appl_s);
    }

    return 0;
}

static int
uipcp_flow_allocate_req(struct rina_evloop *loop,
                        const struct rina_msg_base_resp *b_resp,
                        const struct rina_msg_base *b_req)
{
    struct application *application = container_of(loop, struct application,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_flow_allocate_req *req =
                (struct rina_kmsg_flow_allocate_req *)b_resp;

    PD("%s: Got reflected message\n", __func__);

    assert(b_req == NULL);
    (void)uipcp;
    (void)req;

    return 0;
}

static int
uipcp_flow_allocate_resp(struct rina_evloop *loop,
                         const struct rina_msg_base_resp *b_resp,
                         const struct rina_msg_base *b_req)
{
    struct application *application = container_of(loop, struct application,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_flow_allocate_resp *resp =
                (struct rina_kmsg_flow_allocate_resp *)b_resp;

    PD("%s: Got reflected message\n", __func__);

    assert(b_req == NULL);
    (void)uipcp;
    (void)resp;

    return 0;
}

void *
uipcp_server(void *arg)
{
    struct uipcp *uipcp = arg;

    for (;;) {
        struct pending_flow_req *pfr;
        unsigned int port_id;
        int result, fd;
        uint8_t cmd;

        pfr = flow_request_wait(&uipcp->appl);
        port_id = pfr->port_id;
        PD("%s: flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
                __func__, pfr->ipcp_id, pfr->port_id);

        result = flow_allocate_resp(&uipcp->appl, pfr->ipcp_id,
                                    pfr->port_id, 0);
        free(pfr);

        if (result) {
            continue;
        }

        fd = open_port_ipcp(port_id, uipcp->ipcp_id);
        if (fd < 0) {
            continue;
        }

        if (read(fd, &cmd, 1) != 1) {
            PE("%s: read(cmd) failed\n", __func__);
            close(fd);
            continue;
        }

        switch (cmd) {
            case IPCP_MGMT_ENROLL:
                uipcp_server_enroll(uipcp, port_id, fd);
                break;
            default:
                PI("%s: Unknown cmd %u received\n", __func__, cmd);
                break;
        }
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

    list_add_tail(&uipcp->node, &ipcm->uipcps);

    ret = rina_application_init(&uipcp->appl);
    if (ret) {
        goto err1;
    }

    /* Set the evloop handlers for flow allocation request/response
     * reflected messages. */
    ret = rina_evloop_set_handler(&uipcp->appl.loop,
                                  RINA_KERN_FLOW_ALLOCATE_REQ,
                                  uipcp_flow_allocate_req);
    if (ret) {
        goto err2;
    }

    ret = rina_evloop_set_handler(&uipcp->appl.loop,
                                  RINA_KERN_FLOW_ALLOCATE_RESP,
                                  uipcp_flow_allocate_resp);
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
    struct uipcp *uipcp;
    int ret;

    uipcp = uipcp_lookup(ipcm, ipcp_id);
    if (!uipcp) {
        /* The specified IPCP is a Shim IPCP. */
        return 0;
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

