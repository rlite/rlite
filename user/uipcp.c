#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <rina/rina-utils.h>
#include "ipcm.h"

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

    list_add_tail(&uipcp->node, &ipcm->uipcps);

    ret = rina_application_init(&uipcp->appl);
    if (ret) {
        list_del(&uipcp->node);
        return ret;
    }

    ret = uipcp_evloop_set(uipcp, ipcp_id);
    if (ret) {
        list_del(&uipcp->node);
        rina_application_fini(&uipcp->appl);
    }

    ret = pthread_create(&uipcp->server_th, NULL, uipcp_server, uipcp);
    if (ret) {
        list_del(&uipcp->node);
        rina_application_fini(&uipcp->appl);
    }

    PD("userspace IPCP %u created\n", ipcp_id);

    return 0;
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

