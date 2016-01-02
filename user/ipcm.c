#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <assert.h>
#include <endian.h>
#include <rina/rina-kernel-msg.h>
#include <rina/rina-conf-msg.h>
#include <rina/rina-utils.h>

#include "list.h"
#include "helpers.h"
#include "evloop.h"
#include "application.h"
#include "ipcm.h"


struct registered_ipcp {
    struct rina_name dif_name;
    unsigned int ipcp_id;
    struct rina_name ipcp_name;

    struct list_head node;
};

/* Global variable containing the main struct of the IPCM. This variable
 * should be accessed directly only by signal handlers (because I don't know
 * how to do it differently). The rest of the program should access it
 * through pointers.
 */
static struct ipcm gipcm;

/* Empty kernel handlers. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_MSG_MAX] = NULL,
};

static int
rina_conf_response(int sfd, struct rina_msg_base *req,
                   struct rina_msg_base_resp *resp)
{
    resp->msg_type = RINA_CONF_BASE_RESP;
    resp->event_id = req->event_id;

    return rina_msg_write(sfd, RMB(resp));
}

uint8_t
rina_ipcp_register(struct ipcm *ipcm, int reg,
                   const struct rina_name *dif_name,
                   unsigned int ipcp_id,
                   const struct rina_name *ipcp_name)
{
    struct uipcp *uipcp;
    uint8_t result;

    /* Grab the corresponding userspace IPCP. */
    uipcp = uipcp_lookup(ipcm, ipcp_id);
    if (!uipcp) {
        PE("%s: No such uipcp [%u]\n", __func__, ipcp_id);
        return -1;
    }

    /* Perform the registration. */
    result = application_register(&uipcp->appl, reg, dif_name,
                                  0, NULL, ipcp_name);

    if (result == 0) {
        struct registered_ipcp *ripcp;

        if (reg) {
            /* Append a successful registration to the persistent
             * registration list. */
            ripcp = malloc(sizeof(*ripcp));
            if (!ripcp) {
                PE("%s: ripcp allocation failed\n", __func__);
            } else {
                memset(ripcp, 0, sizeof(*ripcp));
                rina_name_copy(&ripcp->dif_name, dif_name);
                ripcp->ipcp_id = ipcp_id;
                rina_name_copy(&ripcp->ipcp_name, ipcp_name);
                list_add_tail(&ripcp->node, &ipcm->ipcps_registrations);
            }
        } else {
            /* Remove a registration element from the persistent
             * registration list. */
            list_for_each_entry(ripcp, &ipcm->ipcps_registrations, node) {
                if (rina_name_cmp(&ripcp->dif_name, dif_name) == 0 &&
                        rina_name_cmp(&ripcp->ipcp_name,
                            ipcp_name) == 0) {
                    list_del(&ripcp->node);
                    free(ripcp);
                    break;
                }
            }
        }
    }

    return result;
}

static int
rina_conf_ipcp_register(struct ipcm *ipcm, int sfd,
                       const struct rina_msg_base *b_req)
{
    struct rina_cmsg_ipcp_register *req = (struct rina_cmsg_ipcp_register *)b_req;
    struct rina_msg_base_resp resp;

    resp.result = rina_ipcp_register(ipcm, req->reg, &req->dif_name,
                                     req->ipcp_id, &req->ipcp_name);

    return rina_conf_response(sfd, RMB(req), &resp);
}

static int
rina_conf_ipcp_enroll(struct ipcm *ipcm, int sfd,
                      const struct rina_msg_base *b_req)
{
    struct rina_cmsg_ipcp_enroll *req = (struct rina_cmsg_ipcp_enroll *)b_req;
    struct rina_msg_base_resp resp;
    struct ipcp *ipcp;
    struct uipcp *uipcp;
    int ret;

    resp.result = 1; /* Report failure by default. */

    ipcp = lookup_ipcp_by_name(&ipcm->loop, &req->ipcp_name);
    if (!ipcp) {
        PE("%s: Could not find enrolling IPC process\n", __func__);
        goto out;
    }

    /* Find the userspace part of the enrolling IPCP. */
    uipcp = uipcp_lookup(ipcm, ipcp->ipcp_id);
    if (!uipcp) {
        PE("%s: Could not find userspace IPC process %u\n",
            __func__, ipcp->ipcp_id);
        goto out;
    }

    /* Perform enrollment in userspace. */
    ret = uipcp_enroll(uipcp, req);
    if (ret) {
        goto out;
    }

    resp.result = 0;

out:
    return rina_conf_response(sfd, RMB(req), &resp);
}

static int
rina_conf_ipcp_dft_set(struct ipcm *ipcm, int sfd,
                       const struct rina_msg_base *b_req)
{
    struct rina_cmsg_ipcp_dft_set *req = (struct rina_cmsg_ipcp_dft_set *)b_req;
    struct rina_msg_base_resp resp;
    struct ipcp *ipcp;
    struct uipcp *uipcp;
    int ret;

    resp.result = 1; /* Report failure by default. */

    ipcp = lookup_ipcp_by_name(&ipcm->loop, &req->ipcp_name);
    if (!ipcp) {
        PE("%s: Could not find IPC process\n", __func__);
        goto out;
    }

    uipcp = uipcp_lookup(ipcm, ipcp->ipcp_id);
    if (!uipcp) {
        PE("%s: Could not find uipcp for IPC process %u\n",
            __func__, ipcp->ipcp_id);
        goto out;
    }

    ret = uipcp_dft_set(uipcp, &req->appl_name, req->remote_addr);
    if (ret) {
        goto out;
    }

    resp.result = 0;

out:
    return rina_conf_response(sfd, RMB(req), &resp);
}

static int
rina_conf_uipcp_update(struct ipcm *ipcm, int sfd,
                       const struct rina_msg_base *b_req)
{
    struct rina_cmsg_uipcp_update *req = (struct rina_cmsg_uipcp_update *)b_req;
    struct rina_msg_base_resp resp;
    struct uipcp *uipcp;

    resp.result = 1; /* Report failure by default. */

    if (req->msg_type == RINA_CONF_UIPCP_CREATE) {
        resp.result = uipcp_add(ipcm, req->ipcp_id);

    } else if (req->msg_type == RINA_CONF_UIPCP_DESTROY) {
        uipcp = uipcp_lookup(ipcm, req->ipcp_id);
        if (!uipcp) {
            PE("%s: Could not find uipcp for IPC process %u\n",
                __func__, req->ipcp_id);
            goto out;
        }

        resp.result = uipcp_del(ipcm, req->ipcp_id);
    }

    ipcps_fetch(&ipcm->loop);
    uipcps_fetch(ipcm);

    resp.result = 0;

out:
    return rina_conf_response(sfd, RMB(req), &resp);
}

typedef int (*rina_req_handler_t)(struct ipcm *ipcm, int sfd,
                                   const struct rina_msg_base * b_req);

/* The table containing all application request handlers. */
static rina_req_handler_t rina_config_handlers[] = {
    [RINA_CONF_IPCP_REGISTER] = rina_conf_ipcp_register,
    [RINA_CONF_IPCP_ENROLL] = rina_conf_ipcp_enroll,
    [RINA_CONF_IPCP_DFT_SET] = rina_conf_ipcp_dft_set,
    [RINA_CONF_UIPCP_CREATE] = rina_conf_uipcp_update,
    [RINA_CONF_UIPCP_DESTROY] = rina_conf_uipcp_update,
    [RINA_CONF_UIPCP_UPDATE] = rina_conf_uipcp_update,
    [RINA_CONF_MSG_MAX] = NULL,
};

/* Unix server thread to manage configuration requests. */
static void *
unix_server(void *arg)
{
    struct ipcm *ipcm = arg;
    char serbuf[4096];
    char msgbuf[4096];

    for (;;) {
        struct sockaddr_un client_address;
        socklen_t client_address_len = sizeof(client_address);
        struct rina_msg_base *req;
        int cfd;
        int ret;
        int n;

        /* Accept a new client. */
        cfd = accept(ipcm->lfd, (struct sockaddr *)&client_address,
                     &client_address_len);

        /* Read the request message in serialized form. */
        n = read(cfd, serbuf, sizeof(serbuf));
        if (n < 0) {
            PE("%s: read() error [%d]\n", __func__, n);
        }

        /* Deserialize into a formatted message. */
        ret = deserialize_rina_msg(rina_conf_numtables, serbuf, n,
                                        msgbuf, sizeof(msgbuf));
        if (ret) {
            PE("%s: deserialization error [%d]\n", __func__, ret);
        }

        /* Lookup the message type. */
        req = RMB(msgbuf);
        if (rina_config_handlers[req->msg_type] == NULL) {
            struct rina_msg_base_resp resp;

            PE("%s: Invalid message received [type=%d]\n", __func__,
                    req->msg_type);
            resp.msg_type = RINA_CONF_BASE_RESP;
            resp.event_id = req->event_id;
            resp.result = 1;
            rina_msg_write(cfd, (struct rina_msg_base *)&resp);
        } else {
            /* Valid message type: handle the request. */
            ret = rina_config_handlers[req->msg_type](ipcm, cfd, req);
            if (ret) {
                PE("%s: Error while handling message type [%d]\n",
                        __func__, req->msg_type);
            }
        }

        /* Close the connection. */
	close(cfd);
    }

    return NULL;
}

/* Dump the ipcps_registrations list to a file, so that
 * subsequent ipcm invocations can redo the registrations. */
static void
persistent_ipcp_reg_dump(struct ipcm *ipcm)
{
    FILE *fpreg = fopen(RINA_PERSISTENT_REG_FILE, "w");

    if (!fpreg) {
        PE("%s: Cannot open persistent register file (%s)\n",
                __func__, RINA_PERSISTENT_REG_FILE);
    } else {
        char *dif_s, *ipcp_s;
        struct registered_ipcp *ripcp;

        list_for_each_entry(ripcp, &ipcm->ipcps_registrations, node) {
            dif_s = rina_name_to_string(&ripcp->dif_name);
            ipcp_s = rina_name_to_string(&ripcp->ipcp_name);
            if (dif_s && ipcp_s) {
                fprintf(fpreg, "%s %u %s\n", dif_s, ripcp->ipcp_id, ipcp_s);
            } else {
                PE("%s: Error in rina_name_to_string()\n", __func__);
            }
            if (dif_s) free(dif_s);
            if (ipcp_s) free(ipcp_s);
        }
        fclose(fpreg);
    }
}

static void
sigint_handler(int signum)
{
    struct ipcm *ipcm = &gipcm;

    persistent_ipcp_reg_dump(ipcm);

    /* TODO Here we should free all the dynamically allocated memory
     * referenced by ipcm. */

    unlink(RINA_IPCM_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

static void
sigpipe_handler(int signum)
{
    PI("SIGPIPE received\n");
}

int main(int argc, char **argv)
{
    struct ipcm *ipcm = &gipcm;
    pthread_t unix_th;
    struct sockaddr_un server_address;
    struct sigaction sa;
    int ret;

    ret = rina_evloop_init(&ipcm->loop, "/dev/rina-ctrl",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

    /* Open a Unix domain socket to listen to. */
    ipcm->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipcm->lfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RINA_IPCM_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    if (unlink(RINA_IPCM_UNIX_NAME) == 0) {
        /* This should not happen if everything behaves correctly.
         * However, if something goes wrong, the Unix domain socket
         * could still exist and so the following bind() would fail.
         * This unlink() will clean up in this situation. */
        PI("info: cleaned up existing unix domain socket\n");
    }
    ret = bind(ipcm->lfd, (struct sockaddr *)&server_address,
                sizeof(server_address));
    if (ret) {
        perror("bind(AF_UNIX, path)");
        exit(EXIT_FAILURE);
    }
    ret = listen(ipcm->lfd, 50);
    if (ret) {
        perror("listen(AF_UNIX)");
        exit(EXIT_FAILURE);
    }

    list_init(&ipcm->uipcps);
    list_init(&ipcm->ipcps_registrations);

    /* Set an handler for SIGINT and SIGTERM so that we can remove
     * the Unix domain socket used to access the IPCM server. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        exit(EXIT_FAILURE);
    }

    /* Handle the SIGPIPE signal, which is received when
     * trying to read/write from/to a Unix domain socket
     * that has been closed by the other end. */
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGPIPE, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGPIPE)");
        exit(EXIT_FAILURE);
    }

    /* Fetch kernel state and create userspace IPCPs as needed. This
     * must be done before launching the unix server in order to
     * avoid race conditions between main thread fetching and unix
     * server thread serving a client. That is, a client could see
     * incomplete state and its operation may fail or behave
     * unexpectedly.*/
    ipcps_fetch(&ipcm->loop);
    ret = uipcps_update(ipcm);
    if (ret) {
        PE("Failed to load userspace ipcps\n");
        exit(EXIT_FAILURE);
    }

    /* Create and start the unix server thread. */
    ret = pthread_create(&unix_th, NULL, unix_server, ipcm);
    if (ret) {
        perror("pthread_create(unix)");
        exit(EXIT_FAILURE);
    }

    /* The following code should be never reached, since the unix
     * socket server should execute until a SIGINT signal comes. */
    ret = pthread_join(unix_th, NULL);
    if (ret < 0) {
        perror("pthread_join(unix)");
        exit(EXIT_FAILURE);
    }

    rina_evloop_fini(&ipcm->loop);

    return 0;
}
