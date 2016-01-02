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
#include <sys/stat.h>
#include <pthread.h>

#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"
#include "rlite/list.h"
#include "rlite/evloop.h"
#include "rlite/evloop.h"

#include "../helpers.h"
#include "uipcp-container.h"


struct registered_ipcp {
    char *dif_name;
    unsigned int ipcp_id;
    struct rina_name ipcp_name;

    struct list_head node;
};

/* Global variable containing the main struct of the uipcps. This variable
 * should be accessed directly only by signal handlers (because I don't know
 * how to do it differently). The rest of the program should access it
 * through pointers.
 */
static struct uipcps guipcps;

static int
rlite_conf_response(int sfd, struct rlite_msg_base *req,
                   struct rlite_msg_base_resp *resp)
{
    resp->msg_type = RLITE_CFG_BASE_RESP;
    resp->event_id = req->event_id;

    return rlite_msg_write_fd(sfd, RLITE_MB(resp));
}

static void
track_ipcp_registration(struct uipcps *uipcps, int reg,
                        const char *dif_name,
                        unsigned int ipcp_id,
                        const struct rina_name *ipcp_name)
{
    struct registered_ipcp *ripcp;

    if (reg) {
        int found = 0;

        /* Append a successful registration to the persistent
         * registration list. */
        list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
            if (strcmp(ripcp->dif_name, dif_name) == 0 &&
                    rina_name_cmp(&ripcp->ipcp_name, ipcp_name) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            ripcp = malloc(sizeof(*ripcp));
            if (!ripcp) {
                PE("ripcp allocation failed\n");
            } else {
                memset(ripcp, 0, sizeof(*ripcp));
                ripcp->dif_name = strdup(dif_name);
                ripcp->ipcp_id = ipcp_id;
                rina_name_copy(&ripcp->ipcp_name, ipcp_name);
                list_add_tail(&ripcp->node, &uipcps->ipcps_registrations);
            }
        }
    } else {
        /* Try to remove a registration element from the persistent
         * registration list. If 'dif_name' and 'ipcp_name' are specified,
         * match the corresponding tuple fields. Otherwise match the
         * by IPCP id. */
        list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
            if ((dif_name && ipcp_name &&
                    strcmp(ripcp->dif_name, dif_name) == 0 &&
                    rina_name_cmp(&ripcp->ipcp_name, ipcp_name) == 0) ||
                    (!dif_name && !ipcp_name && ripcp->ipcp_id == ipcp_id)) {
                list_del(&ripcp->node);
                free(ripcp->dif_name);
                rina_name_free(&ripcp->ipcp_name);
                free(ripcp);
                break;
            }
        }
    }
}

static uint8_t
rlite_ipcp_register(struct uipcps *uipcps, int reg,
                    const char *dif_name,
                    unsigned int ipcp_id,
                    const struct rina_name *ipcp_name)
{
    struct uipcp *uipcp;
    uint8_t result = RLITE_ERR;

    /* Grab the corresponding userspace IPCP. */
    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        PE("No such uipcp [%u]\n", ipcp_id);
        pthread_mutex_unlock(&uipcps->lock);
        return -1;
    }

    if (uipcp->ops.register_to_lower) {
        result = uipcp->ops.register_to_lower(uipcp, reg, dif_name, ipcp_id,
                                              ipcp_name);

        if (result == RLITE_SUCC) {
            /* Track the (un)registration in the persistent registration
             * list. */
            track_ipcp_registration(uipcps, reg, dif_name, ipcp_id, ipcp_name);
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    return result;
}

static int
rlite_conf_ipcp_register(struct uipcps *uipcps, int sfd,
                        const struct rlite_msg_base *b_req)
{
    struct rl_cmsg_ipcp_register *req = (struct rl_cmsg_ipcp_register *)b_req;
    struct rlite_msg_base_resp resp;

    resp.result = rlite_ipcp_register(uipcps, req->reg, req->dif_name,
                                     req->ipcp_id, &req->ipcp_name);

    return rlite_conf_response(sfd, RLITE_MB(req), &resp);
}

static int
rlite_conf_ipcp_enroll(struct uipcps *uipcps, int sfd,
                      const struct rlite_msg_base *b_req)
{
    struct rl_cmsg_ipcp_enroll *req = (struct rl_cmsg_ipcp_enroll *)b_req;
    struct rlite_msg_base_resp resp;
    struct uipcp *uipcp;

    resp.result = RLITE_ERR; /* Report failure by default. */

    /* Find the userspace part of the enrolling IPCP. */
    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, req->ipcp_id);
    if (!uipcp) {
        PE("Could not find userspace IPC process %u\n",
            req->ipcp_id);
        goto out;
    }

    if (uipcp->ops.enroll) {
        resp.result = uipcp->ops.enroll(uipcp, req);
    }

out:
    pthread_mutex_unlock(&uipcps->lock);

    return rlite_conf_response(sfd, RLITE_MB(req), &resp);
}

static int
rlite_conf_ipcp_dft_set(struct uipcps *uipcps, int sfd,
                       const struct rlite_msg_base *b_req)
{
    struct rl_cmsg_ipcp_dft_set *req = (struct rl_cmsg_ipcp_dft_set *)b_req;
    struct rlite_msg_base_resp resp;
    struct uipcp *uipcp;

    resp.result = RLITE_ERR; /* Report failure by default. */

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, req->ipcp_id);
    if (!uipcp) {
        PE("Could not find uipcp for IPC process %u\n",
            req->ipcp_id);
        goto out;
    }

    if (uipcp->ops.dft_set) {
        resp.result = uipcp->ops.dft_set(uipcp, req);
    }

out:
    pthread_mutex_unlock(&uipcps->lock);

    return rlite_conf_response(sfd, RLITE_MB(req), &resp);
}

static int
rlite_conf_ipcp_rib_show(struct uipcps *uipcps, int sfd,
                        const struct rlite_msg_base *b_req)
{
    struct rl_cmsg_ipcp_rib_show_req *req =
                    (struct rl_cmsg_ipcp_rib_show_req *)b_req;
    struct rl_cmsg_ipcp_rib_show_resp resp;
    struct uipcp *uipcp;
    int ret;

    resp.result = RLITE_ERR; /* Report failure by default. */
    resp.dump = NULL;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, req->ipcp_id);
    if (!uipcp) {
        PE("Could not find uipcp for IPC process %u\n",
            req->ipcp_id);
        goto out;
    }

    if (uipcp->ops.rib_show) {
        resp.dump = uipcp->ops.rib_show(uipcp);
        if (resp.dump) {
            resp.result = RLITE_SUCC;
        }
    }

out:
    pthread_mutex_unlock(&uipcps->lock);

    resp.msg_type = RLITE_CFG_IPCP_RIB_SHOW_RESP;
    resp.event_id = req->event_id;

    ret = rlite_msg_write_fd(sfd, RLITE_MB(&resp));

    if (resp.dump) {
        free(resp.dump);
    }

    return ret;
}

typedef int (*rlite_req_handler_t)(struct uipcps *uipcps, int sfd,
                                   const struct rlite_msg_base * b_req);

/* The table containing all application request handlers. */
static rlite_req_handler_t rlite_config_handlers[] = {
    [RLITE_CFG_IPCP_REGISTER] = rlite_conf_ipcp_register,
    [RLITE_CFG_IPCP_ENROLL] = rlite_conf_ipcp_enroll,
    [RLITE_CFG_IPCP_DFT_SET] = rlite_conf_ipcp_dft_set,
    [RLITE_CFG_IPCP_RIB_SHOW_REQ] = rlite_conf_ipcp_rib_show,
    [RLITE_CFG_MSG_MAX] = NULL,
};

/* Unix server thread to manage configuration requests. */
static int
unix_server(struct uipcps *uipcps)
{
    char serbuf[4096];
    char msgbuf[4096];

    for (;;) {
        struct sockaddr_un client_address;
        socklen_t client_address_len = sizeof(client_address);
        struct rlite_msg_base *req;
        int cfd;
        int ret;
        int n;

        /* Accept a new client. */
        cfd = accept(uipcps->lfd, (struct sockaddr *)&client_address,
                     &client_address_len);

        /* Read the request message in serialized form. */
        n = read(cfd, serbuf, sizeof(serbuf));
        if (n < 0) {
            PE("read() error [%d]\n", n);
        }

        /* Deserialize into a formatted message. */
        ret = deserialize_rlite_msg(rlite_conf_numtables, RLITE_CFG_MSG_MAX,
                                   serbuf, n, msgbuf, sizeof(msgbuf));
        if (ret) {
            PE("deserialization error [%d]\n", ret);
        }

        /* Lookup the message type. */
        req = RLITE_MB(msgbuf);
        if (rlite_config_handlers[req->msg_type] == NULL) {
            struct rlite_msg_base_resp resp;

            PE("Invalid message received [type=%d]\n",
                    req->msg_type);
            resp.msg_type = RLITE_CFG_BASE_RESP;
            resp.event_id = req->event_id;
            resp.result = RLITE_ERR;
            rlite_msg_write_fd(cfd, RLITE_MB(&resp));
        } else {
            /* Valid message type: handle the request. */
            ret = rlite_config_handlers[req->msg_type](uipcps, cfd, req);
            if (ret) {
                PE("Error while handling message type [%d]\n",
                        req->msg_type);
            }
        }

        rlite_msg_free(rlite_conf_numtables, RLITE_CFG_MSG_MAX, req);

        /* Close the connection. */
	close(cfd);
    }

    return 0;
}

/* Dump the ipcps_registrations list to a file, so that
 * subsequent uipcps invocations can redo the registrations. */
static void
persistent_ipcp_reg_dump(struct uipcps *uipcps)
{
    FILE *fpreg = fopen(RLITE_PERSISTENT_REG_FILE, "w");

    if (!fpreg) {
        PE("Cannot open persistent register file (%s)\n",
                RLITE_PERSISTENT_REG_FILE);
    } else {
        char *ipcp_s;
        struct registered_ipcp *ripcp;

        list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
            ipcp_s = rina_name_to_string(&ripcp->ipcp_name);
            if (ipcp_s) {
                fprintf(fpreg, "REG %s %u %s\n", ripcp->dif_name, ripcp->ipcp_id, ipcp_s);
            } else {
                PE("Error in rina_name_to_string()\n");
            }
            if (ipcp_s) free(ipcp_s);
        }
        fclose(fpreg);
    }
}

static int
uipcps_ipcp_update(struct rlite_evloop *loop,
                   const struct rlite_msg_base *b_resp,
                   const struct rlite_msg_base *b_req)
{
    struct uipcps *uipcps = container_of(loop, struct uipcps, loop);
    struct rl_kmsg_ipcp_update *upd = (struct rl_kmsg_ipcp_update *)b_resp;
    struct uipcp *uipcp;
    int ret = -1;

    pthread_mutex_lock(&uipcps->lock);

    switch (upd->update_type) {
        case RLITE_UPDATE_ADD:
            if (upd->dif_type && type_has_uipcp(upd->dif_type)) {
                /* We only care about IPCP with userspace implementation. */
                ret = uipcp_add(uipcps, upd->ipcp_id, upd->dif_type);
            }
            break;

        case RLITE_UPDATE_DEL:
            uipcp = uipcp_lookup(uipcps, upd->ipcp_id);
            if (uipcp) {
                /* Track all the unregistrations of the destroyed IPCP in
                 * the persistent registrations list. */
                track_ipcp_registration(uipcps, 0, NULL, upd->ipcp_id, NULL);
                ret = uipcp_del(uipcps, upd->ipcp_id);

            } else {
                /* This is an IPCP with no userspace implementation. */
                ret = 0;
            }
            break;

        default:
            ret = 0;
            break;
    }

    pthread_mutex_unlock(&uipcps->lock);

    if (ret) {
        PE("IPCP update synchronization failed\n");
    }

    uipcps_print(uipcps);

    return 0;
}

static int
uipcps_update(struct uipcps *uipcps)
{
    struct rlite_ipcp *rlite_ipcp;
    int ret = 0;

    ret = rl_evloop_init(&uipcps->loop, "/dev/rlite", NULL, 0);
    if (ret) {
        return ret;
    }

    rl_evloop_set_handler(&uipcps->loop, RLITE_KER_IPCP_UPDATE,
                          uipcps_ipcp_update);

    rl_ctrl_ipcps_print(&uipcps->loop.ctrl);

    /* Create an userspace IPCP for each existing IPCP. */
    pthread_mutex_lock(&uipcps->loop.lock);
    list_for_each_entry(rlite_ipcp, &uipcps->loop.ctrl.ipcps, node) {
        if (type_has_uipcp(rlite_ipcp->dif_type)) {
            ret = uipcp_add(uipcps, rlite_ipcp->ipcp_id,
                            rlite_ipcp->dif_type);
            if (ret) {
                pthread_mutex_unlock(&uipcps->loop.lock);
                return ret;
            }
        }
    }
    pthread_mutex_unlock(&uipcps->loop.lock);

    uipcps_print(uipcps);

    if (1) {
        /* Read the persistent IPCP registration file into
         * the ipcps_registrations list. */
        FILE *fpreg = fopen(RLITE_PERSISTENT_REG_FILE, "r");
        char line[4096];

        if (fpreg) {
            PD("Persistence file %s opened\n", RLITE_PERSISTENT_REG_FILE);
            while (fgets(line, sizeof(line), fpreg)) {
                char *s0 = NULL;
                char *s1 = NULL;
                char *s2 = NULL;
                char *s3 = NULL;
                struct rina_name ipcp_name;
                unsigned int ipcp_id;
                uint8_t reg_result;

                s0 = strchr(line, '\n');
                if (s0) {
                    *s0 = '\0';
                }

                s0 = strtok(line, " ");
                s1 = strtok(0, " ");
                s2 = strtok(0, " ");
                s3 = strtok(0, " ");

                if (strncmp(s0, "REG", 3) == 0) {
                    if (s1 && s2 && s3
                            && rina_name_from_string(s3, &ipcp_name) == 0) {
                        ipcp_id = atoi(s2);
                        reg_result = rlite_ipcp_register(uipcps, 1, s3,
                                                         ipcp_id, &ipcp_name);
                        PI("Automatic re-registration for %s --> %s\n",
                                s3, (reg_result == 0) ? "DONE" : "FAILED");
                    }

                } else if (strncmp(s0, "ENR", 3) == 0) {
                }
            }

            fclose(fpreg);

        } else {
            PD("Persistence file %s not found\n", RLITE_PERSISTENT_REG_FILE);
        }
    }

    return 0;
}

static void
sigint_handler(int signum)
{
    struct uipcps *uipcps = &guipcps;

    persistent_ipcp_reg_dump(uipcps);

    /* TODO Here we should free all the dynamically allocated memory
     * referenced by uipcps. */

    unlink(RLITE_UIPCPS_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    struct uipcps *uipcps = &guipcps;
    struct sockaddr_un server_address;
    struct sigaction sa;
    int ret;

    /* We require root permissions. */
    if (geteuid() != 0) {
        PE("uipcps daemon needs root permissions\n");
        return -1;
    }

    /* Open a Unix domain socket to listen to. */
    uipcps->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (uipcps->lfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RLITE_UIPCPS_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    if (unlink(RLITE_UIPCPS_UNIX_NAME) == 0) {
        /* This should not happen if everything behaves correctly.
         * However, if something goes wrong, the Unix domain socket
         * could still exist and so the following bind() would fail.
         * This unlink() will clean up in this situation. */
        PI("Cleaned up existing unix domain socket\n");
    }
    ret = bind(uipcps->lfd, (struct sockaddr *)&server_address,
                sizeof(server_address));
    if (ret) {
        perror("bind(AF_UNIX, path)");
        exit(EXIT_FAILURE);
    }
    ret = listen(uipcps->lfd, 50);
    if (ret) {
        perror("listen(AF_UNIX)");
        exit(EXIT_FAILURE);
    }

    /* Change permissions to rlite control and I/O device and uipcp
     * Unix socket, so that anyone can read and write. This
     * a temporary solution, to be used until a precise
     * permission scheme is designed. */
    if (chmod("/dev/rlite", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                            | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/dev/rlite) failed\n");
    }

    if (chmod("/dev/rlite-io", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                               | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/dev/rlite-io) failed\n");
    }

    if (chmod(RLITE_UIPCPS_UNIX_NAME, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                                     | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/var/rlite/uipcp-server) failed\n");
    }

    list_init(&uipcps->uipcps);
    pthread_mutex_init(&uipcps->lock, NULL);
    list_init(&uipcps->ipcps_registrations);
    list_init(&uipcps->ipcp_nodes);

    /* Set an handler for SIGINT and SIGTERM so that we can remove
     * the Unix domain socket used to access the uipcp server. */
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
    ret = sigaction(SIGSEGV, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    /* Handle the SIGPIPE signal, which is received when
     * trying to read/write from/to a Unix domain socket
     * that has been closed by the other end. */
    ret = sigaction(SIGPIPE, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGPIPE)");
        exit(EXIT_FAILURE);
    }

    /* Init main evloop and create userspace IPCPs as needed. This
     * must be done before launching the unix server in order to
     * avoid race conditions between main thread fetching and unix
     * server thread serving a client. That is, a client could see
     * incomplete state and its operation may fail or behave
     * unexpectedly.*/
    ret = uipcps_update(uipcps);
    if (ret) {
        PE("Failed to load userspace ipcps\n");
        exit(EXIT_FAILURE);
    }

    /* Start the unix server. */
    unix_server(uipcps);

    /* The following code should be never reached, since the unix
     * socket server should execute until a SIGINT signal comes. */

    return 0;
}
