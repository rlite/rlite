/*
 * Unix server for uipcps daemon.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#define _GNU_SOURCE
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
#include "rlite/uipcps-msg.h"
#include "rlite/utils.h"
#include "rlite/list.h"
#include "rlite/evloop.h"
#include "rlite/evloop.h"

#include "../helpers.h"
#include "uipcp-container.h"


const char *ctrl_dev_name = "/dev/rlite";
const char *io_dev_name = "/dev/rlite-io";

struct registered_ipcp {
    rl_ipcp_id_t id;
    struct rina_name name;
    char *dif_name;

    struct list_head node;
};


/* Global variable containing the main struct of the uipcps. This variable
 * should be accessed directly only by signal handlers (because I don't know
 * how to do it differently). The rest of the program should access it
 * through pointers.
 */
static struct uipcps guipcps;

static int
rl_u_response(int sfd, struct rl_msg_base *req,
                   struct rl_msg_base_resp *resp)
{
    resp->msg_type = RLITE_U_BASE_RESP;
    resp->event_id = req->event_id;

    return rl_msg_write_fd(sfd, RLITE_MB(resp));
}

static void
track_ipcp_registration(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id,
                        const struct rl_cmsg_ipcp_register *req)
{
    struct registered_ipcp *ripcp;

    /* Append a successful registration to the persistent
     * registration list. */
    list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
        if (strcmp(ripcp->dif_name, req->dif_name) == 0 &&
                rina_name_cmp(&ripcp->name, &req->ipcp_name) == 0) {
            return;
        }
    }

    ripcp = malloc(sizeof(*ripcp));
    if (!ripcp) {
        PE("ripcp allocation failed\n");
        return;
    }

    memset(ripcp, 0, sizeof(*ripcp));
    ripcp->dif_name = strdup(req->dif_name);
    ripcp->id = ipcp_id;
    rina_name_copy(&ripcp->name, &req->ipcp_name);
    list_add_tail(&ripcp->node, &uipcps->ipcps_registrations);
}

static void
track_ipcp_unregistration(struct uipcps *uipcps,
                          rl_ipcp_id_t ipcp_id)
{
    struct registered_ipcp *ripcp;

    /* Try to remove a registration element from the persistent
     * registration list, matching by IPCP id. */
    list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
        if (ripcp->id == ipcp_id) {
            list_del(&ripcp->node);
            free(ripcp->dif_name);
            rina_name_free(&ripcp->name);
            free(ripcp);
            break;
        }
    }
}

static int
ipcp_register(struct uipcps *uipcps,
              const struct rl_cmsg_ipcp_register *req)
{
    struct uipcp *uipcp;
    int result = RLITE_ERR;

    /* Grab the corresponding userspace IPCP. */
    uipcp = uipcp_get_by_name(uipcps, &req->ipcp_name);
    if (!uipcp) {
        return -1;
    }

    if (uipcp->ops.register_to_lower) {
        result = uipcp->ops.register_to_lower(uipcp, req);

        if (result == RLITE_SUCC) {
            /* Track the (un)registration in the persistent registration
             * list. */
            if (req->reg) {
                track_ipcp_registration(uipcps, uipcp->id, req);
            } else {
                track_ipcp_unregistration(uipcps, uipcp->id);
            }
        }
    }

    uipcp_put(uipcps, uipcp->id);

    return result;
}

static int
rl_u_ipcp_register(struct uipcps *uipcps, int sfd,
                        const struct rl_msg_base *b_req)
{
    struct rl_cmsg_ipcp_register *req = (struct rl_cmsg_ipcp_register *)b_req;
    struct rl_msg_base_resp resp;

    resp.result = ipcp_register(uipcps, req);

    return rl_u_response(sfd, RLITE_MB(req), &resp);
}

static int
ipcp_enroll(struct uipcps *uipcps, const struct rl_cmsg_ipcp_enroll *req)
{
    int ret = RLITE_ERR; /* Report failure by default. */
    struct uipcp *uipcp;

    /* Find the userspace part of the enrolling IPCP. */
    uipcp = uipcp_get_by_name(uipcps, &req->ipcp_name);
    if (uipcp && uipcp->ops.enroll) {
        ret = uipcp->ops.enroll(uipcp, req, 1);
    }

    uipcp_put(uipcps, uipcp->id);

    return ret;
}

static int
rl_u_ipcp_enroll(struct uipcps *uipcps, int sfd,
                       const struct rl_msg_base *b_req)
{
    struct rl_cmsg_ipcp_enroll *req = (struct rl_cmsg_ipcp_enroll *)b_req;
    struct rl_msg_base_resp resp;

    resp.result = ipcp_enroll(uipcps, req);

    return rl_u_response(sfd, RLITE_MB(req), &resp);
}

static int
rl_u_ipcp_dft_set(struct uipcps *uipcps, int sfd,
                       const struct rl_msg_base *b_req)
{
    struct rl_cmsg_ipcp_dft_set *req = (struct rl_cmsg_ipcp_dft_set *)b_req;
    struct rl_msg_base_resp resp;
    struct uipcp *uipcp;

    resp.result = RLITE_ERR; /* Report failure by default. */

    uipcp = uipcp_get_by_name(uipcps, &req->ipcp_name);
    if (!uipcp) {
        goto out;
    }

    if (uipcp->ops.dft_set) {
        resp.result = uipcp->ops.dft_set(uipcp, req);
    }

    uipcp_put(uipcps, uipcp->id);

out:
    return rl_u_response(sfd, RLITE_MB(req), &resp);
}

static int
rl_u_ipcp_rib_show(struct uipcps *uipcps, int sfd,
                        const struct rl_msg_base *b_req)
{
    struct rl_cmsg_ipcp_rib_show_req *req =
                    (struct rl_cmsg_ipcp_rib_show_req *)b_req;
    struct rl_cmsg_ipcp_rib_show_resp resp;
    struct uipcp *uipcp;
    char *dumpstr = NULL;
    int ret;

    resp.result = RLITE_ERR; /* Report failure by default. */
    resp.dump.buf = NULL;
    resp.dump.len = 0;

    uipcp = uipcp_get_by_name(uipcps, &req->ipcp_name);
    if (!uipcp) {
        goto out;
    }

    if (uipcp->ops.rib_show) {
        dumpstr = uipcp->ops.rib_show(uipcp);
        if (dumpstr) {
            resp.result = RLITE_SUCC;
            resp.dump.buf = dumpstr;
            resp.dump.len = strlen(dumpstr) + 1; /* include terminator */
        }
    }

    uipcp_put(uipcps, uipcp->id);

out:
    resp.msg_type = RLITE_U_IPCP_RIB_SHOW_RESP;
    resp.event_id = req->event_id;

    ret = rl_msg_write_fd(sfd, RLITE_MB(&resp));

    if (dumpstr) {
        free(dumpstr);
    }

    return ret;
}

typedef int (*rl_req_handler_t)(struct uipcps *uipcps, int sfd,
                                   const struct rl_msg_base * b_req);

/* The table containing all application request handlers. */
static rl_req_handler_t rl_config_handlers[] = {
    [RLITE_U_IPCP_REGISTER] = rl_u_ipcp_register,
    [RLITE_U_IPCP_ENROLL] = rl_u_ipcp_enroll,
    [RLITE_U_IPCP_DFT_SET] = rl_u_ipcp_dft_set,
    [RLITE_U_IPCP_RIB_SHOW_REQ] = rl_u_ipcp_rib_show,
    [RLITE_U_MSG_MAX] = NULL,
};

struct worker_info {
    pthread_t           th;
    struct uipcps       *uipcps;
    int                 cfd;
    struct list_head    node;
};

static void *
worker_fn(void *opaque)
{
    struct worker_info *wi = opaque;
    struct rl_msg_base *req;
    char serbuf[4096];
    char msgbuf[4096];
    int ret;
    int n;

    PV("Worker %p started\n", wi);

    /* Read the request message in serialized form. */
    n = read(wi->cfd, serbuf, sizeof(serbuf));
    if (n < 0) {
        PE("read() error [%d]\n", n);
    }

    /* Deserialize into a formatted message. */
    ret = deserialize_rlite_msg(rl_uipcps_numtables, RLITE_U_MSG_MAX,
            serbuf, n, msgbuf, sizeof(msgbuf));
    if (ret) {
        PE("deserialization error [%d]\n", ret);
    }

    /* Lookup the message type. */
    req = RLITE_MB(msgbuf);
    if (rl_config_handlers[req->msg_type] == NULL) {
        struct rl_msg_base_resp resp;

        PE("Invalid message received [type=%d]\n",
                req->msg_type);
        resp.msg_type = RLITE_U_BASE_RESP;
        resp.event_id = req->event_id;
        resp.result = RLITE_ERR;
        rl_msg_write_fd(wi->cfd, RLITE_MB(&resp));
    } else {
        /* Valid message type: handle the request. */
        ret = rl_config_handlers[req->msg_type](wi->uipcps, wi->cfd, req);
        if (ret) {
            PE("Error while handling message type [%d]\n",
                    req->msg_type);
        }
    }

    rl_msg_free(rl_uipcps_numtables, RLITE_U_MSG_MAX, req);

    /* Close the connection. */
    close(wi->cfd);

    PV("Worker %p stopped\n", wi);

    return NULL;
}

/* Unix server thread to manage configuration requests. */
static int
unix_server(struct uipcps *uipcps)
{
    struct list_head threads;
    int threads_cnt = 0;
#define RL_MAX_THREADS     16

    list_init(&threads);

    for (;;) {
        struct sockaddr_un client_address;
        socklen_t client_address_len = sizeof(client_address);
        struct worker_info *wi, *tmp;
        int ret;

        for (;;) {
            /* Try to clean up previously terminated worker threads. */
            list_for_each_entry_safe(wi, tmp, &threads, node) {
                ret = pthread_tryjoin_np(wi->th, NULL);
                if (ret == EBUSY) {
                    /* Skip this since it has not finished yet. */
                    continue;
                } else if (ret) {
                    PE("pthread_tryjoin_np() failed: %d\n", ret);
                }

                PV("Worker %p cleaned-up\n", wi);
                list_del(&wi->node);
                free(wi);
                threads_cnt --;
            }

            if (threads_cnt < RL_MAX_THREADS) {
                /* We have not reached the maximum, let's go ahead. */
                break;
            }

            /* Too many threads, let's wait a bit and try again to free up
             * resources. */
            PD("Too many active threads, wait to free up some\n");
            usleep(50000);
        }

        wi = malloc(sizeof(*wi));
        wi->uipcps = uipcps;

        /* Accept a new client and create a thread to serve it. */
        wi->cfd = accept(uipcps->lfd, (struct sockaddr *)&client_address,
                         &client_address_len);

        ret = pthread_create(&wi->th, NULL, worker_fn, wi);
        if (ret) {
            PE("pthread_create() failed [%d]\n", errno);
            close(wi->cfd);
            free(wi);
        }

        list_add_tail(&wi->node, &threads);
        threads_cnt ++;
    }

    return 0;
#undef RL_MAX_THREADS
}

static int
uipcps_ipcp_update(struct rl_evloop *loop,
                   const struct rl_msg_base *b_resp,
                   const struct rl_msg_base *b_req)
{
    struct uipcps *uipcps = container_of(loop, struct uipcps, loop);
    struct rl_kmsg_ipcp_update *upd = (struct rl_kmsg_ipcp_update *)b_resp;
    int ret = 0;

    switch (upd->update_type) {
        case RLITE_UPDATE_ADD:
        case RLITE_UPDATE_UPD:
            if (!upd->dif_type || !upd->dif_name ||
                    !rina_name_valid(&upd->ipcp_name)) {
                PE("Invalid ipcp update\n");
                return -1;
            }
        break;
    }

    switch (upd->update_type) {
        case RLITE_UPDATE_ADD:
            ret = uipcp_add(uipcps, upd);
            break;

        case RLITE_UPDATE_DEL:
            /* Track all the unregistrations of the destroyed IPCP in
             * the persistent registrations list.
             * This can be an IPCP with no userspace implementation. */
            track_ipcp_unregistration(uipcps, upd->ipcp_id);
            ret = uipcp_put(uipcps, upd->ipcp_id);
            break;

        case RLITE_UPDATE_UPD:
            ret = uipcp_update(uipcps, upd);
            break;
    }

    if (ret) {
        PE("IPCP update synchronization failed\n");
    }
#if 0
    uipcps_print(uipcps);
#endif
    return 0;
}

static void
process_persistence_file(struct uipcps *uipcps)
{
    /* Read the persistent IPCP registration file into
     * the ipcps_registrations list. */
    FILE *fpreg = fopen(RLITE_PERSISTENCE_FILE, "r");
    char line[4096];

    if (!fpreg) {
        PD("Persistence file %s not found\n", RLITE_PERSISTENCE_FILE);
        return;
    }

    PD("Persistence file %s opened\n", RLITE_PERSISTENCE_FILE);

    while (fgets(line, sizeof(line), fpreg)) {
        char *s0 = NULL;
        char *s1 = NULL;
        char *s2 = NULL;
        char *s3 = NULL;
        char *s4 = NULL;

        s0 = strchr(line, '\n');
        if (s0) {
            *s0 = '\0';
        }

        s0 = strtok(line, " ");
        s1 = strtok(0, " ");
        s2 = strtok(0, " ");
        s3 = strtok(0, " ");
        s4 = strtok(0, " ");

        if (strncmp(s0, "REG", 3) == 0) {
            /* Redo an ipcp registration. */
            struct rl_cmsg_ipcp_register msg;
            int ret = 0;

            if (!s1 || !s2) {
                PE("Invalid REG line");
                continue;
            }

            msg.reg = 1;
            ret |= rina_name_from_string(s2, &msg.ipcp_name);
            msg.dif_name = strdup(s1);
            if (ret || !msg.dif_name) {
                PE("Out of memory\n");
                rl_msg_free(rl_uipcps_numtables, RLITE_U_MSG_MAX,
                               RLITE_MB(&msg));
                continue;
            }

            ret = ipcp_register(uipcps, &msg);
            PI("Automatic re-registration for %s --> %s\n",
                    s2, (ret == RLITE_SUCC) ? "DONE" : "FAILED");
            rl_msg_free(rl_uipcps_numtables, RLITE_U_MSG_MAX,
                           RLITE_MB(&msg));

        } else if (strncmp(s0, "ENR", 3) == 0) {
            /* Redo an enrollment. */
            struct rl_cmsg_ipcp_enroll msg;
            int ret = 0;

            if (!s1 || !s2 || !s3 || !s4) {
                PE("Invalid ENR line");
                continue;
            }

            ret |= rina_name_from_string(s2, &msg.ipcp_name);
            ret |= rina_name_from_string(s3, &msg.neigh_name);
            msg.dif_name = strdup(s1);
            msg.supp_dif_name = strdup(s4);
            if (ret || !msg.dif_name || !msg.supp_dif_name) {
                PE("Out of memory\n");
                rl_msg_free(rl_uipcps_numtables, RLITE_U_MSG_MAX,
                               RLITE_MB(&msg));
                continue;
            }

            ret = ipcp_enroll(uipcps, &msg);
            PI("Automatic re-enrollment for %s in DIF %s --> %s\n", s2, s1,
               (ret == RLITE_SUCC) ? "DONE" : "FAILED");
            rl_msg_free(rl_uipcps_numtables, RLITE_U_MSG_MAX,
                           RLITE_MB(&msg));
        }
    }

    fclose(fpreg);
}

static int
uipcps_init(struct uipcps *uipcps)
{
    rl_resp_handler_t handlers[RLITE_KER_MSG_MAX+1];
    int ret = 0;

    memset(handlers, 0, sizeof(handlers));
    handlers[RLITE_KER_IPCP_UPDATE] = uipcps_ipcp_update;

    /* The main control loop will take care of IPCP updates, to
     * align userspace IPCPs with kernelspace ones. */
    ret = rl_evloop_init(&uipcps->loop, ctrl_dev_name, handlers, RL_F_IPCPS);
    if (ret) {
        return ret;
    }

    /* At this point an userspace IPCP for each existing IPCP has been
     * created. */
#if 0
    uipcps_print(uipcps);
#endif
    process_persistence_file(uipcps);

    return 0;
}

static void
dump_persistence_file(struct uipcps *uipcps)
{
    FILE *fpreg = fopen(RLITE_PERSISTENCE_FILE, "w");
    struct registered_ipcp *ripcp;
    struct uipcp *uipcp;

    if (!fpreg) {
        PE("Cannot open persistence file (%s)\n",
                RLITE_PERSISTENCE_FILE);
        return;
    }

    /* Dump the ipcps_registrations list, so that
     * subsequent uipcps invocations can redo the registrations. */
    list_for_each_entry(ripcp, &uipcps->ipcps_registrations, node) {
        char *ipcp_s;

        ipcp_s = rina_name_to_string(&ripcp->name);
        if (ipcp_s) {
            fprintf(fpreg, "REG %s %s\n", ripcp->dif_name, ipcp_s);
        } else {
            PE("Error in rina_name_to_string()\n");
        }
        if (ipcp_s) free(ipcp_s);
    }

    /* Dump to a file the list of enrolled ipcps for which we were initiator,
     * so that subsequent uipcps invocations can redo the registrations. */
    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        char *ipcp_s, *neigh_s;
        struct enrolled_neigh *en, *tmp;
        struct list_head neighs;

        if (!uipcp->ops.get_enrollment_targets) {
            continue;
        }

        if (uipcp->ops.get_enrollment_targets(uipcp, &neighs)) {
            PE("get_enrolled_neighs() failed for uipcp [%u]\n",
               uipcp->id);
            continue;
        }

        list_for_each_entry_safe(en, tmp, &neighs, node) {
            ipcp_s = rina_name_to_string(&en->ipcp_name);
            neigh_s = rina_name_to_string(&en->neigh_name);

            if (ipcp_s && neigh_s) {
                fprintf(fpreg, "ENR %s %s %s %s\n", en->dif_name, ipcp_s,
                        neigh_s, en->supp_dif);

            } else {
                PE("Error in rina_name_to_string()\n");
            }

            if (ipcp_s) free(ipcp_s);
            if (neigh_s) free(neigh_s);
        }
    }

    fclose(fpreg);
}

static void
sigint_handler(int signum)
{
    struct uipcps *uipcps = &guipcps;

    pthread_mutex_lock(&uipcps->lock);
    dump_persistence_file(uipcps);
    pthread_mutex_unlock(&uipcps->lock);

    /* TODO Here we should free all the dynamically allocated memory
     * referenced by uipcps. */

    unlink(RLITE_UIPCPS_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

static int
char_device_exists(const char *path)
{
    struct stat s;

    return stat(path, &s) == 0 && S_ISCHR(s.st_mode);
}

static void
usage(void)
{
    printf("rlite-uipcps [OPTIONS]\n"
        "   -h : show this help\n"
        "   -v VERB_LEVEL: set verbosity LEVEL: QUIET, WARN, INFO, "
                           "DBG (default), VERY\n"
          );
}

int main(int argc, char **argv)
{
    struct uipcps *uipcps = &guipcps;
    struct sockaddr_un server_address;
    struct sigaction sa;
    const char *verbosity = "DBG";
    int ret, opt;

    /* We require root permissions. */
    if (geteuid() != 0) {
        PE("uipcps daemon needs root permissions\n");
        return -1;
    }

    if (!char_device_exists(ctrl_dev_name)) {
        PE("Device %s not found\n", ctrl_dev_name);
        return -1;
    }

    if (!char_device_exists(io_dev_name)) {
        PE("Device %s not found\n", io_dev_name);
        return -1;
    }

    while ((opt = getopt(argc, argv, "hv:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'v':
                verbosity = optarg;
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    /* Set verbosity level. */
    if (strcmp(verbosity, "VERY") == 0) {
        rl_verbosity = RL_VERB_VERY;
    } else if (strcmp(verbosity, "INFO") == 0) {
        rl_verbosity = RL_VERB_INFO;
    } else if (strcmp(verbosity, "WARN") == 0) {
        rl_verbosity = RL_VERB_WARN;
    } else if (strcmp(verbosity, "QUIET") == 0) {
        rl_verbosity = RL_VERB_QUIET;
    } else {
        rl_verbosity = RL_VERB_DBG;
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

    ret = mkdir(RLITE_UIPCPS_VAR, 0x777);
    if (ret && errno != EEXIST) {
        perror("mkdir(/var/rlite)");
        exit(EXIT_FAILURE);
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
    if (chmod(ctrl_dev_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                            | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/dev/rlite) failed");
    }

    if (chmod(io_dev_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                               | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/dev/rlite-io) failed");
    }

    if (chmod(RLITE_UIPCPS_UNIX_NAME, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                                     | S_IROTH | S_IWOTH)) {
        perror("warning: chmod(/var/rlite/uipcp-server) failed");
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
    ret = uipcps_init(uipcps);
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
