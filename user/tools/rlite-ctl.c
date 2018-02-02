/*
 * Command-line tool to manage and monitor the rlite stack.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

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
#include <sys/ioctl.h>
#include <poll.h>

#include "rlite/list.h"
#include "rlite/uipcps-msg.h"
#include "rlite/conf.h"
#include "rlite/uipcps-helpers.h"

/* IPCP attributes. */
struct ipcp_attrs {
    rl_ipcp_id_t id;
    char *name;
    rlm_addr_t addr;
    unsigned int txhdroom;
    unsigned int rxhdroom;
    unsigned int tailroom;
    unsigned int max_sdu_size;
    char *dif_type;
    char *dif_name;
    int wait_for_delete;

    struct list_head node;
};

/* Keeps the list of IPCPs in the system. */
static struct list_head ipcps;

struct cmd_descriptor {
    const char *name;
    const char *usage;
    unsigned int num_args;
    int (*func)(int argc, char **argv, struct cmd_descriptor *cd);
};

static struct ipcp_attrs *
lookup_ipcp_by_name(const char *name)
{
    struct ipcp_attrs *attrs;

    if (rina_sername_valid(name)) {
        list_for_each_entry (attrs, &ipcps, node) {
            if (rina_sername_valid(attrs->name) &&
                strcmp(attrs->name, name) == 0) {
                return attrs;
            }
        }
    }

    return NULL;
}

static struct ipcp_attrs *
ipcp_by_dif(const char *dif_name)
{
    struct ipcp_attrs *attrs;

    list_for_each_entry (attrs, &ipcps, node) {
        if (strcmp(attrs->dif_name, dif_name) == 0) {
            return attrs;
        }
    }

    return NULL;
}

/* Select the IPCP with the smaller MSS, which is
 * probably the one with the higher rank. */
static struct ipcp_attrs *
select_ipcp()
{
    unsigned int smaller_mss = ~0U;
    struct ipcp_attrs *ret   = NULL;
    struct ipcp_attrs *attrs;

    list_for_each_entry (attrs, &ipcps, node) {
        if (type_is_normal_ipcp(attrs->dif_type) &&
            attrs->max_sdu_size < smaller_mss) {
            smaller_mss = attrs->max_sdu_size;
            ret         = attrs;
        }
    }

    return ret;
}

static int
uipcps_connect(void)
{
    struct sockaddr_un server_address;
    int ret;
    int sfd;

    /* Open a Unix domain socket towards the uipcps. */
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RLITE_UIPCPS_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    ret = connect(sfd, (struct sockaddr *)&server_address,
                  sizeof(server_address));
    if (ret) {
        perror("connect(AF_UNIX, path)");
        PI("Warning: maybe uipcps are not running?\n");
        return -1;
    }

    return sfd;
}

static int
uipcps_disconnect(int sfd)
{
    return close(sfd);
}

typedef int (*response_handler_t)(struct rl_msg_base_resp *);

static int
read_response(int sfd, response_handler_t handler)
{
    struct rl_msg_base_resp *resp;
    char msgbuf[4096];
    char *serbuf    = NULL;
    int serbuf_size = 4096;
    int read_ofs    = 0;
    int ret         = -1;
    int n;

    for (;;) {
        struct pollfd pfd[1];
        char *sbold = serbuf;

        serbuf = realloc(serbuf, serbuf_size);
        if (!serbuf) {
            PE("Out of memory\n");
            if (sbold) {
                free(sbold); /* Original buffer is not auto-freed. */
            }
            return -1;
        }

        pfd[0].fd     = sfd;
        pfd[0].events = POLLIN;
        ret           = poll(pfd, 1, 10000 /* 10 seconds */);
        if (ret < 0) {
            PE("poll() error [%s]\n", strerror(errno));
            return ret;
        } else if (ret == 0) {
            PE("request timed out\n");
            return -1;
        }

        n = read(sfd, serbuf + read_ofs, serbuf_size - read_ofs);
        if (n < 0) {
            PE("read() error [%s]\n", strerror(errno));
            return n;
        }

        read_ofs += n;
        ret = deserialize_rlite_msg(rl_uipcps_numtables, RLITE_U_MSG_MAX,
                                    serbuf, read_ofs, msgbuf, sizeof(msgbuf));
        if (ret == 0) {
            break;
        }
        serbuf_size *= 2; /* Try with a bigger buffer. */
    }

    free(serbuf);
    if (ret) {
        errno = EPROTO;
        PE("error while deserializing response [%s]\n", strerror(errno));
        return -1;
    }

    resp = RLITE_MBR(msgbuf);
    ret  = (resp->result) == 0 ? 0 : -1;

    if (ret) {
        PE("Operation failed\n");
    }

    if (handler) {
        handler(resp);
    }

    return ret;
}

static int
request_response(struct rl_msg_base *req, response_handler_t handler)
{
    int fd;
    int ret;

    fd = uipcps_connect();
    if (fd < 0) {
        return fd;
    }

    ret = rl_msg_write_fd(fd, req);
    if (ret) {
        return ret;
    }

    ret = read_response(fd, handler);
    uipcps_disconnect(fd);

    return ret;
}

static int
ipcp_create(int argc, char **argv, struct cmd_descriptor *cd)
{
    const char *ipcp_name;
    const char *dif_type;
    const char *dif_name;
    long int ipcp_id;
    int ret;

    assert(argc >= 3);
    ipcp_name = argv[0];
    dif_type  = argv[1];
    dif_name  = argv[2];

    ipcp_id = rl_conf_ipcp_create(ipcp_name, dif_type, dif_name);

    if (ipcp_id >= 0L) {
        PI("IPCP of type '%s' created, assigned id %u\n", dif_type,
           (unsigned int)ipcp_id);

        if (type_has_uipcp(dif_type)) {
            ret = rl_conf_ipcp_uipcp_wait((unsigned int)ipcp_id);
            if (ret) {
                PE("Cannot wait for uIPCP %u\n", (unsigned int)ipcp_id);
                rl_conf_ipcp_destroy((unsigned int)ipcp_id, /*sync=*/0);

            } else {
                PI("uIPCP %u showed up\n", (unsigned int)ipcp_id);
            }
        }
    }

    return ipcp_id < 0 ? -1 : 0;
}

static int
ipcp_destroy(int argc, char **argv, struct cmd_descriptor *cd)
{
    const char *ipcp_name;
    struct ipcp_attrs *attrs;
    int ret = -1;

    assert(argc >= 1);
    ipcp_name = argv[0];

    /* Does the request specifies an existing IPC process ? */
    attrs = lookup_ipcp_by_name(ipcp_name);
    if (!attrs) {
        PE("No such IPCP process\n");
        return -1;
    }

    /* Valid IPCP id. Forward the request to the kernel. */
    ret = rl_conf_ipcp_destroy(attrs->id, /*sync=*/1);
    if (!ret) {
        PI("IPCP %u destroyed\n", attrs->id);
    }

    return ret;
}

static int
reset(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct ipcp_attrs *attrs;
    int ret = 0;
    int fd;

    /* Open a control device to receive kernel notifications about IPCP
     * removal events. */
    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    ret = ioctl(fd, RLITE_IOCTL_CHFLAGS, RL_F_IPCPS);
    if (ret < 0) {
        perror("ioctl()");
        return ret;
    }

    /* Scan the list of IPCPs and issue asynchronous IPCP destroy
     * commands. */
    list_for_each_entry (attrs, &ipcps, node) {
        int r;

        r = rl_conf_ipcp_destroy(attrs->id, /*sync=*/0);
        if (r) {
            PE("Failed to destroy IPCP %u\n", attrs->id);
        } else {
            attrs->wait_for_delete = 1;
        }

        ret |= r;
    }

    /* Wait for all the IPCPs to be deleted by the kernel. */
    for (;;) {
        struct rl_kmsg_ipcp_update *upd;
        int stop = 1;

        list_for_each_entry (attrs, &ipcps, node) {
            if (attrs->wait_for_delete) {
                stop = 0;
            }
        }

        if (stop) {
            /* We don't have more IPCPs to wait for. We can stop. */
            break;
        }

        /* Read the next update message and check if it reports the
         * deletion of an IPCP we are waiting for. */
        upd = (struct rl_kmsg_ipcp_update *)rl_read_next_msg(fd, 1);
        if (!upd) {
            if (errno) {
                perror("rl_read_next_msg()");
            }
            break;
        }
        assert(upd->msg_type == RLITE_KER_IPCP_UPDATE);

        list_for_each_entry (attrs, &ipcps, node) {
            if (upd->update_type == RL_IPCP_UPDATE_DEL &&
                upd->ipcp_id == attrs->id) {
                attrs->wait_for_delete = 0;
                break;
            }
        }
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(upd));
        rl_free(upd, RL_MT_MSG);
    }

    close(fd);

    return ret;
}

static int
ipcp_config(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_config req;
    const char *ipcp_name;
    const char *param_name;
    const char *param_value;
    struct ipcp_attrs *attrs;

    assert(argc >= 3);
    ipcp_name   = argv[0];
    param_name  = argv[1];
    param_value = argv[2];

    /* The request specifies an IPCP: lookup that. */
    attrs = lookup_ipcp_by_name(ipcp_name);
    if (!attrs) {
        PE("Could not find a suitable IPC process\n");
        return -1;
    }

    req.msg_type = RLITE_U_IPCP_CONFIG;
    req.event_id = 0;
    req.ipcp_id  = attrs->id;
    req.name     = strdup(param_name);
    req.value    = strdup(param_value);

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_register_common(int argc, char **argv, unsigned int reg,
                     struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_register req;
    const char *ipcp_name;
    const char *dif_name;
    struct ipcp_attrs *attrs;

    assert(argc >= 2);
    ipcp_name = argv[0];
    dif_name  = argv[1];

    req.ipcp_name = strdup(ipcp_name);
    if (!req.ipcp_name) {
        PE("Out of memory\n");
        return -1;
    }

    attrs = lookup_ipcp_by_name(req.ipcp_name);
    if (!attrs) {
        PE("Could not find the IPC process to register\n");
        return -1;
    }

    req.msg_type = RLITE_U_IPCP_REGISTER;
    req.event_id = 0;
    req.dif_name = strdup(dif_name);
    req.reg      = reg;

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_register(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_register_common(argc, argv, 1, cd);
}

static int
ipcp_unregister(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_register_common(argc, argv, 0, cd);
}

static int
ipcp_enroll_common(int argc, char **argv, rl_msg_t msg_type)
{
    struct rl_cmsg_ipcp_enroll req;
    const char *ipcp_name;
    const char *neigh_ipcp_name;
    const char *dif_name;
    const char *supp_dif_name;
    struct ipcp_attrs *attrs;
    int ret;

    assert(argc >= 3);
    ipcp_name       = argv[0];
    dif_name        = argv[1];
    supp_dif_name   = argv[2];
    neigh_ipcp_name = (argc >= 4) ? argv[3] : NULL;

    req.ipcp_name = strdup(ipcp_name);
    if (!req.ipcp_name) {
        PE("Out of memory\n");
        return -1;
    }

    attrs = lookup_ipcp_by_name(req.ipcp_name);
    if (!attrs) {
        PE("Could not find enrolling IPC process\n");
        return -1;
    }

    req.msg_type      = msg_type;
    req.event_id      = 0;
    req.dif_name      = strdup(dif_name);
    req.neigh_name    = neigh_ipcp_name ? strdup(neigh_ipcp_name) : NULL;
    req.supp_dif_name = strdup(supp_dif_name);

    ret = request_response(RLITE_MB(&req), NULL);
    if (ret) {
        PE("Enrollment failed\n");
    } else {
        PI("Enrollment completed successfully\n");
    }

    return ret;
}

static int
ipcp_enroll(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_enroll_common(argc, argv, RLITE_U_IPCP_ENROLL);
}

static int
ipcp_lower_flow_alloc(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_enroll_common(argc, argv, RLITE_U_IPCP_LOWER_FLOW_ALLOC);
}

static int
ipcp_enroll_retry(int argc, char **argv, struct cmd_descriptor *cd)
{
    int ret = -1;
    int i;

    for (i = 0; i < 3; i++) {
        ret = ipcp_enroll_common(argc, argv, RLITE_U_IPCP_ENROLL);
        if (!ret) {
            break;
        }
        sleep(i + 1);
        PI("Retry #%d...\n", i + 1);
    }

    return ret;
}

static int
ipcps_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct ipcp_attrs *attrs;
    char addrbuf[20];

    PI_S("IPC Processes table:\n");

    list_for_each_entry (attrs, &ipcps, node) {
        if (attrs->addr == RL_ADDR_NULL) {
            strncpy(addrbuf, "*", sizeof(addrbuf));
        } else {
            snprintf(addrbuf, sizeof(addrbuf), "%llu",
                     (long long unsigned int)attrs->addr);
        }
        PI_S("    id=%d, name='%s', dif_type='%s', dif_name='%s',"
             " address=%s, txhdroom=%u, rxhdroom=%u, troom=%u, mss=%u\n",
             attrs->id, attrs->name, attrs->dif_type, attrs->dif_name, addrbuf,
             attrs->txhdroom, attrs->rxhdroom, attrs->tailroom,
             attrs->max_sdu_size);
    }

    return 0;
}

static int
flows_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct list_head flows;
    rl_ipcp_id_t ipcp_id = 0xffff; /* no IPCP */

    if (argc > 0) {
        struct ipcp_attrs *attrs;

        attrs = ipcp_by_dif(argv[0]);
        if (!attrs) {
            PE("Could not find IPC process in DIF %s\n", argv[0]);
            return -1;
        }
        ipcp_id = attrs->id;
    }

    list_init(&flows);
    rl_conf_flows_fetch(&flows, ipcp_id);
    rl_conf_flows_print(&flows);
    rl_conf_flows_purge(&flows);

    return 0;
}

static int
flow_dump(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_flow_dtp dtp;
    unsigned long port_id;
    int ret;

    assert(argc >= 1);
    errno   = 0;
    port_id = strtoul(argv[0], NULL, 10);
    if (errno) {
        PE("Invalid flow id %s\n", argv[0]);
        return -1;
    }

    ret = rl_conf_flow_get_dtp(port_id, &dtp);
    if (ret) {
        PE("Could not find flow with port id %lu\n", port_id);
        return ret;
    }

    printf("    snd_lwe                = %lu\n"
           "    snd_rwe                = %lu\n"
           "    next_seq_num_to_send   = %lu\n"
           "    last_seq_num_sent      = %lu\n"
           "    last_ctrl_seq_num_rcvd = %lu\n"
           "    cwq_len                = %lu [max=%lu]\n"
           "    rtxq_len               = %lu [max=%lu]\n"
           "    rtt                    = %lu [stddev=%lu]\n"
           "    rcv_lwe                = %lu\n"
           "    rcv_lwe_priv           = %lu\n"
           "    rcv_rwe                = %lu\n"
           "    max_seq_num_rcvd       = %lu\n"
           "    last_snd_data_ack      = %lu\n"
           "    next_snd_ctl_seq       = %lu\n"
           "    last_lwe_sent          = %lu\n"
           "    seqq_len               = %lu\n",
           (unsigned long)dtp.snd_lwe, (unsigned long)dtp.snd_rwe,
           (unsigned long)dtp.next_seq_num_to_send,
           (unsigned long)dtp.last_seq_num_sent,
           (unsigned long)dtp.last_ctrl_seq_num_rcvd,
           (unsigned long)dtp.cwq_len, (unsigned long)dtp.max_cwq_len,
           (unsigned long)dtp.rtxq_len, (unsigned long)dtp.max_rtxq_len,
           (unsigned long)dtp.rtt, (unsigned long)dtp.rtt_stddev,

           (unsigned long)dtp.rcv_lwe, (unsigned long)dtp.rcv_lwe_priv,
           (unsigned long)dtp.rcv_rwe, (unsigned long)dtp.max_seq_num_rcvd,
           (unsigned long)dtp.last_snd_data_ack,
           (unsigned long)dtp.next_snd_ctl_seq,
           (unsigned long)dtp.last_lwe_sent, (unsigned long)dtp.seqq_len);

    return 0;
}

static int
regs_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct list_head regs;
    rl_ipcp_id_t ipcp_id = 0xffff; /* no IPCP */

    if (argc > 0) {
        struct ipcp_attrs *attrs;

        attrs = ipcp_by_dif(argv[0]);
        if (!attrs) {
            PE("Could not find IPC process in DIF %s\n", argv[0]);
            return -1;
        }
        ipcp_id = attrs->id;
    }

    list_init(&regs);
    rl_conf_regs_fetch(&regs, ipcp_id);
    rl_conf_regs_print(&regs);
    rl_conf_regs_purge(&regs);

    return 0;
}

static int
ipcp_policy_mod(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_policy_mod req;
    const char *name;
    const char *comp_name;
    const char *policy_name;
    struct ipcp_attrs *attrs;

    assert(argc >= 3);
    name        = argv[0];
    comp_name   = argv[1];
    policy_name = argv[2];

    if (strcmp(cd->name, "dif-policy-mod") == 0) {
        attrs = ipcp_by_dif(name);
        if (!attrs) {
            PE("Could not find any IPCP in DIF %s\n", name);
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else {
        req.ipcp_name = strdup(name);
        attrs         = lookup_ipcp_by_name(req.ipcp_name);
        if (!attrs) {
            PE("Could not find IPC process %s\n", name);
            return -1;
        }
    }

    req.msg_type    = RLITE_U_IPCP_POLICY_MOD;
    req.event_id    = 0;
    req.comp_name   = strdup(comp_name);
    req.policy_name = strdup(policy_name);

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_policy_param_mod(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_policy_param_mod req;
    const char *name;
    const char *comp_name;
    const char *param_name;
    const char *param_value;
    struct ipcp_attrs *attrs;

    assert(argc >= 4);
    name        = argv[0];
    comp_name   = argv[1];
    param_name  = argv[2];
    param_value = argv[3];

    if (strcmp(cd->name, "dif-policy-param-mod") == 0) {
        attrs = ipcp_by_dif(name);
        if (!attrs) {
            PE("Could not find any IPCP in DIF %s\n", name);
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else {
        req.ipcp_name = strdup(name);
        attrs         = lookup_ipcp_by_name(req.ipcp_name);
        if (!attrs) {
            PE("Could not find IPC process %s\n", name);
            return -1;
        }
    }

    req.msg_type    = RLITE_U_IPCP_POLICY_PARAM_MOD;
    req.event_id    = 0;
    req.comp_name   = strdup(comp_name);
    req.param_name  = strdup(param_name);
    req.param_value = strdup(param_value);

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_enroller_mod(int argc, char **argv, struct cmd_descriptor *cd, int enable)
{
    struct rl_cmsg_ipcp_enroller_enable req;
    const char *ipcp_name;
    struct ipcp_attrs *attrs;

    assert(argc >= 1);
    ipcp_name = argv[0];

    req.ipcp_name = strdup(ipcp_name);
    attrs         = lookup_ipcp_by_name(req.ipcp_name);
    if (!attrs) {
        PE("Could not find IPC process %s\n", ipcp_name);
        return -1;
    }

    req.msg_type = RLITE_U_IPCP_ENROLLER_ENABLE;
    req.event_id = 0;
    req.enable   = enable ? 1 : 0;

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_enroller_enable(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_enroller_mod(argc, argv, cd, 1);
}

static int
ipcp_enroller_disable(int argc, char **argv, struct cmd_descriptor *cd)
{
    return ipcp_enroller_mod(argc, argv, cd, 0);
}

static int
probe(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_msg_base req;

    req.msg_type = RLITE_U_PROBE;
    req.event_id = 0;

    return request_response(RLITE_MB(&req), NULL);
}

static int
terminate(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_msg_base req;

    req.msg_type = RLITE_U_TERMINATE;
    req.event_id = 0;

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcp_neigh_disconnect(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_neigh_disconnect req;
    struct ipcp_attrs *attrs;
    const char *ipcp_name;
    const char *neigh_name;

    assert(argc >= 2);
    ipcp_name  = argv[0];
    neigh_name = argv[1];

    req.ipcp_name  = strdup(ipcp_name);
    req.neigh_name = strdup(neigh_name);
    attrs          = lookup_ipcp_by_name(req.ipcp_name);
    if (!attrs) {
        PE("Could not find IPC process %s\n", ipcp_name);
        return -1;
    }

    req.msg_type = RLITE_U_IPCP_NEIGH_DISCONNECT;
    req.event_id = 0;

    return request_response(RLITE_MB(&req), NULL);
}

#ifdef RL_MEMTRACK
static int
memtrack_dump(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_msg_base req;

    /* trigger kernel-space dump */
    rl_conf_memtrack_dump();

    /* trigger user-space dump */
    req.msg_type = RLITE_U_MEMTRACK_DUMP;
    req.event_id = 0;

    return request_response(RLITE_MB(&req), NULL);
}
#endif

static int
ipcp_rib_show_handler(struct rl_msg_base_resp *b_resp)
{
    struct rl_cmsg_ipcp_rib_show_resp *resp =
        (struct rl_cmsg_ipcp_rib_show_resp *)b_resp;

    if (resp->dump.len) {
        printf("%s\n", (char *)resp->dump.buf);
    }

    return 0;
}

static int
ipcp_rib_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_rib_show_req req;
    struct ipcp_attrs *attrs;

    if (argc >= 1) {
        const char *name;

        name = argv[0];
        if (strncmp(cd->name, "dif-", 4) == 0) {
            attrs = ipcp_by_dif(name);
            if (!attrs) {
                PE("Could not find any IPCP in DIF %s\n", name);
                return -1;
            }
            req.ipcp_name = strdup(attrs->name);
        } else {
            req.ipcp_name = strdup(name);
            attrs         = lookup_ipcp_by_name(req.ipcp_name);
            if (!attrs) {
                PE("Could not find IPC process %s\n", name);
                return -1;
            }
        }
    } else {
        attrs = select_ipcp();
        if (!attrs) {
            PE("Could not find any IPCP\n");
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    }

    if (strcmp(cd->name, "dif-rib-show") == 0 ||
        strcmp(cd->name, "ipcp-rib-show") == 0) {
        req.msg_type = RLITE_U_IPCP_RIB_SHOW_REQ;
    } else if (strcmp(cd->name, "dif-routing-show") == 0 ||
               strcmp(cd->name, "ipcp-routing-show") == 0) {
        req.msg_type = RLITE_U_IPCP_ROUTING_SHOW_REQ;
    } else {
        return -1;
    }
    req.event_id = 0;

    return request_response(RLITE_MB(&req), ipcp_rib_show_handler);
}

static int
ipcp_policy_list(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_policy_list_req req;
    const char *name      = NULL;
    const char *comp_name = NULL;
    struct ipcp_attrs *attrs;

    if (argc >= 1) {
        name = argv[0];
    }
    if (argc >= 2) {
        comp_name = argv[1];
    }

    if (argc == 0) {
        attrs = select_ipcp();
        if (!attrs) {
            PE("Could not find any IPCP\n");
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else if (strcmp(cd->name, "dif-policy-list") == 0) {
        attrs = ipcp_by_dif(name);
        if (!attrs) {
            PE("Could not find any IPCP in DIF %s\n", name);
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else {
        req.ipcp_name = strdup(name);
        attrs         = lookup_ipcp_by_name(req.ipcp_name);
        if (!attrs) {
            PE("Could not find IPC process %s\n", name);
            return -1;
        }
    }

    req.msg_type  = RLITE_U_IPCP_POLICY_LIST_REQ;
    req.event_id  = 0;
    req.comp_name = comp_name ? strdup(comp_name) : NULL;

    return request_response(RLITE_MB(&req), ipcp_rib_show_handler);
}

static int
ipcp_policy_param_list(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_policy_param_list_req req;
    const char *name       = NULL;
    const char *comp_name  = NULL;
    const char *param_name = NULL;
    struct ipcp_attrs *attrs;

    if (argc >= 1) {
        name = argv[0];
    }
    if (argc >= 2) {
        comp_name = argv[1];
    }
    if (argc >= 3) {
        param_name = argv[2];
    }

    if (argc == 0) {
        attrs = select_ipcp();
        if (!attrs) {
            PE("Could not find any IPCP\n");
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else if (strcmp(cd->name, "dif-policy-param-list") == 0) {
        attrs = ipcp_by_dif(name);
        if (!attrs) {
            PE("Could not find any IPCP in DIF %s\n", name);
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else {
        req.ipcp_name = strdup(name);
        attrs         = lookup_ipcp_by_name(req.ipcp_name);
        if (!attrs) {
            PE("Could not find IPC process %s\n", name);
            return -1;
        }
    }

    req.msg_type   = RLITE_U_IPCP_POLICY_PARAM_LIST_REQ;
    req.event_id   = 0;
    req.comp_name  = comp_name ? strdup(comp_name) : NULL;
    req.param_name = param_name ? strdup(param_name) : NULL;

    return request_response(RLITE_MB(&req), ipcp_rib_show_handler);
}

/* Build the list of IPCPs running in the system, ordered by id. */
static int
ipcps_load()
{
    int ret = 0;
    int fd;

    /* We init an rlite control device, with IPCP updates
     * enabled. */
    fd = rina_open();
    if (fd < 0) {
        perror("rina_open()");
        return fd;
    }
    ret = ioctl(fd, RLITE_IOCTL_CHFLAGS, RL_F_IPCPS);
    if (ret < 0) {
        perror("ioctl()");
        return ret;
    }
    ret = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (ret < 0) {
        perror("fcntl(F_SETFL, O_NONBLOCK)");
        return ret;
    }

    list_init(&ipcps);

    for (;;) {
        struct rl_kmsg_ipcp_update *upd;
        struct ipcp_attrs *attrs, *scan;

        upd = (struct rl_kmsg_ipcp_update *)rl_read_next_msg(fd, 1);
        if (!upd) {
            if (errno && errno != EAGAIN) {
                perror("rl_read_next_msg()");
            }
            break;
        }
        assert(upd->msg_type == RLITE_KER_IPCP_UPDATE);

        if (upd->update_type == RL_IPCP_UPDATE_ADD) {
            attrs = malloc(sizeof(*attrs));
            if (!attrs) {
                PE("Out of memory\n");
                ret = -1;
                break;
            }

            attrs->id           = upd->ipcp_id;
            attrs->name         = upd->ipcp_name;
            upd->ipcp_name      = NULL;
            attrs->dif_type     = upd->dif_type;
            upd->dif_type       = NULL;
            attrs->dif_name     = upd->dif_name;
            upd->dif_name       = NULL;
            attrs->addr         = upd->ipcp_addr;
            attrs->txhdroom     = upd->txhdroom;
            attrs->rxhdroom     = upd->rxhdroom;
            attrs->tailroom     = upd->tailroom;
            attrs->max_sdu_size = upd->max_sdu_size;

            list_for_each_entry (scan, &ipcps, node) {
                if (attrs->id < scan->id) {
                    break;
                }
            }
            list_add_tail(&attrs->node, &scan->node);
        }
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(upd));
        rl_free(upd, RL_MT_MSG);
    }
    close(fd);

    return ret;
}

static struct cmd_descriptor cmd_descriptors[] = {
    {
        .name     = "ipcp-create",
        .usage    = "IPCP_NAME DIF_TYPE DIF_NAME",
        .num_args = 3,
        .func     = ipcp_create,
    },
    {
        .name     = "ipcp-destroy",
        .usage    = "IPCP_NAME",
        .num_args = 1,
        .func     = ipcp_destroy,
    },
    {
        .name     = "reset",
        .usage    = "",
        .num_args = 0,
        .func     = reset,
    },
    {
        .name     = "ipcp-config",
        .usage    = "IPCP_NAME PARAM_NAME PARAM_VALUE",
        .num_args = 3,
        .func     = ipcp_config,
    },
    {
        .name     = "ipcp-register",
        .usage    = "IPCP_NAME DIF_NAME",
        .num_args = 2,
        .func     = ipcp_register,
    },
    {
        .name     = "ipcp-unregister",
        .usage    = "IPCP_NAME DIF_NAME",
        .num_args = 2,
        .func     = ipcp_unregister,
    },
    {
        .name     = "ipcp-enroll",
        .usage    = "IPCP_NAME DIF_NAME SUPP_DIF_NAME [NEIGH_IPCP_NAME]",
        .num_args = 3,
        .func     = ipcp_enroll,
    },
    {
        .name     = "ipcp-enroll-retry",
        .usage    = "IPCP_NAME DIF_NAME SUPP_DIF_NAME [NEIGH_IPCP_NAME]",
        .num_args = 3,
        .func     = ipcp_enroll_retry,
    },
    {
        .name     = "ipcp-lower-flow-alloc",
        .usage    = "IPCP_NAME DIF_NAME SUPP_DIF_NAME [NEIGH_IPCP_NAME]",
        .num_args = 3,
        .func     = ipcp_lower_flow_alloc,
    },
    {
        .name     = "ipcps-show",
        .usage    = "",
        .num_args = 0,
        .func     = ipcps_show,
    },
    {
        .name     = "dif-rib-show",
        .usage    = "[DIF_NAME]",
        .num_args = 0,
        .func     = ipcp_rib_show,
    },
    {
        .name     = "dif-routing-show",
        .usage    = "[DIF_NAME]",
        .num_args = 0,
        .func     = ipcp_rib_show,
    },
    {
        .name     = "flows-show",
        .usage    = "[DIF_NAME]",
        .num_args = 0,
        .func     = flows_show,
    },
    {
        .name     = "flow-dump",
        .usage    = "PORT_ID",
        .num_args = 1,
        .func     = flow_dump,
    },
    {
        .name     = "regs-show",
        .usage    = "[DIF_NAME]",
        .num_args = 0,
        .func     = regs_show,
    },
    {
        .name     = "dif-policy-mod",
        .usage    = "DIF_NAME COMPONENT_NAME POLICY_NAME",
        .num_args = 3,
        .func     = ipcp_policy_mod,
    },
    {
        .name     = "dif-policy-list",
        .usage    = "[DIF_NAME] [COMPONENT_NAME]",
        .num_args = 0,
        .func     = ipcp_policy_list,
    },
    {
        .name     = "dif-policy-param-mod",
        .usage    = "DIF_NAME COMPONENT_NAME PARAM_NAME PARAM_VALUE",
        .num_args = 4,
        .func     = ipcp_policy_param_mod,
    },
    {
        .name     = "dif-policy-param-list",
        .usage    = "[DIF_NAME] [COMPONENT_NAME] [PARAM_NAME]",
        .num_args = 0,
        .func     = ipcp_policy_param_list,
    },
    {
        .name     = "ipcp-enroller-enable",
        .usage    = "IPCP_NAME",
        .num_args = 1,
        .func     = ipcp_enroller_enable,
    },
    {
        .name     = "ipcp-enroller-disable",
        .usage    = "IPCP_NAME",
        .num_args = 1,
        .func     = ipcp_enroller_disable,
    },
    {
        .name     = "probe",
        .usage    = "",
        .num_args = 0,
        .func     = probe,
    },
    {
        .name     = "terminate",
        .usage    = "",
        .num_args = 0,
        .func     = terminate,
    },
    {
        .name     = "ipcp-neigh-disconnect",
        .usage    = "IPCP_NAME NEIGH_NAME",
        .num_args = 2,
        .func     = ipcp_neigh_disconnect,
    },
#if 0
    {
        .name = "ipcp-rib-show",
        .usage = "IPCP_NAME",
        .num_args = 1,
        .func = ipcp_rib_show,
    },
    {
        .name = "ipcp-routing-show",
        .usage = "IPCP_NAME",
        .num_args = 1,
        .func = ipcp_rib_show,
    },
    {
        .name = "ipcp-policy-mod",
        .usage = "IPCP_NAME COMPONENT_NAME POLICY_NAME",
        .num_args = 3,
        .func = ipcp_policy_mod,
    },
    {
        .name = "ipcp-policy-param-mod",
        .usage = "IPCP_NAME COMPONENT_NAME PARAM_NAME PARAM_VALUE",
        .num_args = 4,
        .func = ipcp_policy_param_mod,
    },
#endif
#ifdef RL_MEMTRACK
    {
        .name     = "memtrack",
        .usage    = "",
        .num_args = 0,
        .func     = memtrack_dump,
    },
#endif
};

#define NUM_COMMANDS (sizeof(cmd_descriptors) / sizeof(struct cmd_descriptor))

static void
usage(int i)
{
    if (i >= 0 && i < NUM_COMMANDS) {
        printf("    %s %s\n", cmd_descriptors[i].name,
               cmd_descriptors[i].usage);
        return;
    }

    printf("\nAvailable commands:\n");

    for (i = 0; i < NUM_COMMANDS; i++) {
        printf("    %s %s\n", cmd_descriptors[i].name,
               cmd_descriptors[i].usage);
    }
}

static int
process_args(int argc, char **argv)
{
    const char *cmd;
    int i;

    if (argc < 2) {
        /* No command, assume ipcps-show. */
        cmd = "ipcps-show";

    } else {
        cmd = argv[1];
    }

    /* First of all check if the user is just asking for help.
     * This must work even if rlite modules are not loaded. */
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
        usage(-1);
        return 0;
    }

    for (i = 0; i < NUM_COMMANDS; i++) {
        if (strcmp(cmd, cmd_descriptors[i].name) == 0) {
            int ret;

            assert(cmd_descriptors[i].func);

            if (argc - 2 < cmd_descriptors[i].num_args) {
                /* Not enough arguments. */
                PE("Not enough arguments\n");
                usage(i);
                return -1;
            }

            ret = ipcps_load();
            if (ret) {
                return ret;
            }

            ret = cmd_descriptors[i].func(argc - 2, argv + 2,
                                          cmd_descriptors + i);

            return ret;
        }
    }

    PE("Unknown command '%s'\n", cmd);
    usage(-1);

    return -1;
}

static void
sigint_handler(int signum)
{
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    int ret;

    /* Set an handler for SIGINT and SIGTERM so that we can remove
     * the Unix domain socket used to access the uipcp server. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret         = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        exit(EXIT_FAILURE);
    }

    return process_args(argc, argv);
}
