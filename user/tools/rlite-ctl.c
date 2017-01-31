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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

#include <rlite/list.h>
#include <rlite/uipcps-msg.h>
#include <rlite/conf.h>

#include "../helpers.h"

/* IPCP attributes. */
struct ipcp_attrs {
    rl_ipcp_id_t id;
    char *name;
    rl_addr_t addr;
    unsigned int nhdrs;
    unsigned int max_sdu_size;
    char *dif_type;
    char *dif_name;

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
        list_for_each_entry(attrs, &ipcps, node) {
            if (rina_sername_valid(attrs->name)
                    && strcmp(attrs->name, name) == 0) {
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

    list_for_each_entry(attrs, &ipcps, node) {
        if (strcmp(attrs->dif_name, dif_name) == 0) {
            return attrs;
        }
    }

    return NULL;
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

typedef int (*response_handler_t )(struct rl_msg_base_resp *);

static int
read_response(int sfd, response_handler_t handler)
{
    struct rl_msg_base_resp *resp;
    char msgbuf[4096];
    char *serbuf = NULL;
    int serbuf_size = 4096;
    int read_ofs = 0;
    int ret = -1;
    int n;

    for (;;) {
        char *sbold = serbuf;

        serbuf = realloc(serbuf, serbuf_size);
        if (!serbuf) {
            PE("Out of memory\n");
            if (sbold) {
                free(sbold); /* Original buffer is not auto-freed. */
            }
            return -1;
        }

        n = read(sfd, serbuf + read_ofs, serbuf_size - read_ofs);
        if (n < 0) {
            PE("read() error [%d]\n", n);
            return -1;
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
        PE("error while deserializing response [%d]\n",
                ret);
        return -1;
    }

    resp = RLITE_MBR(msgbuf);
    ret = (resp->result) == 0 ? 0 : -1;

    PV("uipcps response [type=%u] --> %d\n", resp->msg_type, ret);

    if (!ret && handler) {
        ret = handler(resp);
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
    if (ret) {
        return ret;
    }

    return uipcps_disconnect(fd);
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
    dif_type = argv[1];
    dif_name = argv[2];

    ipcp_id = rl_conf_ipcp_create(ipcp_name, dif_type, dif_name);

    if (ipcp_id >= 0L) {
        PI("IPCP of type '%s' created, assigned id %u\n", dif_type,
           (unsigned int)ipcp_id);

        if (type_has_uipcp(dif_type)) {
            ret = rl_conf_ipcp_uipcp_wait((unsigned int)ipcp_id);
            if (ret) {
                PE("Cannot wait for uIPCP %u\n", (unsigned int)ipcp_id);
                rl_conf_ipcp_destroy((unsigned int)ipcp_id);

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
    ret = rl_conf_ipcp_destroy(attrs->id);
    if (!ret) {
        PI("IPCP %u destroyed\n", attrs->id);
    }

    return ret;
}

static int
ipcp_config(int argc, char **argv, struct cmd_descriptor *cd)
{
    const char *ipcp_name;
    const char *param_name;
    const char *param_value;
    struct ipcp_attrs *attrs;
    int ret = -1;  /* Report failure by default. */

    assert(argc >= 3);
    ipcp_name = argv[0];
    param_name = argv[1];
    param_value = argv[2];

    /* The request specifies an IPCP: lookup that. */
    attrs = lookup_ipcp_by_name(ipcp_name);
    if (!attrs) {
        PE("Could not find a suitable IPC process\n");
    } else {
        /* Forward the request to the kernel. */
        ret = rl_conf_ipcp_config(attrs->id, param_name, param_value);
        if (!ret) {
            PI("IPCP %u configured correctly: %s <== %s\n", attrs->id,
               param_name, param_value);
        }
    }

    return ret;
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
    dif_name = argv[0];
    ipcp_name = argv[1];

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
    req.reg = reg;

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

    assert(argc >= 4);
    dif_name = argv[0];
    ipcp_name = argv[1];
    neigh_ipcp_name = argv[2];
    supp_dif_name = argv[3];

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

    req.msg_type = msg_type;
    req.event_id = 0;
    req.dif_name = strdup(dif_name);
    req.neigh_name = strdup(neigh_ipcp_name);
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
ipcp_dft_set(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct rl_cmsg_ipcp_dft_set req;
    const char *ipcp_name;
    const char *appl_name;
    unsigned long remote_addr;
    struct ipcp_attrs *attrs;

    assert(argc >= 3);
    ipcp_name = argv[0];
    appl_name = argv[1];
    errno = 0;
    remote_addr = strtoul(argv[2], NULL, 10);
    if (errno) {
        PE("Invalid address %s\n", argv[2]);
        return -1;
    }

    req.ipcp_name = strdup(ipcp_name);
    if (!req.ipcp_name) {
        PE("Out of memory\n");
        return -1;
    }

    attrs = lookup_ipcp_by_name(req.ipcp_name);
    if (!attrs) {
        PE("Could not find IPC process\n");
        return -1;
    }

    req.msg_type = RLITE_U_IPCP_DFT_SET;
    req.event_id = 0;
    req.appl_name = strdup(appl_name);
    req.remote_addr = remote_addr;

    return request_response(RLITE_MB(&req), NULL);
}

static int
ipcps_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct ipcp_attrs *attrs;
    char addrbuf[20];

    PI_S("IPC Processes table:\n");

    list_for_each_entry(attrs, &ipcps, node) {
        if (attrs->addr == 0) {
            strncpy(addrbuf, "*", sizeof(addrbuf));
        } else {
            snprintf(addrbuf, sizeof(addrbuf), "%llu",
                     (long long unsigned int)attrs->addr);
        }
        PI_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
                " address = %s, nhdrs = %u, mss = %u\n",
                attrs->id, attrs->name, attrs->dif_type,
                attrs->dif_name, addrbuf,
                attrs->nhdrs, attrs->max_sdu_size);
    }

    return 0;
}

static int
flows_show(int argc, char **argv, struct cmd_descriptor *cd)
{
    struct list_head flows;

    list_init(&flows);
    rl_conf_flows_fetch(&flows);
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
    errno = 0;
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

    printf( "    snd_lwe                = %lu\n"
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
            (unsigned long)dtp.rcv_rwe,
            (unsigned long)dtp.max_seq_num_rcvd,
            (unsigned long)dtp.last_snd_data_ack,
            (unsigned long)dtp.next_snd_ctl_seq,
            (unsigned long)dtp.last_lwe_sent,
            (unsigned long)dtp.seqq_len
            );

    return 0;
}

#ifdef RL_MEMTRACK
static int
memtrack_dump(int argc, char **argv, struct cmd_descriptor *cd)
{
    rl_conf_memtrack_dump();

    return 0;
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
    const char *name;
    struct ipcp_attrs *attrs;

    assert(argc >= 1);
    name = argv[0];

    if (strcmp(cd->name, "dif-rib-show") == 0) {
        attrs = ipcp_by_dif(name);
        if (!attrs) {
            PE("Could not find any IPCP in DIF %s\n", name);
            return -1;
        }
        req.ipcp_name = strdup(attrs->name);
    } else {
        req.ipcp_name = strdup(name);
        attrs = lookup_ipcp_by_name(req.ipcp_name);
        if (!attrs) {
            PE("Could not find IPC process %s\n", name);
            return -1;
        }
    }

    req.msg_type = RLITE_U_IPCP_RIB_SHOW_REQ;
    req.event_id = 0;

    return request_response(RLITE_MB(&req),
                            ipcp_rib_show_handler);
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
        perror("rina_open");
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

        attrs = malloc(sizeof(*attrs));
        if (!attrs) {
            PE("Out of memory\n");
            ret = -1;
            break;
        }

        attrs->id = upd->ipcp_id;
        attrs->name = upd->ipcp_name; upd->ipcp_name = NULL;
        attrs->dif_type = upd->dif_type; upd->dif_type = NULL;
        attrs->dif_name = upd->dif_name; upd->dif_name = NULL;
        attrs->addr = upd->ipcp_addr;
        attrs->nhdrs = upd->nhdrs;
        attrs->max_sdu_size = upd->max_sdu_size;

        list_for_each_entry(scan, &ipcps, node) {
            if (attrs->id < scan->id) {
                break;
            }
        }
        list_add_tail(&attrs->node, &scan->node);
    }
    close(fd);

    return ret;
}

static struct cmd_descriptor cmd_descriptors[] = {
    {
        .name = "ipcp-create",
        .usage = "IPCP_NAME DIF_TYPE DIF_NAME",
        .num_args = 3,
        .func = ipcp_create,
    },
    {
        .name = "ipcp-destroy",
        .usage = "IPCP_NAME",
        .num_args = 1,
        .func = ipcp_destroy,
    },
    {
        .name = "ipcp-config",
        .usage = "IPCP_NAME PARAM_NAME PARAM_VALUE",
        .num_args = 3,
        .func = ipcp_config,
    },
    {
        .name = "ipcp-register",
        .usage = "DIF_NAME IPCP_NAME",
        .num_args = 2,
        .func = ipcp_register,
    },
    {
        .name = "ipcp-unregister",
        .usage = "DIF_NAME IPCP_NAME",
        .num_args = 2,
        .func = ipcp_unregister,
    },
    {
        .name = "ipcp-enroll",
        .usage = "DIF_NAME IPCP_NAME NEIGH_IPCP_NAME SUPP_DIF_NAME",
        .num_args = 4,
        .func = ipcp_enroll,
    },
    {
        .name = "ipcp-lower-flow-alloc",
        .usage = "DIF_NAME IPCP_NAME NEIGH_IPCP_NAME SUPP_DIF_NAME",
        .num_args = 4,
        .func = ipcp_lower_flow_alloc,
    },
#ifdef WITH_DFT_SET
    {
        .name = "ipcp-dft-set",
        .usage = "IPCP_NAME APPL_NAME REMOTE_ADDR",
        .num_args = 3,
        .func = ipcp_dft_set,
    },
#endif /* WITH_DFT_SET */
    {
        .name = "ipcps-show",
        .usage = "",
        .num_args = 0,
        .func = ipcps_show,
    },
    {
        .name = "ipcp-rib-show",
        .usage = "IPCP_NAME",
        .num_args = 1,
        .func = ipcp_rib_show,
    },
    {
        .name = "dif-rib-show",
        .usage = "DIF_NAME",
        .num_args = 1,
        .func = ipcp_rib_show,
    },
    {
        .name = "flows-show",
        .usage = "",
        .num_args = 0,
        .func = flows_show,
    },
    {
        .name = "flow-dump",
        .usage = "PORT_ID",
        .num_args = 1,
        .func = flow_dump,
    },
#ifdef RL_MEMTRACK
    {
        .name = "memtrack",
        .usage = "",
        .num_args = 0,
        .func = memtrack_dump,
    },
#endif
};

#define NUM_COMMANDS    (sizeof(cmd_descriptors)/sizeof(struct cmd_descriptor))

static void
usage(int i)
{
    if (i >= 0 && i < NUM_COMMANDS) {
        printf("    %s %s\n", cmd_descriptors[i].name, cmd_descriptors[i].usage);
        return;
    }

    printf("\nAvailable commands:\n");

    for (i = 0; i < NUM_COMMANDS; i++) {
        printf("    %s %s\n", cmd_descriptors[i].name, cmd_descriptors[i].usage);
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

    if (strcmp(cmd, "-h") != 0 && strcmp(cmd, "--help") != 0) {
        PE("Unknown command '%s'\n", cmd);
    }
    usage(-1);

    return -1;
}

static void
sigint_handler(int signum)
{
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    int ret;

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

    (void) ipcp_dft_set;

    return process_args(argc, argv);
}
