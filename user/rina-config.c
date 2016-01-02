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

#include <rina/rina-application-msg.h>
#include "helpers.h"
#include "evloop.h"


struct rinaconf {
    struct rina_evloop loop;
};

/* Kernel response handlers. */
static int
ipcp_create_resp(struct rina_evloop *loop,
                 const struct rina_msg_base_resp *b_resp,
                 const struct rina_msg_base *b_req)
{
    struct rina_kmsg_ipcp_create_resp *resp =
            (struct rina_kmsg_ipcp_create_resp *)b_resp;
    struct rina_kmsg_ipcp_create *req =
            (struct rina_kmsg_ipcp_create *)b_req;

    PI("%s: Assigned id %d\n", __func__, resp->ipcp_id);
    (void)req;

    return 0;
}

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call issue_request(), in
 * order to avoid deadlocks.
 * These would happen because issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_IPCP_CREATE_RESP] = ipcp_create_resp,
    [RINA_KERN_MSG_MAX] = NULL,
};

static int
ipcm_connect()
{
    struct sockaddr_un server_address;
    int ret;
    int sfd;

    /* Open a Unix domain socket towards the IPCM. */
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RINA_IPCM_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    ret = connect(sfd, (struct sockaddr *)&server_address,
                    sizeof(server_address));
    if (ret) {
        perror("bind(AF_UNIX, path)");
        exit(EXIT_FAILURE);
        return -1;
    }

    return sfd;
}

static int ipcm_disconnect(int sfd)
{
        return close(sfd);
}

static int
read_response(int sfd)
{
    struct rina_msg_base_resp *resp;
    char msgbuf[4096];
    char serbuf[4096];
    int ret;
    int n;

    n = read(sfd, serbuf, sizeof(serbuf));
    if (n < 0) {
        PE("%s: read() error [%d]\n", __func__, n);
        return -1;
    }

    ret = deserialize_rina_msg(rina_conf_numtables, serbuf,
                               n, msgbuf, sizeof(msgbuf));
    if (ret) {
        PE("%s: error while deserializing response [%d]\n",
                __func__, ret);
        return -1;
    }

    resp = (struct rina_msg_base_resp *)msgbuf;
    ret = (resp->result) == 0 ? 0 : -1;

    PI("IPCM response [type=%u] --> %d\n", resp->msg_type, ret);

    return ret;
}

static int
request_response(struct rina_msg_base *req)
{
    int fd;
    int ret;

    fd = ipcm_connect();
    if (fd < 0) {
        return fd;
    }

    ret = rina_msg_write(fd, req);
    if (ret) {
        return ret;
    }

    ret = read_response(fd);
    if (ret) {
        return ret;
    }

    return ipcm_disconnect(fd);
}

static const char *dif_types[] = {
    [DIF_TYPE_NORMAL] = "normal",
    [DIF_TYPE_SHIM_DUMMY] = "shim-dummy",
    [DIF_TYPE_SHIM_HV] = "shim-hv",
};

/* Create an IPC process. */
static struct rina_kmsg_ipcp_create_resp *
rina_ipcp_create(struct rinaconf *rc, unsigned int wait_for_completion,
                 const struct rina_name *name, uint8_t dif_type,
                 int *result)
{
    struct rina_kmsg_ipcp_create *msg;
    struct rina_kmsg_ipcp_create_resp *resp;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        PE("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_CREATE;
    rina_name_copy(&msg->name, name);
    msg->dif_type = dif_type;

    PD("Requesting IPC process creation...\n");

    resp = (struct rina_kmsg_ipcp_create_resp *)
           issue_request(&rc->loop, RMB(msg),
                         sizeof(*msg), 1, wait_for_completion, result);

    ipcps_fetch(&rc->loop);

    /* TODO notify the uipcps manager
    if (dif_type == DIF_TYPE_NORMAL && *result == 0 && resp) {
        *result = uipcp_add(ipcm, resp->ipcp_id);
    }

    uipcps_fetch(ipcm);
    */

    return resp;
}

static int ipcp_create(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_kmsg_ipcp_create_resp *kresp;
    const char *ipcp_apn;
    const char *ipcp_api;
    struct rina_name ipcp_name;
    uint8_t dif_type;
    int result;
    int i;

    assert(argc >= 3);
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    dif_type = DIF_TYPE_MAX;
    for (i = 0; i < DIF_TYPE_MAX; i++) {
        assert(dif_types[i]);
        if (strcmp(argv[0], dif_types[i]) == 0) {
            dif_type = i;
            break;
        }
    }
    if (dif_type == DIF_TYPE_MAX) {
        /* No such dif type. Print the available types
         * and exit. */
        PE("No such dif type. Available DIF types:\n");
        for (i = 0; i < DIF_TYPE_MAX; i++) {
            PE("    %s\n", dif_types[i]);
        }
        return -1;
    }
    rina_name_fill(&ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    kresp = rina_ipcp_create(rc, ~0U, &ipcp_name, dif_type, &result);
    if (kresp) {
        rina_msg_free(rina_kernel_numtables, RMB(kresp));
    }

    return result;
}

static int ipcp_destroy(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_amsg_ipcp_destroy req;
    const char *ipcp_apn;
    const char *ipcp_api;

    assert(argc >= 2);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];

    req.msg_type = RINA_CONF_IPCP_DESTROY;
    req.event_id = 0;
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

static int assign_to_dif(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_amsg_assign_to_dif req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *dif_name;

    assert(argc >= 3);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    req.msg_type = RINA_CONF_ASSIGN_TO_DIF;
    req.event_id = 0;
    rina_name_fill(&req.application_name, ipcp_apn, ipcp_api, NULL, NULL);
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

static int ipcp_config(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_amsg_ipcp_config req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *param_name;
    const char *param_value;

    assert(argc >= 4);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];
    param_name = argv[2];
    param_value = argv[3];

    req.msg_type = RINA_CONF_IPCP_CONFIG;
    req.event_id = 0;
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    req.name = strdup(param_name);
    req.value = strdup(param_value);

    return request_response((struct rina_msg_base *)&req);
}

static int ipcp_register_common(int argc, char **argv, unsigned int reg)
{
    struct rina_amsg_ipcp_register req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *dif_name;

    assert(argc >= 3);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    req.msg_type = RINA_CONF_IPCP_REGISTER;
    req.event_id = 0;
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);
    req.reg = reg;

    return request_response((struct rina_msg_base *)&req);
}

static int ipcp_register(int argc, char **argv, struct rinaconf *rc)
{
    return ipcp_register_common(argc, argv, 1);
}

static int ipcp_unregister(int argc, char **argv, struct rinaconf *rc)
{
    return ipcp_register_common(argc, argv, 0);
}

static int ipcp_enroll(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_amsg_ipcp_enroll req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *neigh_ipcp_apn;
    const char *neigh_ipcp_api;
    const char *dif_name;
    const char *supp_dif_name;

    assert(argc >= 6);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];
    neigh_ipcp_apn = argv[3];
    neigh_ipcp_api = argv[4];
    supp_dif_name = argv[5];

    req.msg_type = RINA_CONF_IPCP_ENROLL;
    req.event_id = 0;
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    rina_name_fill(&req.neigh_ipcp_name, neigh_ipcp_apn, neigh_ipcp_api, NULL, NULL);
    rina_name_fill(&req.supp_dif_name, supp_dif_name, NULL, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

static int ipcp_dft_set(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_amsg_ipcp_dft_set req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *appl_apn;
    const char *appl_api;
    unsigned long remote_addr;

    assert(argc >= 5);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];
    appl_apn = argv[2];
    appl_api = argv[3];
    errno = 0;
    remote_addr = strtoul(argv[4], NULL, 10);
    if (errno) {
        PE("%s: Invalid address %s\n", __func__, argv[4]);
        return -1;
    }

    req.msg_type = RINA_CONF_IPCP_DFT_SET;
    req.event_id = 0;
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    rina_name_fill(&req.appl_name, appl_apn, appl_api, NULL, NULL);
    req.remote_addr = remote_addr;

    return request_response((struct rina_msg_base *)&req);
}

struct cmd_descriptor {
    const char *name;
    const char *usage;
    unsigned int num_args;
    int (*func)(int argc, char **argv, struct rinaconf *rc);
};

static struct cmd_descriptor cmd_descriptors[] = {
    {
        .name = "ipcp-create",
        .usage = "DIF_TYPE IPCP_APN IPCP_API",
        .num_args = 3,
        .func = ipcp_create,
    },
    {
        .name = "ipcp-destroy",
        .usage = "IPCP_APN IPCP_API",
        .num_args = 2,
        .func = ipcp_destroy,
    },
    {
        .name = "assign-to-dif",
        .usage = "DIF_NAME IPCP_APN IPCP_API",
        .num_args = 3,
        .func = assign_to_dif,
    },
    {
        .name = "ipcp-config",
        .usage = "IPCP_APN IPCP_API PARAM_NAME PARAM_VALUE",
        .num_args = 4,
        .func = ipcp_config,
    },
    {
        .name = "ipcp-register",
        .usage = "DIF_NAME IPCP_APN IPCP_API",
        .num_args = 3,
        .func = ipcp_register,
    },
    {
        .name = "ipcp-unregister",
        .usage = "DIF_NAME IPCP_APN IPCP_API",
        .num_args = 3,
        .func = ipcp_unregister,
    },
    {
        .name = "ipcp-enroll",
        .usage = "DIF_NAME IPCP_APN IPCP_API NEIGH_IPCP_APN NEIGH_IPCP_API SUPP_DIF_NAME",
        .num_args = 6,
        .func = ipcp_enroll,
    },
    {
        .name = "ipcp-dft-set",
        .usage = "IPCP_APN IPCP_API APPL_APN APPL_API REMOTE_ADDR",
        .num_args = 5,
        .func = ipcp_dft_set,
    },
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
process_args(int argc, char **argv, struct rinaconf *rc)
{
    const char *cmd;
    int i;

    if (argc < 2) {
        /* No command. */
        usage(-1);
        return -1;
    }

    cmd = argv[1];

    for (i = 0; i < NUM_COMMANDS; i++) {
        if (strcmp(cmd, cmd_descriptors[i].name) == 0) {
            assert(cmd_descriptors[i].func);

            if (argc - 2 < cmd_descriptors[i].num_args) {
                /* Not enough arguments. */
                PE("Not enough arguments\n");
                usage(i);
                return -1;
            }

            return cmd_descriptors[i].func(argc - 2, argv + 2, rc);
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

int main(int argc, char **argv)
{
    struct rinaconf rc;
    struct sigaction sa;
    int ret;

    ret = rina_evloop_init(&rc.loop, "/dev/rina-ctrl",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

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

    /* Fetch kernel state. */
    ipcps_fetch(&rc.loop);

    ret = process_args(argc, argv, &rc);

    evloop_stop(&rc.loop);

    rina_evloop_fini(&rc.loop);

    return 0;
}
