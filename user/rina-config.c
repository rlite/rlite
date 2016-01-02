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

#include "rinalite/rina-conf-msg.h"
#include "helpers.h"
#include "rinalite-evloop.h"


struct rinaconf {
    struct rinalite_evloop loop;
};

/* Kernel response handlers. */
static int
ipcp_create_resp(struct rinalite_evloop *loop,
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
 * Response handlers must not call rinalite_issue_request(), in
 * order to avoid deadlocks.
 * These would happen because rinalite_issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_IPCP_CREATE_RESP] = ipcp_create_resp,
    [RINA_KERN_MSG_MAX] = NULL,
};

static int
uipcps_connect(int verbose)
{
    struct sockaddr_un server_address;
    int ret;
    int sfd;

    /* Open a Unix domain socket towards the uipcps. */
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        if (verbose) {
            perror("socket(AF_UNIX)");
        }
        return -1;
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RINA_UIPCPS_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    ret = connect(sfd, (struct sockaddr *)&server_address,
                    sizeof(server_address));
    if (ret) {
        if (verbose) {
            perror("connect(AF_UNIX, path)");
        } else {
            PI("Warning: uipcps are not running\n");
        }
        return -1;
    }

    return sfd;
}

static int uipcps_disconnect(int sfd)
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

    PI("uipcps response [type=%u] --> %d\n", resp->msg_type, ret);

    return ret;
}

static int
request_response(struct rina_msg_base *req, int verbose)
{
    int fd;
    int ret;

    fd = uipcps_connect(verbose);
    if (fd < 0) {
        return fd;
    }

    ret = rina_msg_write_fd(fd, req);
    if (ret) {
        return ret;
    }

    ret = read_response(fd);
    if (ret) {
        return ret;
    }

    return uipcps_disconnect(fd);
}

static int
uipcp_update(struct rinaconf *rc, rina_msg_t update_type, uint16_t ipcp_id)
{
    struct rina_cmsg_uipcp_update req;

    req.msg_type = update_type;
    req.event_id = 0;
    req.ipcp_id = ipcp_id;

    return request_response((struct rina_msg_base *)&req, 0);
}

/* Create an IPC process. */
static struct rina_kmsg_ipcp_create_resp *
rina_ipcp_create(struct rinaconf *rc, unsigned int wait_for_completion,
                 const struct rina_name *name, const char *dif_type,
                 const char *dif_name, int *result)
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
    msg->dif_type = strdup(dif_type);
    msg->dif_name = strdup(dif_name);

    PD("Requesting IPC process creation...\n");

    resp = (struct rina_kmsg_ipcp_create_resp *)
           rinalite_issue_request(&rc->loop, RINALITE_RMB(msg),
                         sizeof(*msg), 1, wait_for_completion, result);

    rinalite_ipcps_fetch(&rc->loop);

    if (strcmp(dif_type, "normal") == 0 && *result == 0 && resp) {
        uipcp_update(rc, RINA_CONF_UIPCP_CREATE, resp->ipcp_id);
    } else {
        uipcp_update(rc, RINA_CONF_UIPCP_UPDATE, 0);
    }

    return resp;
}

static int
ipcp_create(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_kmsg_ipcp_create_resp *kresp;
    const char *ipcp_apn;
    const char *ipcp_api;
    struct rina_name ipcp_name;
    const char *dif_type;
    const char *dif_name;
    int result;
    int i;

    assert(argc >= 4);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];
    dif_type = argv[2];
    dif_name = argv[3];

    rina_name_fill(&ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    kresp = rina_ipcp_create(rc, ~0U, &ipcp_name, dif_type, dif_name, &result);
    if (kresp) {
        rina_msg_free(rina_kernel_numtables, RINALITE_RMB(kresp));
    }

    return result;
}

/* Destroy an IPC process. */
static int
rina_ipcp_destroy(struct rinaconf *rc, unsigned int ipcp_id,
                  const char *dif_type)
{
    struct rina_kmsg_ipcp_destroy *msg;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    if (strcmp(dif_type, "normal") == 0) {
        uipcp_update(rc, RINA_CONF_UIPCP_DESTROY, ipcp_id);
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_DESTROY;
    msg->ipcp_id = ipcp_id;

    PD("Requesting IPC process destruction...\n");

    resp = rinalite_issue_request(&rc->loop, RINALITE_RMB(msg),
                         sizeof(*msg), 0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    rinalite_ipcps_fetch(&rc->loop);

    uipcp_update(rc, RINA_CONF_UIPCP_UPDATE, ipcp_id);

    return result;
}

static int
ipcp_destroy(int argc, char **argv, struct rinaconf *rc)
{
    const char *ipcp_apn;
    const char *ipcp_api;
    struct rina_name ipcp_name;
    struct rinalite_ipcp *rinalite_ipcp;
    int ret = -1;

    assert(argc >= 2);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];

    rina_name_fill(&ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    /* Does the request specifies an existing IPC process ? */
    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&rc->loop, &ipcp_name);
    if (!rinalite_ipcp) {
        PE("%s: No such IPCP process\n", __func__);
    } else {
        /* Valid IPCP id. Forward the request to the kernel. */
        ret = rina_ipcp_destroy(rc, rinalite_ipcp->ipcp_id, rinalite_ipcp->dif_type);
    }

    return ret;
}

static int
rina_ipcp_config(struct rinaconf *rc, uint16_t ipcp_id,
                 const char *param_name, const char *param_value)
{
    struct rina_kmsg_ipcp_config *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_CONFIG;
    req->ipcp_id = ipcp_id;
    req->name = strdup(param_name);
    req->value = strdup(param_value);

    PD("Requesting IPCP config...\n");

    resp = rinalite_issue_request(&rc->loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    if (result == 0 && strcmp(param_name, "address") == 0) {
        /* Fetch after a succesfull address setting operation. */
        rinalite_ipcps_fetch(&rc->loop);
        uipcp_update(rc, RINA_CONF_UIPCP_UPDATE, 0);
    }

    return result;
}

static int
ipcp_config(int argc, char **argv, struct rinaconf *rc)
{
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *param_name;
    const char *param_value;
    struct rina_name ipcp_name;
    struct rinalite_ipcp *rinalite_ipcp;
    int ret = -1;  /* Report failure by default. */

    assert(argc >= 4);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];
    param_name = argv[2];
    param_value = argv[3];

    rina_name_fill(&ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    /* The request specifies an IPCP: lookup that. */
    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&rc->loop, &ipcp_name);
    if (!rinalite_ipcp) {
        PE("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        ret = rina_ipcp_config(rc, rinalite_ipcp->ipcp_id, param_name, param_value);
    }

    return ret;
}

static int
ipcp_register_common(int argc, char **argv, unsigned int reg,
                     struct rinaconf *rc)
{
    struct rina_cmsg_ipcp_register req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *dif_name;
    struct rinalite_ipcp *rinalite_ipcp;

    assert(argc >= 3);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    /* Lookup the id of the registering IPCP. */
    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&rc->loop, &req.ipcp_name);
    if (!rinalite_ipcp) {
        PE("%s: Could not find the IPC process to register\n", __func__);
        return -1;
    }

    req.msg_type = RINA_CONF_IPCP_REGISTER;
    req.event_id = 0;
    req.ipcp_id = rinalite_ipcp->ipcp_id;
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);
    req.reg = reg;

    return request_response((struct rina_msg_base *)&req, 1);
}

static int
ipcp_register(int argc, char **argv, struct rinaconf *rc)
{
    return ipcp_register_common(argc, argv, 1, rc);
}

static int
ipcp_unregister(int argc, char **argv, struct rinaconf *rc)
{
    return ipcp_register_common(argc, argv, 0, rc);
}

static int
ipcp_enroll(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_cmsg_ipcp_enroll req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *neigh_ipcp_apn;
    const char *neigh_ipcp_api;
    const char *dif_name;
    const char *supp_dif_name;
    struct rinalite_ipcp *rinalite_ipcp;

    assert(argc >= 6);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];
    neigh_ipcp_apn = argv[3];
    neigh_ipcp_api = argv[4];
    supp_dif_name = argv[5];

    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&rc->loop, &req.ipcp_name);
    if (!rinalite_ipcp) {
        PE("%s: Could not find enrolling IPC process\n", __func__);
        return -1;
    }

    req.msg_type = RINA_CONF_IPCP_ENROLL;
    req.event_id = 0;
    req.ipcp_id = rinalite_ipcp->ipcp_id;
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);
    rina_name_fill(&req.neigh_ipcp_name, neigh_ipcp_apn, neigh_ipcp_api, NULL, NULL);
    rina_name_fill(&req.supp_dif_name, supp_dif_name, NULL, NULL, NULL);

    return request_response((struct rina_msg_base *)&req, 1);
}

static int
ipcp_dft_set(int argc, char **argv, struct rinaconf *rc)
{
    struct rina_cmsg_ipcp_dft_set req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *appl_apn;
    const char *appl_api;
    unsigned long remote_addr;
    struct rina_name ipcp_name;
    struct rinalite_ipcp *rinalite_ipcp;

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

    rina_name_fill(&ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);
    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&rc->loop, &ipcp_name);
    rina_name_free(&ipcp_name);
    if (!rinalite_ipcp) {
        PE("%s: Could not find IPC process\n", __func__);
        return -1;
    }

    req.msg_type = RINA_CONF_IPCP_DFT_SET;
    req.event_id = 0;
    req.ipcp_id = rinalite_ipcp->ipcp_id;
    rina_name_fill(&req.appl_name, appl_apn, appl_api, NULL, NULL);
    req.remote_addr = remote_addr;

    return request_response((struct rina_msg_base *)&req, 1);
}

static int
ipcps_show(int argc, char **argv, struct rinaconf *rc)
{
    rinalite_ipcps_print(&rc->loop);

    return 0;
}

static int
test(struct rinaconf *rc)
{
    struct rina_name name;
    struct rina_kmsg_ipcp_create_resp *icresp;
    int result;
    int ret;

    /* Create an IPC process of type shim-loopback. */
    rina_name_fill(&name, "test-shim-loopback.IPCP", "1", NULL, NULL);
    icresp = rina_ipcp_create(rc, 0, &name, "shim-loopback",
                              "test-shim-loopback.DIF", &result);
    assert(!icresp);
    rina_name_free(&name);

    rina_name_fill(&name, "test-shim-loopback.IPCP", "2", NULL, NULL);
    icresp = rina_ipcp_create(rc, ~0U, &name, "shim-loopback",
                              "test-shim-loopback.DIF", &result);
    assert(icresp);
    if (icresp) {
        rina_msg_free(rina_kernel_numtables, RINALITE_RMB(icresp));
    }
    icresp = rina_ipcp_create(rc, ~0U, &name, "shim-loopback",
                              "test-shim-loopback.DIF", &result);
    assert(!icresp);
    rina_name_free(&name);

    /* Fetch IPC processes table. */
    rinalite_ipcps_fetch(&rc->loop);

    /* Destroy the IPCPs. */
    ret = rina_ipcp_destroy(rc, 0, "shim-loopback");
    assert(!ret);
    ret = rina_ipcp_destroy(rc, 1, "shim-loopback");
    assert(!ret);
    ret = rina_ipcp_destroy(rc, 0, "shim-loopback");
    assert(ret);

    return 0;
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
        .usage = "IPCP_APN IPCP_API DIF_TYPE DIF_NAME",
        .num_args = 4,
        .func = ipcp_create,
    },
    {
        .name = "ipcp-destroy",
        .usage = "IPCP_APN IPCP_API",
        .num_args = 2,
        .func = ipcp_destroy,
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
    {
        .name = "ipcps-show",
        .usage = "",
        .num_args = 0,
        .func = ipcps_show,
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
    int enable_testing = 0;
    int ret;

    ret = rinalite_evloop_init(&rc.loop, "/dev/rinalite",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

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

    /* Fetch kernel state. */
    rinalite_ipcps_fetch(&rc.loop);

    if (enable_testing) {
        /* Run the hardwired test script. */
        test(&rc);
    }

    ret = process_args(argc, argv, &rc);

    rinalite_evloop_stop(&rc.loop);

    rinalite_evloop_fini(&rc.loop);

    return 0;
}
