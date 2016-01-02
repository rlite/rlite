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


static void usage(void);

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
        printf("%s: read() error [%d]\n", __func__, n);
        return -1;
    }

    ret = deserialize_rina_msg(rina_application_numtables, serbuf,
                               n, msgbuf, sizeof(msgbuf));
    if (ret) {
        printf("%s: error while deserializing response [%d]\n",
                __func__, ret);
        return -1;
    }

    resp = (struct rina_msg_base_resp *)msgbuf;
    ret = (resp->result) == 0 ? 0 : -1;

    printf("IPCM response [type=%u] --> %d\n", resp->msg_type, ret);

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

static int ipcp_create(int argc, char **argv)
{
    struct rina_amsg_ipcp_create req;
    const char *ipcp_apn;
    const char *ipcp_api;
    int i;

    assert(argc >= 3);
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    req.msg_type = RINA_APPL_IPCP_CREATE;
    req.event_id = 0;
    req.dif_type = DIF_TYPE_MAX;
    for (i = 0; i < DIF_TYPE_MAX; i++) {
        assert(dif_types[i]);
        if (strcmp(argv[0], dif_types[i]) == 0) {
            req.dif_type = i;
            break;
        }
    }
    if (req.dif_type == DIF_TYPE_MAX) {
        /* No such dif type. Print the available types
         * and exit. */
        printf("No such dif type. Available DIF types:\n");
        for (i = 0; i < DIF_TYPE_MAX; i++) {
            printf("    %s\n", dif_types[i]);
        }
        return -1;
    }
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

static int ipcp_destroy(int argc, char **argv)
{
    struct rina_amsg_ipcp_destroy req;
    const char *ipcp_apn;
    const char *ipcp_api;

    assert(argc >= 2);
    ipcp_apn = argv[0];
    ipcp_api = argv[1];

    req.msg_type = RINA_APPL_IPCP_DESTROY;
    req.event_id = 0;
    rina_name_fill(&req.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

static int assign_to_dif(int argc, char **argv)
{
    struct rina_amsg_assign_to_dif req;
    const char *ipcp_apn;
    const char *ipcp_api;
    const char *dif_name;

    assert(argc >= 3);
    dif_name = argv[0];
    ipcp_apn = argv[1];
    ipcp_api = argv[2];

    req.msg_type = RINA_APPL_ASSIGN_TO_DIF;
    req.event_id = 0;
    rina_name_fill(&req.application_name, ipcp_apn, ipcp_api, NULL, NULL);
    rina_name_fill(&req.dif_name, dif_name, NULL, NULL, NULL);

    return request_response((struct rina_msg_base *)&req);
}

struct cmd_descriptor {
    const char *name;
    const char *usage;
    unsigned int num_args;
    int (*func)(int argc, char **argv);
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
};

#define NUM_COMMANDS    (sizeof(cmd_descriptors)/sizeof(struct cmd_descriptor))

static void
usage(void)
{
    int i;

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
        /* No command. */
        usage();
        return -1;
    }

    cmd = argv[1];

    for (i = 0; i < NUM_COMMANDS; i++) {
        if (strcmp(cmd, cmd_descriptors[i].name) == 0) {
            assert(cmd_descriptors[i].func);

            if (argc - 2 < cmd_descriptors[i].num_args) {
                /* Not enough arguments. */
                printf("Not enough arguments\n");
                usage();
                return -1;
            }

            return cmd_descriptors[i].func(argc - 2, argv + 2);
        }
    }

    printf("Unknown command '%s'\n", cmd);
    usage();

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

    return process_args(argc, argv);
}
