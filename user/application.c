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

#include <rina/rina-application-msg.h>
#include "helpers.h"


#define UNIX_DOMAIN_SOCKNAME    "/home/vmaffione/unix"

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

static int application_register(int sfd)
{
    struct rina_amsg_register msg;
    int ret;

    msg.msg_type = RINA_APPL_REGISTER;
    msg.event_id = 0;
    rina_name_fill(&msg.application_name, "echo", "1", NULL, NULL);
    rina_name_fill(&msg.dif_name, "test-shim-dummy.DIF", NULL, NULL, NULL);

    ret = rina_msg_write(sfd, (struct rina_msg_base *)&msg);
    if (ret) {
        return ret;
    }

    return read_response(sfd);
}

static int application_unregister(int sfd)
{
    return 0;
}

static void
sigint_handler(int signum)
{
    exit(EXIT_SUCCESS);
}

int main()
{
    struct sockaddr_un server_address;
    struct sigaction sa;
    int ret;
    int sfd;

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

    /* Open a Unix domain socket towards the IPCM. */
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, UNIX_DOMAIN_SOCKNAME,
            sizeof(server_address.sun_path) - 1);
    ret = connect(sfd, (struct sockaddr *)&server_address,
                    sizeof(server_address));
    if (ret) {
        perror("bind(AF_UNIX, path)");
        exit(EXIT_FAILURE);
    }

    application_register(sfd);
    application_unregister(sfd);

    close(sfd);

    return 0;
}
