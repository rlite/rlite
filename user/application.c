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


#define UNIX_DOMAIN_SOCKNAME    "/home/vmaffione/unix"

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

    /* Open a Unix domain socket to listen to. */
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

    printf("Connected\n");

    close(sfd);

    return 0;
}
