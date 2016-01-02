#include <iostream>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>  /* system data type definitions */
#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */

#include "cdap.hpp"

using namespace std;


static int
test_cdap_server(int port)
{
    struct sockaddr_in skaddr;
    socklen_t addrlen;
    char bufin[4096];
    struct sockaddr_in remote;
    struct CDAPMessage *m;
    int pipefds[2];
    int one = 1;
    int ld;
    int n;

    if (pipe(pipefds) < 0) {
        perror("pipe()");
        return -1;
    }

    if ((ld = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    if (setsockopt(ld, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt()");
        return -1;
    }

    skaddr.sin_family = AF_INET;
    skaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    skaddr.sin_port = htons(port);

    if (bind(ld, (struct sockaddr *)&skaddr, sizeof(skaddr)) < 0) {
        perror("bind()");
        return -1;
    }

    addrlen = sizeof(remote);

    while (1) {
        /* read a datagram from the socket (put result in bufin) */
        n = recvfrom(ld, bufin, sizeof(bufin), 0,
                (struct sockaddr *)&remote, &addrlen);

        /* print out the address of the sender */
        PD("Got a datagram from %s port %d, len %d\n",
                inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), n);

        if (n < 0) {
            perror("recvfrom()");
            continue;
        }

        write(pipefds[1], bufin, n);

        m = cdap_msg_recv(pipefds[0]);

        if (!m) {
            PE("%s: cdap_msg_recv()");
            continue;
        }

        PD("%s: CDAP message received\n", __func__);
        m->print();
    }

    return 0;
}

static int
test_cdap_client(int port)
{
    struct CDAPMessage m(gpb::M_CONNECT);
    struct sockaddr_in server;
    int buf_len;
    int sk;

    if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(port);

    if (connect(sk, (struct sockaddr *)&server,
                (socklen_t)(sizeof(server))) < 0) {
        perror("connect()");
        return -1;
    }

    if (cdap_msg_send(&m, sk)) {
        PE("%s: Failed to send CDAP message\n", __func__);
    }

    PD("CDAP message sent\n");
    m.print();

    close(sk);

    return 0;
}

void
usage()
{
    PI("cdap test program");
}

int main(int argc, char **argv)
{
    int port = 23872;
    int listen;
    int opt;

    while ((opt = getopt(argc, argv, "hlp:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'l':
                listen = 1;
                break;

            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port >= 65535) {
                    PE("    Invalid port number\n");
                    return -1;
                }
                break;

            default:
                PE("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    if (listen) {
        test_cdap_server(port);
    } else {
        test_cdap_client(port);
    }

    return 0;
}
