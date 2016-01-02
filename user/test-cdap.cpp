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
#include "rinalite/rinalite-utils.h"

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
    int n, k;

    if (pipe(pipefds) < 0) {
        perror("pipe()");
        return -1;
    }

    CDAPConn conn(pipefds[0]);

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

        conn.fd = pipefds[0]; /* This is just a trick. */
        m = conn.msg_recv();

        if (!m) {
            PE("%s: msg_recv()");
            continue;
        }

        PD("%s: CDAP message received\n", __func__);
        m->print();

        conn.fd = pipefds[1];  /* This is just a trick. */

        switch (m->op_code) {
            case gpb::M_CONNECT:
                conn.m_connect_r_send(m, 0, string());
                break;

            case gpb::M_RELEASE:
                conn.m_release_r_send(m, gpb::F_NO_FLAGS, 0, string());
                break;

            default:
                PE("Unmanaged op_code %d\n", m->op_code);
                break;
        }

        n = read(pipefds[0], bufin, sizeof(bufin));
        if (n < 0) {
            perror("read()");
            break;
        }

        k = sendto(ld, bufin, n, 0, (struct sockaddr *)&remote, addrlen);
        if (k < 0) {
            perror("sendto()");
            continue;
        }

        if (k != n) {
            PE("%s: Partial write %d/%d\n", __func__, m, n);
        }
    }

    return 0;
}

static int
client_connect(CDAPConn *conn)
{
    struct CDAPAuthValue av;
    struct rina_name local_appl;
    struct rina_name remote_appl;
    struct CDAPMessage *m;
    int invoke_id;

    av.name = "George";
    av.password = "Washington";

    rina_name_fill(&local_appl, "Dulles", "1", NULL, NULL);
    rina_name_fill(&remote_appl, "London", "1", NULL, NULL);

    if (conn->m_connect_send(&invoke_id, gpb::AUTH_NONE,
                            &av, &local_appl, &remote_appl)) {
        PE("%s: Failed to send CDAP message\n", __func__);
    }

    m = conn->msg_recv();
    if (!m) {
        PE("%s: Error receiving CDAP response\n", __func__);
        return -1;
    }

    m->print();

    return 0;
}

static int
client_disconnect(CDAPConn *conn)
{
    struct CDAPMessage *m;
    int invoke_id;

    if (conn->m_release_send(&invoke_id, gpb::F_NO_FLAGS)) {
        PE("%s: Failed to send CDAP message\n", __func__);
    }

    m = conn->msg_recv();
    if (!m) {
        PE("%s: Error receiving CDAP response\n", __func__);
        return -1;
    }

    m->print();

    return 0;
}

static int
test_cdap_client(int port)
{
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

    CDAPConn conn(sk);

    client_connect(&conn);

    client_disconnect(&conn);

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
