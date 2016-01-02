/*
 * Test program for the librlite-cdap library.
 *
 * Copyright (C) 2016 Vincenzo Maffione <v.maffione@gmail.com>
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

#include <iostream>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>  /* system data type definitions */
#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */

#include "rlite/cdap.hpp"
#include "rlite/utils.h"

using namespace std;

#define TEST_VERSION 132

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
    long obj_inst_cnt = 15;

    if (pipe(pipefds) < 0) {
        perror("pipe()");
        return -1;
    }

    CDAPConn conn(pipefds[0], TEST_VERSION);

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
        CDAPMessage rm;
        int pn;

        /* Read the payload from the socket (put result in bufin). */
        n = recvfrom(ld, bufin, sizeof(bufin), 0,
                (struct sockaddr *)&remote, &addrlen);

        /* Print out the address of the sender. */
        PD("Got a datagram from %s port %d, len %d\n",
                inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), n);

        if (n < 0) {
            perror("recvfrom()");
            continue;
        }

        /* Push the payload in the first end of a pipe. */
        pn = write(pipefds[1], bufin, n);
        if (pn != n) {
            if (pn < 0) {
                perror("write(pipefds[1]");
            } else {
                PE("Partial write(pipefds[1]) %d/%d\n", pn, n);
            }
            continue;
        }

        /* This is a trick to make conn.msg_recv() receive
         * the payload from the pipe. */
        conn.fd = pipefds[0];
        m = conn.msg_recv();

        if (!m) {
            PE("msg_recv()\n");
            continue;
        }

        m->dump();

        /* This is a trick to make conn.msg_send() write the response
         * CDAP message into the pipe. */
        conn.fd = pipefds[1];

        switch (m->op_code) {
            case gpb::M_CONNECT:
                rm.m_connect_r(m, 0, string());
                break;

            case gpb::M_RELEASE:
                rm.m_release_r(gpb::F_NO_FLAGS, 0, string());
                break;

            case gpb::M_CREATE:
                rm.m_create_r(gpb::F_NO_FLAGS, m->obj_class,
                                m->obj_name, obj_inst_cnt++,
                                0, string());
                break;

            case gpb::M_DELETE:
                rm.m_delete_r(gpb::F_NO_FLAGS, m->obj_class,
                                m->obj_name, m->obj_inst,
                                0, string());
                break;

            case gpb::M_READ:
                rm.m_read_r(gpb::F_NO_FLAGS, m->obj_class,
                                m->obj_name, m->obj_inst,
                                0, string());
                break;

            case gpb::M_WRITE:
                rm.m_write_r(gpb::F_NO_FLAGS, 0, string());
                break;

            case gpb::M_START:
                rm.m_start_r(gpb::F_NO_FLAGS, 0, string());
                break;

            case gpb::M_STOP:
                rm.m_stop_r(gpb::F_NO_FLAGS, 0, string());
                break;

            default:
                PE("Unmanaged op_code %d\n", m->op_code);
                break;
        }

        conn.msg_send(&rm, m->invoke_id);

        /* Read the response from the pipe into bufin. */
        n = read(pipefds[0], bufin, sizeof(bufin));
        if (n < 0) {
            perror("read()");
            break;
        }

        /* Send the response to the socket. */
        k = sendto(ld, bufin, n, 0, (struct sockaddr *)&remote, addrlen);
        if (k < 0) {
            perror("sendto()");
            continue;
        }

        if (k != n) {
            PE("Partial write %d/%d\n", (int)k, (int)n);
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
    struct CDAPMessage req;
    struct CDAPMessage *m;

    av.name = "George";
    av.password = "Washington";

    rina_name_fill(&local_appl, "Dulles", "1", NULL, NULL);
    rina_name_fill(&remote_appl, "London", "1", NULL, NULL);

    if (req.m_connect(gpb::AUTH_NONE,
                      &av, &local_appl, &remote_appl) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
client_create_some(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;

    if (req.m_create(gpb::F_NO_FLAGS,
                     "class_A", "x", 0, 0, string()) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
client_write_some(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;
    char buf[10];

    req.m_write(gpb::F_NO_FLAGS, "class_A", "x", 0, 0, string());
    req.set_obj_value(18);
    if(conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    req.m_write(gpb::F_NO_FLAGS, "class_B", "y", 0, 0, string());
    req.set_obj_value("ciccio");
    if (conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    req.m_write(gpb::F_NO_FLAGS, "class_C", "z", 0, 0, string());
    for (unsigned int i = 0; i < sizeof(buf); i++) {
        buf[i] = '0' + i;
    }
    req.set_obj_value(buf, sizeof(buf));
    if (conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    for (int i = 0; i < 3; i++) {
        m = conn->msg_recv();
        if (!m) {
            PE("Error receiving CDAP response\n");
            return -1;
        }

        m->dump();
    }

    return 0;
}

static int
client_read_some(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;

    if (req.m_read(gpb::F_NO_FLAGS,
                    "class_A", "x", 0, 0, string()) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
client_startstop_some(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;

    if (req.m_start(gpb::F_NO_FLAGS,
                    "class_A", "x", 0, 0, string()) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    if (req.m_stop(gpb::F_NO_FLAGS,
                   "class_A", "x", 0, 0, string()) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
client_delete_some(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;

    if (req.m_delete(gpb::F_NO_FLAGS,
                     "class_A", "x", 0, 0, string()) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
client_disconnect(CDAPConn *conn)
{
    struct CDAPMessage req;
    struct CDAPMessage *m;

    if (req.m_release(gpb::F_NO_FLAGS) ||
            conn->msg_send(&req, 0)) {
        PE("Failed to send CDAP message\n");
    }

    m = conn->msg_recv();
    if (!m) {
        PE("Error receiving CDAP response\n");
        return -1;
    }

    m->dump();

    return 0;
}

static int
test_cdap_client(int port)
{
    struct sockaddr_in server;
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

    CDAPConn conn(sk, TEST_VERSION);

    client_connect(&conn);

    client_create_some(&conn);
    client_write_some(&conn);
    client_read_some(&conn);
    client_startstop_some(&conn);
    client_delete_some(&conn);

    client_disconnect(&conn);

    close(sk);

    return 0;
}

void
usage()
{
    PI("CDAP test program\n");
    PI("    ./test-cdap [-l]\n");
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
