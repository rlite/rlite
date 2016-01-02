#!/usr/bin/env python

import socket
import sys
import argparse


def python2():
    return sys.version_info[0] <= 2


def socket_send_string(sock, s):
    if python2():
        sock.send(s)
    else:
        sock.send(bytes(s, 'ascii'))


def socket_recv_string(sock):
    data = sock.recv(4096)
    if python2():
        return data

    return data.decode('ascii')


def server(args):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (args.address, args.port)
    print('starting up on %s port %s' % server_address)
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(10)

    while True:
        # Wait for a connection
        print(sys.stderr, 'waiting for a connection')
        connection, client_address = sock.accept()

        try:
            print('connection from', client_address)

            # Receive the data in small chunks and retransmit it
            while True:
                data = socket_recv_string(connection)
                if not data:
                    print('no more data from', client_address)
                    break

                print('received "%s"' % data)
                print('sending data back to the client')
                socket_send_string(connection, data)

        finally:
            # Clean up the connection
            connection.close()


def client(args):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.address, args.port)
    print('connecting to %s port %s' % server_address)
    sock.connect(server_address)

    try:

        # Send data
        message = 'Hello guys, this is a test message!'
        print('sending "%s"' % message)
        socket_send_string(sock, message)

        # Look for the response
        amount_received = 0
        amount_expected = len(message)

        while amount_received < amount_expected:
            data = socket_recv_string(sock)
            amount_received += len(data)
            print('received "%s"' % data)

    finally:
        print('closing socket')
        sock.close()



description = "TCP echo client/server"
epilog = "2015 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-a', '--address', help = "IP address (destination or bind)",
                       type = str, default = "127.0.0.1")
argparser.add_argument('-p', '--port',
                       help = "TCP port (destination or bind)",
                       type = int, default = 10000)
argparser.add_argument('-l', '--listen', dest = 'server_mode',
                       action='store_true',
                       help = "Run in server mode")

args = argparser.parse_args()

try:
    if args.server_mode:
        server(args)
    else:
        client(args)
except KeyboardInterrupt:
    pass
except:
    print("Uncaught exception. Bye.")
    pass
