#!/bin/bash

set -x

swig -I../../include/ -python rlite.i
gcc -fPIC -I ../../include/ -I /usr/include/python2.7/ -c rlite_wrap.c
gcc -fPIC -I ../../include/ -c utils.c
gcc -fPIC -I ../../include/ -c ctrl.c
gcc -fPIC -I ../../include/ -c ker-numtables.c
gcc -fPIC -I ../../include/ -c conf-numtables.c
gcc -shared -o _rlite.so utils.o ctrl.o ker-numtables.o conf-numtables.o rlite_wrap.o
