CC=gcc
CFLAGS=-Wall -Werror
CFLAGS += -I$(PWD)/../include
LDFLAGS += -lpthread
EXES=ipcm

all: $(EXES)

ipcm: ipcm.o pending_queue.o

ipcm.o: $(PWD)/../include/rina/rina-ctrl.h pending_queue.h

pending_queue.o: pending_queue.h

clean:
	-rm *.o
	-rm $(EXES)
