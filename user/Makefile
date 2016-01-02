CC=gcc
CFLAGS=-Wall -Werror
CFLAGS += -I$(PWD)/../include
LDFLAGS += -lpthread
EXES=ipcm

all: $(EXES)

ipcm: ipcm.o

ipcm.o: $(PWD)/../include/rina/rina-ctrl.h

clean:
	-rm *.o
	-rm $(EXES)
