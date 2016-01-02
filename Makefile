CC=gcc
CFLAGS=-Wall -Werror
CFLAGS += -I$(PWD)/include
LDFLAGS += -lpthread
EXES=user/ipcm user/application

KER=`uname -r`

all: $(EXES) ker

ker:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel modules

user/ipcm: user/ipcm.o user/pending_queue.o user/rina-utils.o

user/ipcm.o: include/rina/rina-ctrl.h user/pending_queue.h

user/pending_queue.o: user/pending_queue.h

user/application: user/application.o

user/rina-utils.o: include/rina/rina-utils.h include/rina/rina-ctrl.h

clean:
	-rm user/*.o
	-rm $(EXES)
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel clean
