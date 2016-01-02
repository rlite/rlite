CC=gcc
CFLAGS=-Wall -Werror -g
CFLAGS += -I$(PWD)/include
LDFLAGS += -lpthread
EXES=user/ipcm user/application
HEADERS=$(shell find include/rina)

KER=`uname -r`

all: $(EXES) ker

ker:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel modules

user/ipcm: user/ipcm.o user/pending_queue.o user/rina-utils.o user/rina-kernel-numtables.o user/rina-application-numtables.o user/helpers.o

user/ipcm.o:  $(HEADERS) user/pending_queue.h user/helpers.h

user/pending_queue.o: $(HEADERS) user/pending_queue.h

user/application: user/application.o user/rina-application-numtables.o user/rina-utils.o user/helpers.o

user/rina-utils.o: $(HEADERS)

user/helpers.o: $(HEADERS) user/helpers.h

clean:
	-rm user/*.o
	-rm $(EXES)
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel clean
