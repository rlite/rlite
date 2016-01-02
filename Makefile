CC=gcc
CFLAGS=-Wall -Werror -g
CFLAGS += -I$(PWD)/include
LDFLAGS += -lpthread
EXES=user/ipcm user/rina-config user/application
HEADERS=$(shell find include/rina)

KER=`uname -r`

all: $(EXES) ker

ker:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel modules

user/ipcm: user/ipcm.o user/pending_queue.o user/rina-utils.o user/rina-kernel-numtables.o user/rina-application-numtables.o user/helpers.o user/evloop.o

user/ipcm.o:  $(HEADERS) user/pending_queue.h user/helpers.h user/evloop.h

user/pending_queue.o: $(HEADERS) user/pending_queue.h

user/evloop.o: $(HEADERS) user/evloop.h user/pending_queue.h

user/rina-config: user/rina-config.o user/rina-application-numtables.o user/rina-utils.o user/helpers.o

user/rina-config.o: $(HEADERS)

user/rina-utils.o: $(HEADERS)

user/helpers.o: $(HEADERS) user/helpers.h

user/application: user/application.o user/pending_queue.o user/rina-utils.o user/rina-kernel-numtables.o user/evloop.o

user/application.o: $(HEADERS) user/pending_queue.h user/evloop.h

clean:
	-rm user/*.o
	-rm $(EXES)
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel clean
