CC=gcc
CFLAGS=-Wall -Werror -g -O2
CFLAGS += -I$(PWD)/include
LDFLAGS = -lpthread
EXES=user/uipcp-server user/rina-config user/rinaperf
HEADERS=$(shell find include/rina)

KER=`uname -r`

all: $(EXES) ker

ker:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel modules

user/uipcp-server: user/uipcp-server.o user/pending_queue.o user/rina-utils.o user/rina-kernel-numtables.o user/rina-conf-numtables.o user/helpers.o user/evloop.o user/application.o user/uipcp.o

user/uipcp-server.o:  $(HEADERS) user/pending_queue.h user/helpers.h user/evloop.h user/application.h user/uipcp-server.h

user/uipcp.o: $(HEADERS) user/uipcp-server.h

user/pending_queue.o: $(HEADERS) user/pending_queue.h

user/evloop.o: $(HEADERS) user/evloop.h user/pending_queue.h

user/rina-config: user/rina-config.o user/rina-conf-numtables.o user/rina-utils.o user/helpers.o user/evloop.o user/rina-kernel-numtables.o user/pending_queue.o

user/rina-config.o: $(HEADERS)

user/rina-utils.o: $(HEADERS)

user/helpers.o: $(HEADERS) user/helpers.h

user/rinaperf: user/rinaperf.o user/application.o user/pending_queue.o user/rina-utils.o user/rina-kernel-numtables.o user/evloop.o

user/application.o: $(HEADERS) user/pending_queue.h user/evloop.h

user/rinaperf.o: $(HEADERS) user/application.h

count:
	find . -type f -and \( -name "*.c" -or -name "*.h" \) | grep -v vmpi | xargs wc -l

test:
	(./unprepare.sh || true; ./prepare.sh && user/uipcp-server -t)

clean:
	-rm user/*.o
	-rm $(EXES)
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel clean
