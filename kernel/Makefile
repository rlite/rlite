obj-m += rina-ctrl.o
rina-ctrl-y := rina-ctrl-main.o rina-utils.o
EXTRA_CFLAGS := -I$(PWD)/../include

KER=`uname -r`

all:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) modules

clean:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) clean
