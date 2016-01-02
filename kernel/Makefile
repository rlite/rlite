obj-m += rina-ctrl.o
EXTRA_CFLAGS := -I$(PWD)/../include

KER=`uname -r`

all:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) modules

clean:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) clean
