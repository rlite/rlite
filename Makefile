obj-m += rina-ctrl.o

KER=`uname -r`

all:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) modules

clean:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD) clean
