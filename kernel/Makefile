obj-m += rinalite.o
rinalite-y := rinalite-main.o rinalite-utils.o rina-kernel-numtables.o rina-bufs.o rina-efcp.o

obj-m += rinalite-shim-loopback.o
rinalite-shim-loopback-y := shim-loopback.o

obj-m += rinalite-shim-hv.o
rinalite-shim-hv-y := shim-hv.o shim-hv-numtables.o

obj-m += rinalite-shim-eth.o
rinalite-shim-eth-y := shim-eth.o

obj-m += rinalite-normal.o
rinalite-normal-y := normal.o

EXTRA_CFLAGS := -I$(PWD)/include -I$(PWD)/kernel/vmpi

obj-y += vmpi/
