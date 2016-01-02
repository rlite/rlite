obj-m += rina-ctrl.o
rina-ctrl-y := rina-ctrl-main.o rinalite-utils.o rina-kernel-numtables.o rina-bufs.o rina-efcp.o
obj-m += rina-shim-loopback.o
obj-m += rina-shim-hv.o
rina-shim-hv-y := rina-shim-hv-main.o rina-shim-hv-numtables.o
obj-m += rina-shim-eth.o
obj-m += rina-normal.o
EXTRA_CFLAGS := -I$(PWD)/include -I$(PWD)/kernel/vmpi

obj-y += vmpi/
