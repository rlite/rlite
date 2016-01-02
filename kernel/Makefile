obj-m += rina-ctrl.o
rina-ctrl-y := rina-ctrl-main.o rina-utils.o rina-kernel-numtables.o rina-bufs.o
obj-m += rina-shim-dummy.o
obj-m += rina-shim-hv.o
obj-m += rina-normal.o
rina-shim-hv-y := rina-shim-hv-main.o rina-shim-hv-numtables.o
EXTRA_CFLAGS := -I$(PWD)/include -I$(PWD)/kernel/vmpi

obj-y += vmpi/
