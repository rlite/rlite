obj-m += rlite.o
rlite-y := ctrl-dev.o io-dev.o utils.o ker-numtables.o bufs.o efcp-utils.o

obj-m += rlite-shim-loopback.o
rlite-shim-loopback-y := shim-loopback.o

obj-m += rlite-shim-eth.o
rlite-shim-eth-y := shim-eth.o

obj-m += rlite-normal.o
rlite-normal-y := normal.o

obj-m += rlite-shim-inet4.o
rlite-shim-inet4-y := shim-inet4.o

EXTRA_CFLAGS := -I$(PWD)/include

ifeq ($(HAVE_VMPI),y)
obj-m += rlite-shim-hv.o
rlite-shim-hv-y := shim-hv.o shim-hv-numtables.o

EXTRA_CFLAGS += -I\$(PWD)/kernel/vmpi

obj-y += vmpi/
endif
