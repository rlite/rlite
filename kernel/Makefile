obj-m += rlite.o
rlite-y := ctrl-dev.o io-dev.o utils.o ker-numtables.o bufs.o efcp-utils.o

obj-m += rlite-shim-loopback.o
rlite-shim-loopback-y := shim-loopback.o

obj-m += rlite-shim-eth.o
rlite-shim-eth-y := shim-eth.o

obj-m += rlite-normal.o
rlite-normal-y := normal.o

obj-m += rlite-shim-tcp4.o
rlite-shim-tcp4-y := shim-tcp4.o

# PWD must be the kernel/ directory
EXTRA_CFLAGS := -I$(PWD)/../include

ifeq ($(HAVE_VMPI),y)
obj-m += rlite-shim-hv.o
rlite-shim-hv-y := shim-hv.o shim-hv-numtables.o

EXTRA_CFLAGS += -I\$(PWD)/vmpi

obj-y += vmpi/
endif
