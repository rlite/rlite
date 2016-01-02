KER=`uname -r`

all: userspace kernelspace

userspace:
	-mkdir build &> /dev/null;	\
	cd build; 			\
	cmake ..;			\
	make

kernelspace:
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel modules

count:
	find kernel user include -type f -and \( -name "*.c" -or -name "*.h" \) | grep -v vmpi | xargs wc -l

clean:
	-rm -rf build
	make -C /usr/lib/modules/$(KER)/build M=$(PWD)/kernel clean
