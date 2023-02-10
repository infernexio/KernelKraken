obj-m := KernalKraken.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod popcorn.ko
	sudo lsmod | grep popcorn
	sudo rmmod popcorn.ko
	dmesg

install:
	sudo dmesg -C
	sudo insmod popcorn.ko

purge:
	sudo rmmod popcorn.ko
	dmesg