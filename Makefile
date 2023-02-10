obj-m := KernalKraken.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod KernalKraken.ko
	sudo lsmod | grep KernalKraken
	sudo rmmod KernalKraken.ko
	dmesg

install:
	sudo dmesg -C
	sudo insmod KernalKraken.ko

purge:
	sudo rmmod KernalKraken.ko
	dmesg