#obj-m += hello.o

MODULE := main_aes_gcm.ko

obj-m := main_aes_gcm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load: 
	sudo insmod $(MODULE)

unload:
	sudo rmmod $(MODULE)
