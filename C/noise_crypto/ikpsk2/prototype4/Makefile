obj-m += ikpsk2_crypto.o
ikpsk2_crypto-y := module.o handshake.o noise_crypto.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
