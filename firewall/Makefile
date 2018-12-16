MODULE_NAME = firewall

SRC     := fw.c sysfs.c

$(MODULE_NAME)-objs = $(SRC:.c=.o)
#firewall-objs := fw.o

obj-m := $(MODULE_NAME).o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
