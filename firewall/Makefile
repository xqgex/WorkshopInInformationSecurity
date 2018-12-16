TARGET = firewall
OBJS = fw.o
OBJS += sysfs.o

CURRENT = $(shell uname -r)
KERNELDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)

obj-m += $(TARGET).o

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

$(TARGET).o: fw.o sysfs.o
	$(LD) $(LD_RFLAG) -r -o $@ $(OBJS)

clean:
	-rm -f *.o *.ko
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
