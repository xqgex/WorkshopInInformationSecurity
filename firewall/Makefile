CURRENT = $(shell uname -r)
KERNELDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)

obj-m := firewall.o
firewall-objs := sysfs.o fw.o
OBJS = sysfs.o fw.o

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

$(TARGET).o: fw.o sysfs.o
	$(LD) $(LD_RFLAG) -r -o $@ $(OBJS)

clean:
	-rm -f *.o *.ko
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
