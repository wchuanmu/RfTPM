
DRIVER = ftpm-driver.ko

ifneq ($(KERNELRELEASE),)
	ftpm-driver-y := \
		ftpm.o \
		ftpm-ioctl.o \
	  ftpm-sbi.o
	obj-m += ftpm-driver.o




PWD := $(shell pwd)
LINUXSRC := $(PWD)/../linuxs



all:
	$(MAKE) -C $(LINUXSRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD)

endif

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
