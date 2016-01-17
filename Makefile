-include kconfig/.config
-include config.mk

ifeq ($(FRESH),y)
  CFLAGS+=-DCONFIG_FRESH=1
endif

ifeq ($(SCSH),y)
  CFLAGS+=-DCONFIG_SCSH=1
endif

ifeq ($(PRODCONS),y)
  CFLAGS+=-DCONFIG_PRODCONS=1
endif

ifeq ($(IDDLELEDS),y)
    CFLAGS += -DCONFIG_IDDLELEDS=1
endif

CROSS_COMPILE?=arm-none-eabi-
CC:=$(CROSS_COMPILE)gcc
AS:=$(CROSS_COMPILE)as
AR:=$(CROSS_COMPILE)ar
CFLAGS+=-mthumb -mlittle-endian -mthumb-interwork -DCORE_M3 -fno-builtin -ffreestanding -DKLOG_LEVEL=6 -DSYS_CLOCK=$(SYS_CLOCK)
CFLAGS+=-Ikernel/libopencm3/include -Ikernel -Iinclude -Inewlb/include
PREFIX:=$(PWD)/build
LDFLAGS:=-gc-sections -nostartfiles -ggdb -L$(PREFIX)/lib 

#debugging
CFLAGS+=-ggdb

#optimization
#CFLAGS+=-Os

ASFLAGS:=-mcpu=cortex-m3 -mthumb -mlittle-endian -mthumb-interwork -ggdb
APPS-y:= apps/init.o 
APPS-$(FRESH)+=apps/fresh.o apps/binutils.o apps/stubs.o


OBJS-y:=kernel/systick.o kernel/drivers/device.o

# device drivers 
OBJS-$(MEMFS)+= kernel/drivers/memfs.o
OBJS-$(XIPFS)+= kernel/drivers/xipfs.o
CFLAGS-$(MEMFS)+=-DCONFIG_MEMFS

OBJS-$(SYSFS)+= kernel/drivers/sysfs.o
CFLAGS-$(SYSFS)+=-DCONFIG_SYSFS

OBJS-$(DEVNULL)+= kernel/drivers/null.o
CFLAGS-$(DEVNULL)+=-DCONFIG_DEVNULL



OBJS-$(SOCK_UNIX)+= kernel/drivers/socket_un.o
CFLAGS-$(SOCK_UNIX)+=-DCONFIG_SOCK_UNIX

OBJS-$(DEVL3GD20)+= kernel/drivers/l3gd20.o
CFLAGS-$(DEVL3GD20)+=-DCONFIG_DEVL3GD20

OBJS-$(DEVLSM303DLHC)+= kernel/drivers/lsm303dlhc.o
CFLAGS-$(DEVLSM303DLHC)+=-DCONFIG_DEVLSM303DLHC

OBJS-$(DEVSPI)+= kernel/drivers/spi.o
CFLAGS-$(DEVSPI)+=-DCONFIG_DEVSPI

OBJS-$(DEVF4I2C)+= kernel/drivers/stm32f4_i2c.o
CFLAGS-$(DEVF4I2C)+=-DCONFIG_DEVI2C

OBJS-$(DEVUART)+= kernel/drivers/uart.o
CFLAGS-$(DEVUART)+=-DCONFIG_DEVUART

OBJS-$(DEVGPIO)+=kernel/drivers/gpio.o
CFLAGS-$(DEVGPIO)+=-DCONFIG_DEVGPIO

OBJS-$(DEVF4EXTI)+=kernel/drivers/stm32f4_exti.o
CFLAGS-$(DEVF4EXTI)+=-DCONFIG_DEVF4EXTI

OBJS-$(DEVADC)+=kernel/drivers/adc.o
CFLAGS-$(DEVADC)+=-DCONFIG_DEVADC

OBJS-$(DEVRNG)+=kernel/drivers/random.o
CFLAGS-$(DEVRNG)+=-DCONFIG_RNG

OBJS-$(MACH_STM32F407Discovery)+=kernel/$(BOARD)/stm32f407discovery.o 
OBJS-$(MACH_STM32F405Pyboard)+=kernel/$(BOARD)/stm32f405pyboard.o 
OBJS-$(MACH_STM32F4x1Discovery)+=kernel/$(BOARD)/stm32f4x1discovery.o 
OBJS-$(MACH_STM32F429Discovery)+=kernel/$(BOARD)/stm32f429discovery.o 
OBJS-$(MACH_LPC1768MBED)+=kernel/$(BOARD)/lpc1768mbed.o
OBJS-$(MACH_SEEEDPRO)+=kernel/$(BOARD)/lpc1768mbed.o
OBJS-$(MACH_LPC1679XPRESSO)+=kernel/$(BOARD)/lpc1769xpresso.o
OBJS-$(MACH_LM3S6965EVB)+=kernel/$(BOARD)/lm3s6965evb.o

CFLAGS+=$(CFLAGS-y)

SHELL=/bin/bash
APPS_START = 0x20000
PADTO = $$(($(FLASH_ORIGIN)+$(APPS_START)))

include net/tcpip/Makefile
all: image.bin tools/xipfstool

kernel/syscall_table.c: kernel/syscall_table_gen.py
	python2 $^


include/syscall_table.h: kernel/syscall_table.c

.PHONY: FORCE

$(PREFIX)/lib/libkernel.a: FORCE
	make -C kernel

$(PREFIX)/lib/libfrosted.a: FORCE
	make -C libfrosted

tools/xipfstool: tools/xipfs.c
	make -C tools

image.bin: kernel.elf apps.elf
	export PADTO=`python2 -c "print ( $(KFLASHMEM_SIZE) * 1024) + int('$(FLASH_ORIGIN)', 16)"`;	\
	$(CROSS_COMPILE)objcopy -O binary --pad-to=$$PADTO kernel.elf $@
	$(CROSS_COMPILE)objcopy -O binary --pad-to=0x40000 apps.elf apps.bin
	cat apps.bin >> $@
	#cat apps/apps.bflt >> $@

apps/apps.ld: apps/apps.ld.in
	export KMEM_SIZE_B=`python2 -c "print '0x%X' % ( $(KFLASHMEM_SIZE) * 1024)"`;	\
	export AMEM_SIZE_B=`python2 -c "print '0x%X' % ( ($(RAM_SIZE) - $(KRAMMEM_SIZE)) * 1024)"`;	\
	export KFLASHMEM_SIZE_B=`python2 -c "print '0x%X' % ( $(KFLASHMEM_SIZE) * 1024)"`;	\
	export AFLASHMEM_SIZE_B=`python2 -c "print '0x%X' % ( ($(FLASH_SIZE) - $(KFLASHMEM_SIZE)) * 1024)"`;	\
	export KRAMMEM_SIZE_B=`python2 -c "print '0x%X' % ( $(KRAMMEM_SIZE) * 1024)"`;	\
	cat $^ | sed -e "s/__FLASH_ORIGIN/$(FLASH_ORIGIN)/g" | \
			 sed -e "s/__KFLASHMEM_SIZE/$$KFLASHMEM_SIZE_B/g" | \
			 sed -e "s/__AFLASHMEM_SIZE/$$AFLASHMEM_SIZE_B/g" | \
			 sed -e "s/__RAM_BASE/$(RAM_BASE)/g" |\
			 sed -e "s/__KRAMMEM_SIZE/$$KRAMMEM_SIZE_B/g" |\
			 sed -e "s/__AMEM_SIZE/$$AMEM_SIZE_B/g" \
			 >$@


apps.elf: $(PREFIX)/lib/libfrosted.a $(APPS-y) apps/apps.ld
	$(CC) -o $@  $(APPS-y) -Tapps/apps.ld -lfrosted -lc -lfrosted -Wl,-Map,apps.map  $(LDFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)

kernel/libopencm3/lib/libopencm3_$(BOARD).a:
	make -C kernel/libopencm3 $(OPENCM3FLAGS)

net/tcpip/picotcp/build/lib/libpicotcp.a:
	make -C net/tcpip/picotcp $(PICOFLAGS)

$(PREFIX)/lib/libkernel.a: kernel/libopencm3/lib/libopencm3_$(BOARD).a

kernel/$(BOARD)/$(BOARD).ld: kernel/$(BOARD)/$(BOARD).ld.in
	export KRAMMEM_SIZE_B=`python2 -c "print '0x%X' % ( $(KRAMMEM_SIZE) * 1024)"`;	\
	export KFLASHMEM_SIZE_B=`python2 -c "print '0x%X' % ( $(KFLASHMEM_SIZE) * 1024)"`;	\
	cat $^ | sed -e "s/__FLASH_ORIGIN/$(FLASH_ORIGIN)/g" | \
			 sed -e "s/__KFLASHMEM_SIZE/$$KFLASHMEM_SIZE_B/g" | \
			 sed -e "s/__RAM_BASE/$(RAM_BASE)/g" |\
			 sed -e "s/__KRAMMEM_SIZE/$$KRAMMEM_SIZE_B/g" \
			 >$@

kernel.elf: $(PREFIX)/lib/libkernel.a $(OBJS-y) kernel/libopencm3/lib/libopencm3_$(BOARD).a kernel/$(BOARD)/$(BOARD).ld net/tcpip/picotcp/build/lib/libpicotcp.a
	$(CC) -o $@   -Tkernel/$(BOARD)/$(BOARD).ld -Wl,--start-group $(PREFIX)/lib/libkernel.a $(OBJS-y) kernel/libopencm3/lib/libopencm3_$(BOARD).a -Wl,--end-group \
		-Wl,-Map,kernel.map  $(LDFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
	
apps/busybox/busybox: busybox

busybox:
	CROSS_COMPILE=arm-none-eabi- make -C apps/busybox

qemu: image.bin 
	qemu-system-arm -semihosting -M lm3s6965evb --kernel image.bin -serial stdio -S -gdb tcp::3333

qemu2: image.bin
	qemu-system-arm -semihosting -M lm3s6965evb --kernel image.bin -serial stdio

menuconfig:
	@$(MAKE) -C kconfig/ menuconfig -f Makefile.frosted


malloc_test:
	gcc -o malloc.test kernel/malloc.c -Iinclude -Inewlib/include -DCONFIG_KRAM_SIZE=4

libclean:
	@make -C kernel/libopencm3 clean
	@make -C net/tcpip/picotcp clean

clean:
	rm -f malloc.test
	rm -f  kernel/$(BOARD)/$(BOARD).ld
	@make -C kernel clean
	@make -C libfrosted clean
	@rm -f $(OBJS-y)
	@rm -f *.map *.bin *.elf
	@rm -f apps/apps.ld
	@rm -f kernel/$(BOARD)/$(BOARD).ld
	@rm -f tools/xipfstool
	@find . |grep "\.o" | xargs -x rm -f

