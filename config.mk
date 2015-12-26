#Common code used to read the .config
ifeq ($(ARCH_LPC17XX),y)
	CPU=cortex-m
	BOARD=lpc17xx
	FLASH_ORIGIN=0x00000000
	RAM_BASE=0x10000000
	CFLAGS+=-DLPC17XX -mcpu=cortex-m3
endif

ifeq ($(ARCH_LM3S),y)
	CPU=cortex-m
	BOARD=lm3s
	FLASH_ORIGIN=0x00000000
	RAM_BASE=0x20000000
	CFLAGS+=-DLM3S -mcpu=cortex-m3
endif

ifeq ($(ARCH_STM32F4),y)
	CPU=cortex-m
	BOARD=stm32f4
	FLASH_ORIGIN=0x08000000
	RAM_BASE=0x20000000
	CFLAGS+=-DSTM32F4 -mcpu=cortex-m4 -mfloat-abi=soft
	OPENCM3FLAGS=FP_FLAGS="-mfloat-abi=soft" 
endif

ifeq ($(MACH_STM32F405Pyboard),y)
	CFLAGS+=-DPYBOARD
endif

ifeq ($(MACH_STM32F429Discovery),y)
	CFLAGS+=-DF429DISCO
endif

ifeq ($(FLASH_SIZE_2MB),y)
	FLASH_SIZE=2048
endif
ifeq ($(FLASH_SIZE_1MB),y)
	FLASH_SIZE=1024
endif
ifeq ($(FLASH_SIZE_512KB),y)
	FLASH_SIZE=512
endif
ifeq ($(FLASH_SIZE_384KB),y)
	FLASH_SIZE=384
endif
ifeq ($(FLASH_SIZE_256KB),y)
	FLASH_SIZE=256
endif
ifeq ($(FLASH_SIZE_128KB),y)
	FLASH_SIZE=128
endif

ifeq ($(RAM_SIZE_256KB),y)
	RAM_SIZE=256
endif
ifeq ($(RAM_SIZE_192KB),y)
	RAM_SIZE=192
endif
ifeq ($(RAM_SIZE_128KB),y)
	RAM_SIZE=128
endif
ifeq ($(RAM_SIZE_96KB),y)
	RAM_SIZE=96
endif
ifeq ($(RAM_SIZE_64KB),y)
	RAM_SIZE=64
endif
ifeq ($(RAM_SIZE_32KB),y)
	RAM_SIZE=32
endif
ifeq ($(RAM_SIZE_16KB),y)
	RAM_SIZE=16
endif

ifeq ($(CLK_48MHZ),y)
	SYS_CLOCK=48000000
endif
ifeq ($(CLK_84MHZ),y)
	SYS_CLOCK=84000000
endif
ifeq ($(CLK_100MHZ),y)
	SYS_CLOCK=100000000
endif
ifeq ($(CLK_120MHZ),y)
	SYS_CLOCK=120000000
endif
ifeq ($(CLK_168MHZ),y)
	SYS_CLOCK=168000000
endif

#USARTs
ifeq ($(USART_0),y)
    CFLAGS+=-DCONFIG_USART_0
endif
ifeq ($(USART_1),y)
    CFLAGS+=-DCONFIG_USART_1
endif
ifeq ($(USART_2),y)
    CFLAGS+=-DCONFIG_USART_2
endif
ifeq ($(USART_3),y)
    CFLAGS+=-DCONFIG_USART_3
endif
ifeq ($(USART_6),y)
    CFLAGS+=-DCONFIG_USART_6
endif
#UARTs
ifeq ($(UART_1),y)
    CFLAGS+=-DCONFIG_UART_1
endif
ifeq ($(UART_2),y)
    CFLAGS+=-DCONFIG_UART_2
endif    
ifeq ($(UART_3),y)
    CFLAGS+=-DCONFIG_UART_3
endif
ifeq ($(UART_4),y)
    CFLAGS+=-DCONFIG_UART_4
endif

#SPIs
ifeq ($(SPI_1),y)
    CFLAGS+=-DCONFIG_SPI_1
endif
ifeq ($(SPI_2),y)
    CFLAGS+=-DCONFIG_SPI_2
endif
ifeq ($(SPI_3),y)
    CFLAGS+=-DCONFIG_SPI_3
endif
ifeq ($(SPI_4),y)
    CFLAGS+=-DCONFIG_SPI_4
endif
ifeq ($(SPI_5),y)
    CFLAGS+=-DCONFIG_SPI_5
endif
ifeq ($(SPI_6),y)
    CFLAGS+=-DCONFIG_SPI_6
endif

#RNG
ifeq ($(DEVRNG),y)
    CFLAGS+=-DCONFIG_RNG
endif

#PICOTCP
ifeq ($(PICOTCP),y)
    ifeq ($(PICOTCP_IPV4),y)
        CFLAGS+=-DCONFIG_PICOTCP_IPV4
    endif
    ifeq ($(PICOTCP_IPV6),y)
        CFLAGS+=-DCONFIG_PICOTCP_IPV6
    endif
    ifeq ($(PICOTCP_DEVLOOP),y)
        CFLAGS+=-DCONFIG_PICOTCP_DEVLOOP
    endif
    ifeq ($(PICOTCP_CRC),y)
        CFLAGS+=-DCONFIG_PICOTCP_CRC
    endif
    ifeq ($(PICOTCP_ETH),y)
        CFLAGS+=-DCONFIG_PICOTCP_ETH
    endif
    ifeq ($(PICOTCP_TCP),y)
        CFLAGS+=-DCONFIG_PICOTCP_TCP
    endif
    ifeq ($(PICOTCP_UDP),y)
        CFLAGS+=-DCONFIG_PICOTCP_UDP
    endif
    ifeq ($(PICOTCP_IPFRAG),y)
        CFLAGS+=-DCONFIG_PICOTCP_IPFRAG
    endif
    ifeq ($(PICOTCP_NAT),y)
        CFLAGS+=-DCONFIG_PICOTCP_NAT
    endif
    ifeq ($(PICOTCP_ICMP4),y)
        CFLAGS+=-DCONFIG_PICOTCP_ICMP4
    endif
    ifeq ($(PICOTCP_PING),y)
        CFLAGS+=-DCONFIG_PICOTCP_PING
    endif
    ifeq ($(PICOTCP_MCAST),y)
        CFLAGS+=-DCONFIG_PICOTCP_MCAST
    endif
    ifeq ($(PICOTCP_DHCP_CLIENT),y)
        CFLAGS+=-DCONFIG_PICOTCP_DHCP_CLIENT
    endif
    ifeq ($(PICOTCP_DHCP_SERVER),y)
        CFLAGS+=-DCONFIG_PICOTCP_DHCP_SERVER
    endif
    ifeq ($(PICOTCP_DNS_CLIENT),y)
        CFLAGS+=-DCONFIG_PICOTCP_DNS_CLIENT
    endif
    ifeq ($(PICOTCP_IPFILTER),y)
        CFLAGS+=-DCONFIG_PICOTCP_IPFILTER
    endif
    ifeq ($(PICOTCP_OSLR),y)
        CFLAGS+=-DCONFIG_PICOTCP_OSLR
    endif
    ifeq ($(PICOTCP_SLAACV4),y)
        CFLAGS+=-DCONFIG_PICOTCP_SLAACV4
    endif
    ifeq ($(PICOTCP_SNTP_CLIENT),y)
        CFLAGS+=-DCONFIG_PICOTCP_SNTP_CLIENT
    endif
    ifeq ($(PICOTCP_MEMORY_MANAGER),y)
        CFLAGS+=-DCONFIG_PICOTCP_MEMORY_MANAGER
    endif
endif

APPS_ORIGIN=$$(( $(KFLASHMEM_SIZE) * 1024))
CFLAGS+=-DFLASH_ORIGIN=$(FLASH_ORIGIN)
CFLAGS+=-DAPPS_ORIGIN=$(APPS_ORIGIN)
CFLAGS+=-DCONFIG_KRAM_SIZE=$(KRAMMEM_SIZE)
CFLAGS+=-DCONFIG_SYS_CLOCK=$(SYS_CLOCK)

