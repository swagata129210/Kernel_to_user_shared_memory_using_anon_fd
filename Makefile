# Kernel module Makefile
obj-m += anon_fd_memory.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
        $(MAKE) -C $(KDIR) M=$(PWD) modules
        gcc -o test_anon_memory test_anon_memory.c

clean:
        $(MAKE) -C $(KDIR) M=$(PWD) clean
        rm -f test_anon_memory

install:
        sudo insmod anon_fd_memory.ko
        sudo chmod 666 /dev/anon_memory

uninstall:
        sudo rmmod anon_fd_memory

test: all install
        ./test_anon_memory

.PHONY: all clean install uninstall test
