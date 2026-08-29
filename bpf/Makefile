CLANG  ?= clang
ARCH    = $(shell uname -m | sed 's/x86_64/x86/')
CFLAGS  = -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(ARCH) -I.

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@
