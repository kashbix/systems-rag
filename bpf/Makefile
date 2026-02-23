CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags for eBPF
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

SRC := src/sysrag.bpf.c
OBJ := sysrag.bpf.o

all: $(OBJ)

# Generate vmlinux.h if it doesn't exist
headers/vmlinux.h:
	mkdir -p headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

# Compile the C code into eBPF bytecode
$(OBJ): $(SRC) headers/vmlinux.h
	$(CLANG) $(CFLAGS) -Iheaders -c $< -o $@

clean:
	rm -f $(OBJ)
	rm -f headers/vmlinux.h