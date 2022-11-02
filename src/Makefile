CLANG = clang
LIBBPF = $(abspath ../lib/libbpf.a)
LIBBPF_INCLUDE = /usr/include/bpf
BPFTOOL = bpftool
VMLINUX = $(abspath ../include/vmlinux.h)
LLVM_STRIP ?= llvm-strip
INCLUDES := -I../tools/libbpf/include/uapi -I../include -I../tools/libbpf/src
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
CFLAGS := -g  -O2



tprogs := tracingProcess  tracingChmod tracingProcessV2 tracingSock tracingUDP tracingUDP2 tracingUDP3

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath .)/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(tprogs) 

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(tprogs) *.o 

# Build BPF code
%_kern.o: %_kern.c $(wildcard %.h) $(VMLINUX) $(LIBBPF)
	$(call msg,CLANG-BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ 

# Build user-space code
%_user.o:  %_user.c $(wildcard %.h) 
	$(call msg,CC,$@)
	$(Q)$(CLANG) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(tprogs): %: %_user.o $(LIBBPF) | %_kern.o
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(CFLAGS) $^ -lelf -lz -o $@

.DELETE_ON_ERROR: