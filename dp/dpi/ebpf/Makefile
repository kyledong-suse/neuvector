CLANG ?= clang
OUTPUT := .output
LIBBPF_SRC := $(abspath ../../third-party/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath $(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath $(OUTPUT))
BPFTOOL_SRC := $(abspath ../../third-party/bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX := ../../third-party/vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I../../third-party/libbpf/include/uapi -I$(dir $(VMLINUX))
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`

CFLAGS := -g -Wall
EXTRA_LDFLAGS = -Wl,-rpath,'$$ORIGIN' -Wl,--disable-new-dtags

BPF_SOURCES := $(wildcard *.bpf.c)
BPF_OBJECTS := $(patsubst %.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SOURCES))
BPF_SKELETONS := $(patsubst %.bpf.c,$(OUTPUT)/%.skel.h,$(BPF_SOURCES))

.PHONY: all
all: libbpf bpftool bpf_code
# .PHONY: all
# all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf $(OUTPUT)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

# Build libbpf
libbpf: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIBBPF,$@)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=y \
			OBJDIR=$(LIBBPF_OBJDIR)				 \
			DESTDIR=$(LIBBPF_DESTDIR)			 \
			INCLUDEDIR= LIBDIR= UAPIDIR=		 \
			install

# Build bpftool
bpftool: $(BPFTOOL)

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(MAKE) OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
bpf_code: $(BPF_OBJECTS) $(BPF_SKELETONS)

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		     $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
# $(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# $(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
# 	$(call msg,CC,$@)
# 	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# # Build application binary
# $(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
# 	$(call msg,BINARY,$@)
# 	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(EXTRA_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
