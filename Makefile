CLANG ?= clang
# Derived from the running kernel arch so the same Makefile works on both
# amd64 and arm64 runners without a CLI override. libbpf's bpf_tracing.h-style
# helpers key off __TARGET_ARCH_<x86|arm64>; asm headers come from the
# matching multiarch include dir. Can be overridden for cross-compilation.
TARGET_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -I. \
              -I/usr/include/$(shell uname -m)-linux-gnu

BPF_OBJS := bpf/ingress_xdp.bpf.o bpf/transit_loss.bpf.o

.PHONY: all bpf daemon responder clean vmlinux

all: vmlinux bpf daemon responder

# vmlinux.h provides kernel type definitions for CO-RE BPF programs.
# Prefer generating it from the TARGET kernel's BTF (most accurate for
# that host); fall back to a pre-built copy from libbpf/vmlinux.h when
# bpftool isn't available (e.g. CI runners whose -azure kernel flavor
# has no matching linux-tools package). If bpf/vmlinux.h already exists,
# this target is a no-op so an externally-provided file is respected.
vmlinux:
	@if [ -f bpf/vmlinux.h ]; then \
		echo "Using existing bpf/vmlinux.h ($(shell wc -l < bpf/vmlinux.h) lines)"; \
	elif command -v bpftool >/dev/null 2>&1 && bpftool btf dump file /sys/kernel/btf/vmlinux format c >/dev/null 2>&1; then \
		echo "Generating bpf/vmlinux.h from running kernel BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
	else \
		echo "ERROR: bpf/vmlinux.h missing and bpftool cannot read /sys/kernel/btf/vmlinux." >&2; \
		echo "       Install bpftool, or place a pre-built vmlinux.h at bpf/vmlinux.h" >&2; \
		echo "       (e.g. from https://github.com/libbpf/vmlinux.h)." >&2; \
		exit 1; \
	fi

bpf: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c bpf/common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

daemon: bpf
	mkdir -p internal/loader
	cp bpf/*.bpf.o internal/loader/
	cd cmd/daemon && GOOS=$${GOOS:-linux} GOARCH=$${GOARCH:-amd64} go build -o ../../bin/pathprofiler-daemon .

# Standalone cold-probe echo responder. Deliberately does NOT depend on bpf/
# vmlinux -- internal/actuate has no dependency on internal/loader/internal/
# maps, so this builds with plain go build, no BPF toolchain required.
responder:
	cd cmd/responder && GOOS=$${GOOS:-linux} GOARCH=$${GOARCH:-amd64} go build -o ../../bin/pathprofiler-responder .

clean:
	rm -f bpf/*.bpf.o internal/loader/*.bpf.o bin/pathprofiler-daemon bin/pathprofiler-responder
