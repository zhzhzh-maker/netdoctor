APP := netdoctor
CMD := ./cmd/netdoctor
BIN_DIR := bin
CACHE_DIR := .cache
GOCACHE := $(CURDIR)/$(CACHE_DIR)/go-build
GOMODCACHE := $(CURDIR)/$(CACHE_DIR)/gomod
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)

ADDR ?= 127.0.0.1:8080
EVENT_LIMIT ?= 4096

BPF_SRC := bpf/netdoctor.bpf.c
VMLINUX := bpf/vmlinux.h
BPF_TARGET ?= bpfel
BPF_ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/arm64/arm64/')
BPF_OUTPUT_DIR := internal/collector/ebpf
BPF_IDENT := netdoctor
BPF_GO_PACKAGE := ebpfcollector
BPF_OBJECT := $(BPF_OUTPUT_DIR)/$(BPF_IDENT)_$(BPF_TARGET).o
RUNTIME_BPF_OBJECT := $(BIN_DIR)/$(BPF_IDENT)_$(BPF_TARGET).o
OBJECT ?= $(RUNTIME_BPF_OBJECT)

.PHONY: help deps build install test test-linux fmt vet tidy run probe serve bpf bpf-vmlinux clean

help:
	@printf '%s\n' 'netdoctor targets:'
	@printf '  %-14s %s\n' 'build' 'build ./bin/netdoctor for the current OS'
	@printf '  %-14s %s\n' 'deps' 'download Go modules into .cache/gomod'
	@printf '  %-14s %s\n' 'test' 'run Go tests with a repo-local build cache'
	@printf '  %-14s %s\n' 'test-linux' 'compile/test Linux amd64 packages from any host'
	@printf '  %-14s %s\n' 'fmt' 'format Go sources'
	@printf '  %-14s %s\n' 'vet' 'run go vet'
	@printf '  %-14s %s\n' 'tidy' 'tidy go.mod/go.sum'
	@printf '  %-14s %s\n' 'probe' 'run the eBPF probe; pass OBJECT=path optionally'
	@printf '  %-14s %s\n' 'run' 'attach an eBPF object; defaults to bin/netdoctor_bpfel.o'
	@printf '  %-14s %s\n' 'serve' 'start Web UI/API; pass ADDR=host:port and OBJECT=path'
	@printf '  %-14s %s\n' 'bpf-vmlinux' 'generate bpf/vmlinux.h on Linux'
	@printf '  %-14s %s\n' 'bpf' 'generate cilium/ebpf Go bindings with bpf2go; pass BPF_ARCH=x86 or arm64'
	@printf '  %-14s %s\n' 'clean' 'remove build/cache artifacts'

deps:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go mod download

build:
	@mkdir -p $(BIN_DIR) $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go build -o $(BIN_DIR)/$(APP) $(CMD)

install:
	$(GOENV) go install $(CMD)

test:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go test ./...

test-linux:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) GOOS=linux GOARCH=amd64 go test ./...

fmt:
	gofmt -w cmd internal

vet:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go vet ./...

tidy:
	$(GOENV) go mod tidy

probe:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go run $(CMD) probe $(if $(wildcard $(OBJECT)),-object $(OBJECT),) -event-limit $(EVENT_LIMIT)

run:
	@test -r "$(OBJECT)" || (echo 'BPF object not found: $(OBJECT). Run make bpf BPF_ARCH=x86 first, or pass OBJECT=/path/to/file.o' >&2; exit 2)
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go run $(CMD) run -object $(OBJECT) -event-limit $(EVENT_LIMIT)

serve:
	@mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go run $(CMD) serve -addr $(ADDR) $(if $(wildcard $(OBJECT)),-object $(OBJECT),) -event-limit $(EVENT_LIMIT)

bpf-vmlinux:
	@test "$$(uname -s)" = "Linux" || (echo 'bpf-vmlinux must run on Linux' >&2; exit 2)
	@test -r /sys/kernel/btf/vmlinux || (echo '/sys/kernel/btf/vmlinux is not readable' >&2; exit 2)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

bpf: $(VMLINUX)
	@mkdir -p $(BIN_DIR) $(CACHE_DIR)/go-build $(CACHE_DIR)/gomod
	$(GOENV) go run github.com/cilium/ebpf/cmd/bpf2go \
		-target $(BPF_TARGET) \
		-type event \
		-cc clang \
		-cflags "-O2 -g -I./bpf -D__TARGET_ARCH_$(BPF_ARCH)" \
		-go-package $(BPF_GO_PACKAGE) \
		-output-dir $(BPF_OUTPUT_DIR) \
		$(BPF_IDENT) $(BPF_SRC)
	cp $(BPF_OBJECT) $(RUNTIME_BPF_OBJECT)
	@printf 'BPF object ready: %s\n' '$(RUNTIME_BPF_OBJECT)'

clean:
	rm -rf $(BIN_DIR) $(CACHE_DIR)
