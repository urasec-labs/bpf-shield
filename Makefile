SHELL := /bin/bash
CARGO ?= cargo
CLIPPY_FLAGS := -D warnings -D clippy::undocumented_unsafe_blocks

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: doctor
doctor: ## Verify host toolchain / kernel prerequisites
	@echo "== host ==";  $(CARGO) --version; rustc --version
	@echo "== nightly (needed for bpfel-unknown-none) =="; rustup run nightly rustc --version
	@echo "== unprivileged bpf =="; sysctl kernel.unprivileged_bpf_disabled 2>/dev/null || true
	@echo "== kprobe override =="; grep -E 'CONFIG_BPF_KPROBE_OVERRIDE|CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /boot/config-$$(uname -r) 2>/dev/null || zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_BPF_KPROBE_OVERRIDE|CONFIG_BPF_LSM' || true
	@echo "== bpf lsm active =="; cat /sys/kernel/security/lsm 2>/dev/null || true
	@echo "== bpffs =="; mount | grep -w bpffs || echo "bpffs NOT mounted"
	@echo "== tracefs =="; mount | grep -w tracefs || echo "tracefs NOT mounted"

.PHONY: build
build: ## Build user-space binaries (kernel object is a build-script side effect)
	$(CARGO) build --release

.PHONY: build-ebpf
build-ebpf: ## Build only the eBPF object
	$(CARGO) build --release -p bpf-shield-ebpf

.PHONY: fmt
fmt: ## Format
	$(CARGO) fmt --all

.PHONY: clippy
clippy: ## Lint user-space crates
	$(CARGO) clippy --workspace --exclude bpf-shield-ebpf --all-targets -- $(CLIPPY_FLAGS)

.PHONY: test
test: ## Run unit tests
	$(CARGO) test --workspace --exclude bpf-shield-ebpf

.PHONY: check
check: fmt clippy test ## fmt + clippy + test

.PHONY: install
install: build ## Install agent + cli into /usr/local/bin
	install -m 0755 target/release/bpf-shield-agent /usr/local/bin/
	install -m 0755 target/release/bpf-shieldctl   /usr/local/bin/

.PHONY: deploy
deploy: install ## Install agent + cli + systemd unit
	install -Dm0644 deploy/bpf-shield.service /etc/systemd/system/bpf-shield.service
	install -Dm0644 deploy/bpf-shield.sysconfig /etc/default/bpf-shield
	systemctl daemon-reload

.PHONY: poc
poc: build ## Run the end-to-end proof-of-concept against the live kernel
	./scripts/poc.sh

.PHONY: clean
clean: ## Clean
	$(CARGO) clean
