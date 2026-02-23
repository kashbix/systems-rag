# ==============================================================================
# "Systems RAG" - OS-Level Log Anomaly Detector
# Master Makefile
# ==============================================================================

.PHONY: all build build-bpf build-rust run-daemon run-cli clean help

# The default target when you just type `make`
all: build

## ----------------------------------------------------------------------
## Build Commands
## ----------------------------------------------------------------------

# Builds the entire project (Kernel C code + Rust Workspace)
build: build-bpf build-rust
	@echo "✅ [SUCCESS] Entire Systems RAG stack built successfully!"

# Compiles the eBPF C code into kernel bytecode
build-bpf:
	@echo "🔨 [BUILD] Compiling eBPF kernel sensor (C)..."
	@$(MAKE) -C bpf/

# Compiles the Rust CLI and Daemon binaries in release mode for max speed
build-rust:
	@echo "🦀 [BUILD] Compiling Rust user-space binaries (Daemon & CLI)..."
	@cargo build --release

## ----------------------------------------------------------------------
## Execution Commands
## ----------------------------------------------------------------------

# Runs the background AI daemon.
# NOTE: eBPF requires root privileges, so this runs with `sudo`.
run-daemon: build
	@echo "🚀 [RUN] Starting sysragd (Daemon) as root..."
	@sudo ./target/release/sysrag-daemon

# Runs the CLI to check the status.
run-cli:
	@echo "💻 [RUN] Executing sysrag CLI..."
	@./target/release/sysrag status

## ----------------------------------------------------------------------
## Cleanup Commands
## ----------------------------------------------------------------------

# Wipes all compiled artifacts so you can start fresh
clean:
	@echo "🧹 [CLEAN] Removing Rust build artifacts..."
	@cargo clean
	@echo "🧹 [CLEAN] Removing eBPF bytecodes..."
	@$(MAKE) -C bpf/ clean
	@echo "✨ [CLEAN] Project workspace is pristine."

## ----------------------------------------------------------------------
## Help Command
## ----------------------------------------------------------------------
help:
	@echo "Systems RAG - Available Make Commands:"
	@echo "  make build       - Compiles both the C kernel sensor and Rust workspace"
	@echo "  make run-daemon  - Builds the project and starts the AI daemon (requires sudo)"
	@echo "  make run-cli     - Runs the CLI tool to ping the daemon status"
	@echo "  make clean       - Removes all compiled binaries and bytecodes"