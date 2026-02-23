# Systems RAG: AI-Powered OS Kernel Security

Systems RAG is an experimental, memory-safe cybersecurity daemon that bridges the gap between low-level Linux kernel observability and Generative AI.

By utilizing eBPF to trace system calls with zero overhead, and local Large Language Models (LLMs) to analyze behavior, this tool acts as an autonomous, localized threat-hunting agent.

## Architecture Overview

This project is built on a highly optimized, air-gapped pipeline:

1. **Kernel Tracing (C/eBPF):** Hooks directly into the Linux `execve` tracepoint to capture process executions before they hit user space.
2. **High-Speed IPC (Rust/Aya):** Streams kernel telemetry to a user-space daemon via asynchronous Ring Buffers.
3. **Vector Embeddings (ONNX/FastEmbed):** Converts raw OS logs into mathematical vectors (Cosine Similarity) to detect deviations from a normal system baseline.
4. **Local LLM Analysis:** Feeds mathematical anomalies into a local LLM to generate professional, actionable security reports.
5. **Unix Domain Sockets:** Provides a secure, lightning-fast CLI interface to query the background daemon.

## Tech Stack

* **Systems Programming:** Rust, C
* **Kernel Observability:** eBPF, Aya Framework
* **AI/Machine Learning:** ONNX Runtime, FastEmbed, Ollama
* **Concurrency & Networking:** Tokio (Async Rust), Reqwest

## Quick Start

### Prerequisites

* A Linux environment (required for eBPF)
* `clang` and `llvm` installed for compiling BPF bytecode
* Rust (`cargo`) installed
* [Ollama](https://ollama.com/) running locally with the Llama 3 model (`ollama run llama3`)

### Building the Project

The project uses a unified Makefile to compile both the C kernel bytecode and the Rust workspace.

```bash
git clone https://github.com/yourusername/systems-rag.git
cd systems-rag
make build

```

### Running the Daemon

The daemon requires `root` privileges to inject the eBPF program into the kernel. It runs as a background engine, listening on `/tmp/sysrag.sock`.

```bash
sudo ./target/release/sysrag-daemon

```

### Investigating Threats

Open a new terminal and use the CLI to instantly analyze the most recent anomaly caught by the kernel. The CLI features a custom-built, retro-terminal UI for data visualization.

```bash
sudo ./target/release/sysrag-cli investigate

```

Or, check the general health of the system:

```bash
sudo ./target/release/sysrag-cli status

```

## Security & Privacy

Because this tool relies on local LLMs and local Vector Databases, **no kernel telemetry ever leaves your machine.** Your OS logs are analyzed entirely air-gapped from the cloud, ensuring strict compliance and data privacy.

## Roadmap & Contributing

This is an active experimental architecture. Current roadmap items include:

* **Automated Quarantine:** Automatically issue `SIGKILL` to high-threat PIDs based on AI consensus.
* **Persistence Layer:** Integrate SQLite or SurrealDB to maintain anomaly history across system reboots.
* **Network Tracing:** Extend eBPF hooks to `sys_enter_connect` to correlate process execution with outbound IP connections.

Please support this project by contributing and architectural reviews are highly encouraged.
