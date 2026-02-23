use anyhow::{Context, Result};
use aya::{
    maps::RingBuf,
    programs::TracePoint,
    Bpf,
    include_bytes_aligned,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

/// This struct MUST match the exact memory layout of the C struct in `sysrag.bpf.c`
#[repr(C)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
}

/// Manages the lifecycle of the eBPF program to ensure it stays loaded in the kernel
pub struct BpfManager {
    bpf: Bpf,
}

impl BpfManager {
    /// Loads the compiled eBPF object file and injects it into the kernel
    pub fn new() -> Result<Self> {
        // Use Aya's aligned memory macro to safely embed the fresh bytecode
        let bpf_data = include_bytes_aligned!("../../../bpf/sysrag.bpf.o");
        let mut bpf = Bpf::load(bpf_data)
            .context("Failed to load embedded eBPF object bytes.")?;

        // Find the 'trace_execve' program and attach it...
        let program: &mut TracePoint = bpf
            .program_mut("trace_execve")
            .context("Failed to find 'trace_execve' in bytecode")?
            .try_into()?;
            
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")
            .context("Failed to attach to sys_enter_execve tracepoint")?;

        Ok(Self { bpf })
    }

    /// Starts an asynchronous loop to read the Ring Buffer and send logs to the RAG engine
    pub async fn start_listening(&mut self, log_sender: mpsc::Sender<String>) -> Result<()> {
        // Find the shared memory ring buffer established by the C code
        let map = self.bpf.map_mut("events").context("Failed to find 'events' map")?;
        let mut ring_buf = RingBuf::try_from(map)?;

        println!("BPF Manager: Successfully hooked into kernel. Listening for events...");

        // Continuously poll the buffer without blocking the main thread
        loop {
            while let Some(item) = ring_buf.next() {
                // Safely read the raw bytes from kernel memory into our Rust struct
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ProcessEvent) };
                
                // Convert the C string (null-terminated byte array) to a Rust String
                let comm_string = String::from_utf8_lossy(&event.comm)
                    .trim_end_matches('\0')
                    .to_string();

                // Format the raw OS log
                let raw_log = format!(
                    "execve: pid={} uid={} comm={}", 
                    event.pid, event.uid, comm_string
                );

                // Send the log over the channel to the RAG engine.
                // If the channel is closed (e.g., daemon shutting down), we exit cleanly.
                if log_sender.send(raw_log).await.is_err() {
                    eprintln!("BPF Manager: Log channel closed, stopping listener.");
                    return Ok(());
                }
            }

            // Yield control back to the Tokio scheduler so other tasks (like IPC) can run
            sleep(Duration::from_millis(50)).await;
        }
    }
}