#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define standard Rust/C types so the compiler stops complaining
typedef unsigned int u32;
typedef unsigned long long u64;

// The structure of the data we will send to Rust
struct process_event {
    u32 pid;
    u32 uid;
    char comm[16];
};

// Create the Ring Buffer to communicate with User Space (Rust)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

// We use `void *ctx` instead of a complex kernel struct because 
// we don't actually need to read the syscall arguments!
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct process_event *event;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; // Buffer full, drop the event
    }

    // Grab the Process ID and User ID using built-in BPF helpers
    u64 id = bpf_get_current_pid_tgid();
    event->pid = id >> 32; 
    event->uid = bpf_get_current_uid_gid();

    // Grab the name of the command being executed
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Send it to the Rust daemon!
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// eBPF programs must be GPL licensed
char LICENSE[] SEC("license") = "GPL";