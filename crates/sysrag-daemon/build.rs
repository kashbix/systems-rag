use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // 1. Tell Cargo to re-run this script ONLY if the C code or Makefile changes
    println!("cargo:rerun-if-changed=../../bpf/src/sysrag.bpf.c");
    println!("cargo:rerun-if-changed=../../bpf/Makefile");

    // 2. Get the current directory so we can navigate to the bpf/ folder
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Failed to get CARGO_MANIFEST_DIR");
    let mut bpf_dir = PathBuf::from(manifest_dir);
    bpf_dir.push("../../bpf");

    // 3. Execute the `make` command inside the `bpf/` directory
    let status = Command::new("make")
        .current_dir(&bpf_dir)
        .status()
        .expect("Failed to execute 'make'. Is it installed?");

    // 4. Fail the Rust build if the C compilation failed
    if !status.success() {
        panic!("Failed to compile eBPF C code. Check your clang and bpftool setup.");
    }
}