# Rust/Aya samples

This workspace contains the chapter samples for Aya **0.14.0** and aya-ebpf **0.2.1**. Userspace uses stable-compatible APIs with an MSRV of Rust 1.87; `rust-toolchain.toml` pins `nightly-2026-07-15` plus `rust-src` because the eBPF build uses `-Z build-std=core` for `bpfel-unknown-none`. `Cargo.lock` pins the dependency graph.

Build everything as an ordinary user:

```console
cargo fmt --all -- --check
cargo check --workspace --exclude samples-ebpf
cargo test --workspace --exclude samples-ebpf
cargo xtask build-ebpf
cargo build -p sample-runner
```

Do **not** run Cargo with `sudo`. If an approved disposable host requires privilege for attachment, invoke only the already-built loader, for example `sudo ./target/debug/sample-runner run 01-tracepoint-hello --duration 10`. The runner currently requires effective UID 0; it does not demonstrate a capabilities-only deployment.

The default BPF objects carry normal compiler-emitted BTF metadata, but contain no private scheduler-layout decoding or target-kernel structure access and do not require target `vmlinux` BTF for those programs. Samples 06, 07, and 12–14 are quarantined pending target-generated fixtures and recorded load/attach/detach evidence. Sample 15's tracepoint, map, ring buffer, and userspace `SnapshotIter` are in the default object; its optional kernel `bpf_map_elem` iterator remains target-BTF gated. `ebpf-programs/src/vmlinux.rs` is explicitly a manual quarantine fixture, not a proven CO-RE binding. Successful compilation does not prove that an object can load or attach on a particular kernel.

For samples 06, 12–14, and the optional sample 15 kernel iterator, use a disposable worktree on the exact target VM:

```console
cd /home/ubuntu/learn-ebpf-on-linux
nix develop
just target-bindings -- --install-tool
just target-btf-object
llvm-objdump -h samples/target/ebpf/samples-ebpf-target-btf
llvm-objdump -t samples/target/ebpf/samples-ebpf-target-btf
```

The generator records the kernel release, architecture, target-BTF SHA-256 digest, pinned `aya-tool` revision, and generated-file digest beside `vmlinux.rs`. The target build writes `target/ebpf/samples-ebpf-target-btf`; it does not replace the default object. Review relocations and retain the evidence before invoking the runner with both `--object target/ebpf/samples-ebpf-target-btf` and `--target-btf-fixture`. Sample 07 needs a separate tracepoint-format decoder workflow and remains refused.

Ring records are a same-host teaching ABI: schema version, record kind, exact record length, flags, and reserved-zero fields are checked before byte-wise decoding. `transport_metrics` reports producer reservation drops and consumer parse rejects; there is no intermediate userspace queue or intentional event sampling in this runner.

Sample 15 combines this live event stream with a per-CPU aggregate map. Its default final snapshot uses `BPF_MAP_GET_NEXT_KEY` and reduces Aya `PerCpuValues` through a custom Rust iterator. The optional `--kernel-map-iterator` path stages those merged counters into an immutable `TELEMETRY_EXPORT` hash map, loads `iter/bpf_map_elem`, attaches it to that export map through `BPF_LINK_CREATE`, creates a readable iterator descriptor with `BPF_ITER_CREATE`, and decodes binary `bpf_seq_write()` records. Read `15-map-iterator-telemetry/README.md` and Chapter 19 before using that target-specific mode.
