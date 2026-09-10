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

The default BPF objects carry normal compiler-emitted BTF metadata, but contain no private scheduler-layout decoding or target-kernel structure access and do not require target `vmlinux` BTF for those programs. Samples 06, 07, and 12–14 are quarantined pending target-generated fixtures and recorded load/attach/detach evidence. `ebpf-programs/src/vmlinux.rs` is explicitly a manual quarantine fixture, not a proven CO-RE binding. Successful compilation does not prove that an object can load or attach on a particular kernel.

For samples 06 and 12–14, use a disposable worktree on the exact target VM:

```console
cd /home/ubuntu/learn-eBPF-00
nix develop
just target-bindings -- --install-tool
just target-btf-object
llvm-objdump -h samples/target/ebpf/samples-ebpf-target-btf
llvm-objdump -t samples/target/ebpf/samples-ebpf-target-btf
```

The generator records the kernel release, architecture, target-BTF SHA-256 digest, pinned `aya-tool` revision, and generated-file digest beside `vmlinux.rs`. The target build writes `target/ebpf/samples-ebpf-target-btf`; it does not replace the default object. Review relocations and retain the evidence before invoking the runner with both `--object target/ebpf/samples-ebpf-target-btf` and `--target-btf-fixture`. Sample 07 needs a separate tracepoint-format decoder workflow and remains refused.

Ring records are a same-host teaching ABI: schema version, record kind, exact record length, flags, and reserved-zero fields are checked before byte-wise decoding. `transport_metrics` reports producer reservation drops and consumer parse rejects; there is no intermediate userspace queue or intentional event sampling in this runner.
