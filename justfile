set shell := ["bash", "-euo", "pipefail", "-c"]

# Show available commands.
default:
    @just --list

# Enter the reproducible development environment.
develop:
    nix develop

# Format Nix files through the flake formatter.
fmt:
    nix fmt

# Parse shell scripts without executing them.
shell:
    bash -n scripts/*.sh

# Verify repository-local Markdown links without network access.
links:
    ./scripts/verify-links.sh --offline README.md CONTRIBUTING.md

# Parse shell snippets and Nix expressions without building or attaching BPF.
snippets:
    ./scripts/verify-snippets.sh README.md CONTRIBUTING.md

# Evaluate flake outputs only; this does not build the VM test or attach eBPF.
flake:
    nix flake check --no-build

# Format, test, and build the Rust/Aya workspace without attaching a program.
code-check:
    cd samples && cargo fmt --all -- --check
    cd samples && cargo check --workspace --exclude samples-ebpf
    cd samples && cargo test --workspace --exclude samples-ebpf
    cd samples && cargo xtask build-ebpf

# Run all non-privileged project checks.
check: shell links snippets flake code-check

# Build the current book PDF.
book:
    nix build .#book

# Build the user-space runner and eBPF ELF objects; this does not attach them.
samples:
    nix build .#samples

# Replace the quarantined fixture with bindings from this booted kernel.
# Run in a disposable worktree; optionally add --install-tool after `--`.
target-bindings *args:
    ./scripts/generate-target-bindings.sh {{args}}

# Build a separately named object containing target-BTF-gated programs.
target-btf-object:
    cd samples && cargo xtask build-ebpf --target-btf

# Audit the running kernel, BTF, and runtime LSM list without changing state.
kernel-audit:
    ./scripts/check-kernel.sh

# Render diagram source files into the ignored root build directory.
diagrams:
    ./scripts/render-diagrams.sh

# Check whether generated diagrams are current without writing files.
diagrams-check:
    ./scripts/render-diagrams.sh --check

# Run the audit-first smoke harness. Privileged probing needs explicit flags.
smoke:
    ./scripts/smoke-tests.sh --audit

# Build as the ordinary user, then explicitly attach only the payload-free first sample.
test-runtime:
    cd samples && cargo xtask build-ebpf && cargo build -p sample-runner
    sudo ./scripts/smoke-tests.sh --runtime 01-tracepoint-hello --allow-attach

# Build and run the isolated NixOS audit VM test; it never attaches an eBPF program.
vm-test:
    nix build .#checks.x86_64-linux.vm-test
