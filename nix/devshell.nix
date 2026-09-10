{ pkgs }:
let
  rustToolchain = pkgs.rust-bin.nightly."2026-07-15".default.override {
    extensions = [ "rust-src" "rustfmt" "clippy" ];
  };
in
pkgs.mkShell {
  packages = [
    rustToolchain
    pkgs.bpf-linker
    pkgs.bpftools
    pkgs.rust-bindgen
    pkgs.clang
    pkgs.llvm
    pkgs.lld
    pkgs.libbpf
    pkgs.pahole
    pkgs.pkg-config
    pkgs.openssl
    pkgs.zlib
    pkgs.just
    pkgs.typst
    pkgs.graphviz
    pkgs.d2
    pkgs.shellcheck
    pkgs.python3
    pkgs.curl
    pkgs.git
    pkgs.iproute2
  ];

  shellHook = ''
    export BPF_CLANG=clang
    export BPFTOOL=bpftool
    export AYA_BUILD_TOOLCHAIN=nightly-2026-07-15
    export RUST_BACKTRACE=1
    echo "learn-eBPF development shell (x86_64-linux)"
    echo "Rust: $(rustc --version)"
    echo "Run 'just check' for non-privileged checks or 'just samples' to build all artifacts."
  '';
}
