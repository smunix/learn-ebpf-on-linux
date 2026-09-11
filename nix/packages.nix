{ pkgs }:
let
  inherit (pkgs) lib;
  repository = ../.;
  rustToolchain = pkgs.rust-bin.nightly."2026-07-15".default.override {
    extensions = [ "rust-src" "rustfmt" "clippy" ];
  };
  rustPlatform = pkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  book = pkgs.runCommand "learn-ebpf-book" {
    nativeBuildInputs = [ pkgs.typst ];
  } ''
    mkdir -p "$out"
    typst compile --root ${repository} ${repository}/book/main.typ "$out/learn-ebpf.pdf"
  '';

  samples = rustPlatform.buildRustPackage {
    pname = "learn-ebpf-samples";
    version = "0.1.0";
    src = ../samples;
    cargoLock.lockFile = ../samples/Cargo.lock;
    nativeBuildInputs = [ pkgs.bpf-linker pkgs.llvm pkgs.clang ];
    doCheck = true;
    dontCargoBuild = true;
    AYA_BUILD_TOOLCHAIN = "nightly-2026-07-15";

    buildPhase = ''
      runHook preBuild
      cargo fmt --all -- --check
      cargo check --workspace --exclude samples-ebpf --locked
      cargo xtask build-ebpf
      cargo build --locked --release -p sample-runner
      runHook postBuild
    '';

    checkPhase = ''
      runHook preCheck
      cargo test --workspace --exclude samples-ebpf --locked
      runHook postCheck
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p "$out/bin" "$out/lib/learn-ebpf"
      cp target/release/sample-runner "$out/bin/"
      cp target/ebpf/tracepoint-hello target/ebpf/samples-ebpf "$out/lib/learn-ebpf/"
      cp -R . "$out/lib/learn-ebpf/source"
      rm -rf "$out/lib/learn-ebpf/source/target"
      runHook postInstall
    '';
  };

  scriptSyntax = pkgs.runCommand "learn-ebpf-script-syntax" {
    nativeBuildInputs = [ pkgs.bash pkgs.python3 ];
  } ''
    for script in ${../scripts}/*.sh; do
      bash -n "$script"
    done
    for script in ${../scripts}/*.py; do
      python3 -m py_compile "$script"
    done
    touch "$out"
  '';

  documentation = pkgs.runCommand "learn-ebpf-documentation" {
    nativeBuildInputs = [ pkgs.bash pkgs.python3 ];
  } ''
    export PATH="${lib.makeBinPath [ pkgs.bash pkgs.python3 ]}:$PATH"
    cd ${repository}
    bash scripts/verify-links.sh --offline README.md CONTRIBUTING.md samples/README.md samples/15-map-iterator-telemetry/README.md
    bash scripts/verify-snippets.sh README.md CONTRIBUTING.md
    touch "$out"
  '';

  sourceLayout = pkgs.runCommand "learn-ebpf-source-layout" { } ''
    test -f ${../flake.nix}
    test -f ${../book/main.typ}
    test -f ${../samples/Cargo.lock}
    test -d ${../samples/14-sentinel-capstone}
    test -d ${../samples/15-map-iterator-telemetry}
    touch "$out"
  '';
in
{
  packages = {
    inherit book samples;
    default = samples;
  };

  checks = {
    script-syntax = scriptSyntax;
    documentation = documentation;
    source-layout = sourceLayout;
    inherit book samples;
  };
}
