fn main() {
    if let Ok(path) = which::which("bpf-linker") {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
