use anyhow::{Context, Result, bail};
use aya_build::{Package, Toolchain};
use cargo_metadata::MetadataCommand;
use clap::{Parser, Subcommand};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

const EBPF_TOOLCHAIN: &str = "nightly-2026-07-15";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    BuildEbpf {
        /// Enable programs that require bindings generated from this target's BTF.
        #[arg(long)]
        target_btf: bool,
    },
    Check,
    Run {
        sample: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::BuildEbpf { target_btf } => build_ebpf(target_btf),
        CommandKind::Check => {
            run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))?;
            run(Command::new("cargo").args(["check", "--workspace", "--exclude", "samples-ebpf"]))
        }
        CommandKind::Run { sample, args } => {
            let mut cmd = Command::new("cargo");
            cmd.args(["run", "--package", "sample-runner", "--", "run", &sample]);
            cmd.args(args);
            run(&mut cmd)
        }
    }
}

fn build_ebpf(target_btf: bool) -> Result<()> {
    let out = PathBuf::from(if target_btf {
        "target/ebpf-target-btf"
    } else {
        "target/ebpf"
    });
    std::fs::create_dir_all(&out)?;
    unsafe {
        std::env::set_var("OUT_DIR", &out);
        // aya-build normally runs as a build script and reads these Cargo
        // variables to select bpfel/bpfeb and the target architecture. xtask
        // supplies the equivalent host facts explicitly.
        std::env::set_var(
            "CARGO_CFG_TARGET_ENDIAN",
            if cfg!(target_endian = "little") {
                "little"
            } else {
                "big"
            },
        );
        std::env::set_var("CARGO_CFG_TARGET_ARCH", std::env::consts::ARCH);
    }
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let package = metadata
        .packages
        .into_iter()
        .find(|package| package.name.as_str() == "samples-ebpf")
        .context("samples-ebpf package missing")?;
    let root: PathBuf = package
        .manifest_path
        .parent()
        .context("manifest parent")?
        .as_str()
        .into();
    let toolchain =
        std::env::var("AYA_BUILD_TOOLCHAIN").unwrap_or_else(|_| EBPF_TOOLCHAIN.to_owned());
    let features: &[&str] = if target_btf { &["target-btf"] } else { &[] };
    aya_build::build_ebpf(
        [Package {
            name: "samples-ebpf",
            root_dir: root.to_str().context("UTF-8 path")?,
            no_default_features: true,
            features,
            ..Default::default()
        }],
        Toolchain::Custom(&toolchain),
    )?;
    if target_btf {
        let destination = PathBuf::from("target/ebpf/samples-ebpf-target-btf");
        std::fs::create_dir_all(destination.parent().context("target object parent")?)?;
        std::fs::copy(out.join("samples-ebpf"), &destination)
            .with_context(|| format!("copy target-BTF object to {}", destination.display()))?;
        println!("wrote {}", destination.display());
    }
    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("spawn {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed: {status}")
    }
    Ok(())
}
