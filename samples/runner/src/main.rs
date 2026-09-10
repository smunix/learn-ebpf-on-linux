use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Btf, Ebpf,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{BtfTracePoint, CgroupAttachMode, CgroupSockAddr, Lsm, TracePoint, Xdp, XdpMode},
};
use clap::{Parser, Subcommand};
use sentinel_common::{
    ABI_SCHEMA_VERSION, ConnectEvent, EVENT_FLAGS_KNOWN, EnforcementConfig, Event, FileIdentity,
    RecordHeader, kind, metric,
};
use std::{
    fs::{self, File},
    net::Ipv4Addr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Audit-first runner for the learn-eBPF samples")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    LabCheck,
    Run {
        sample: String,
        #[arg(long)]
        object: Option<PathBuf>,
        #[arg(long)]
        iface: Option<String>,
        #[arg(long)]
        cgroup: Option<PathBuf>,
        #[arg(long)]
        protect: Option<PathBuf>,
        #[arg(long)]
        enforce: bool,
        /// Acknowledge that the supplied object was generated and tested for this target BTF.
        #[arg(long)]
        target_btf_fixture: bool,
        #[arg(long, default_value_t = 1)]
        policy_generation: u32,
        #[arg(long, default_value_t = 10)]
        duration: u64,
    },
    Identity {
        path: PathBuf,
    },
    CgroupId {
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::LabCheck => lab_check(),
        Command::Identity { path } => {
            let id = file_identity(&path)?;
            println!("device={} inode={}", id.device, id.inode);
            Ok(())
        }
        Command::CgroupId { path } => {
            println!("{}", cgroup_id(&path)?);
            Ok(())
        }
        Command::Run {
            sample,
            object,
            iface,
            cgroup,
            protect,
            enforce,
            target_btf_fixture,
            policy_generation,
            duration,
        } => run(
            &sample,
            object.as_deref(),
            iface.as_deref(),
            cgroup.as_deref(),
            protect.as_deref(),
            enforce,
            target_btf_fixture,
            policy_generation,
            duration,
        ),
    }
}

#[derive(Clone, Copy)]
enum ProbeState {
    Present,
    Absent,
    Unknown,
}

impl ProbeState {
    const fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

fn probe(label: &str, state: ProbeState, detail: impl std::fmt::Display) {
    println!("{label:<22} {:<8} {detail}", state.label());
}

fn read_state(path: &Path) -> ProbeState {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => match File::open(path) {
            Ok(_) => ProbeState::Present,
            Err(_) => ProbeState::Unknown,
        },
        Ok(_) => ProbeState::Absent,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProbeState::Absent,
        Err(_) => ProbeState::Unknown,
    }
}

fn mountinfo_has(fs_type: &str) -> Option<bool> {
    fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .map(|contents| {
            contents
                .lines()
                .any(|line| line.contains(&format!(" - {fs_type} ")))
        })
}

fn lab_check() -> Result<()> {
    println!("learn-eBPF read-only local facts (not a load/attach proof)");
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unreadable".to_owned());
    probe(
        "Linux process target",
        if cfg!(target_os = "linux") {
            ProbeState::Present
        } else {
            ProbeState::Absent
        },
        release.trim(),
    );
    probe(
        "readable kernel BTF",
        read_state(Path::new("/sys/kernel/btf/vmlinux")),
        "/sys/kernel/btf/vmlinux",
    );

    match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(lsm) => probe(
            "active bpf LSM",
            if lsm.split(',').any(|entry| entry.trim() == "bpf") {
                ProbeState::Present
            } else {
                ProbeState::Absent
            },
            lsm.trim(),
        ),
        Err(error) => probe(
            "active bpf LSM",
            ProbeState::Unknown,
            format!("cannot read /sys/kernel/security/lsm: {error}"),
        ),
    }

    let mount_probe = |label, fs_type| match mountinfo_has(fs_type) {
        Some(true) => probe(
            label,
            ProbeState::Present,
            "mounted in this mount namespace",
        ),
        Some(false) => probe(
            label,
            ProbeState::Absent,
            "not mounted in this mount namespace",
        ),
        None => probe(
            label,
            ProbeState::Unknown,
            "/proc/self/mountinfo unreadable",
        ),
    };
    mount_probe("cgroup v2 mount", "cgroup2");
    mount_probe("bpffs mount", "bpf");
    mount_probe("tracefs mount", "tracefs");

    for (label, category, event) in [
        ("sched_switch event", "sched", "sched_switch"),
        ("openat event", "syscalls", "sys_enter_openat"),
        ("user-fault event", "exceptions", "page_fault_user"),
    ] {
        match tracepoint_format(category, event) {
            Some(path) => probe(label, ProbeState::Present, path.display()),
            None => probe(
                label,
                ProbeState::Unknown,
                "format absent or tracefs inaccessible",
            ),
        }
    }

    let euid = unsafe { libc::geteuid() };
    probe(
        "effective UID 0",
        if euid == 0 {
            ProbeState::Present
        } else {
            ProbeState::Absent
        },
        format!("euid={euid}; this runner currently requires UID 0 for attachment"),
    );
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            let caps = status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .unwrap_or("CapEff: unavailable");
            probe("effective caps", ProbeState::Present, caps);
        }
        Err(error) => probe("effective caps", ProbeState::Unknown, error),
    }
    println!(
        "Interpretation: these are discoverable prerequisites only; successful verifier load, attach, observation, and detach must be tested separately on an approved host."
    );
    Ok(())
}

fn tracefs_roots() -> [&'static Path; 2] {
    [
        Path::new("/sys/kernel/tracing"),
        Path::new("/sys/kernel/debug/tracing"),
    ]
}

fn tracepoint_format(category: &str, event: &str) -> Option<PathBuf> {
    tracefs_roots()
        .into_iter()
        .map(|root| {
            root.join("events")
                .join(category)
                .join(event)
                .join("format")
        })
        .find(|path| File::open(path).is_ok())
}

fn require_tracepoint(category: &str, event: &str) -> Result<PathBuf> {
    tracepoint_format(category, event).ok_or_else(|| {
        anyhow!(
            "tracepoint {category}/{event} is absent or its format is unreadable in local tracefs; refusing attachment"
        )
    })
}

fn object_path(sample: &str, explicit: Option<&Path>) -> PathBuf {
    explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        if sample == "01-tracepoint-hello" {
            PathBuf::from("target/ebpf/tracepoint-hello")
        } else {
            PathBuf::from("target/ebpf/samples-ebpf")
        }
    })
}

fn file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn cgroup_id(path: &Path) -> Result<u64> {
    Ok(fs::metadata(path)
        .with_context(|| format!("stat cgroup {}", path.display()))?
        .ino())
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "this runner requires effective UID 0 for attachment; build as an ordinary user, then invoke only target/debug/sample-runner with the required authority"
        )
    }
    Ok(())
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let format = require_tracepoint(category, name)?;
    println!("using tracepoint format {}", format.display());
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program {program_name} missing from object"))?
        .try_into()?;
    program.load()?;
    program.attach(category, name)?;
    Ok(())
}

fn attach_lsm(ebpf: &mut Ebpf, program_name: &str) -> Result<()> {
    let btf = Btf::from_sys_fs().context("BTF unavailable; LSM requires readable target BTF")?;
    let program: &mut Lsm = ebpf
        .program_mut(program_name)
        .with_context(|| {
            format!("program {program_name} missing; default object quarantines BTF layouts")
        })?
        .try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;
    Ok(())
}

fn configure_policy(
    ebpf: &mut Ebpf,
    protect: &Path,
    cgroup: &Path,
    enforce: bool,
    policy_generation: u32,
) -> Result<(FileIdentity, u64)> {
    if enforce && !protect.starts_with("/tmp/learn-ebpf-") {
        bail!("--enforce accepts only disposable paths under /tmp/learn-ebpf-*")
    }
    if policy_generation == 0 {
        bail!("--policy-generation must be nonzero")
    }
    let identity = file_identity(protect)?;
    let cgroup_id = cgroup_id(cgroup)?;
    let mut policy: HashMap<_, FileIdentity, u8> =
        HashMap::try_from(ebpf.map_mut("POLICY").context("POLICY map missing")?)?;
    policy.insert(identity, 1, 0)?;
    let mut config: Array<_, EnforcementConfig> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map missing")?)?;
    config.set(
        0,
        EnforcementConfig {
            enforce: u32::from(enforce),
            policy_generation,
            cgroup_id,
        },
        0,
    )?;
    println!(
        "policy device={} inode={} cgroup={} mode={} generation={policy_generation}",
        identity.device,
        identity.inode,
        cgroup_id,
        if enforce { "ENFORCE" } else { "AUDIT" }
    );
    Ok((identity, cgroup_id))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn parse_header(bytes: &[u8]) -> Result<RecordHeader> {
    if bytes.len() < std::mem::size_of::<RecordHeader>() {
        bail!("record shorter than header: {}", bytes.len())
    }
    let header = RecordHeader {
        schema_version: read_u16(bytes, 0).context("schema version")?,
        record_len: read_u16(bytes, 2).context("record length")?,
        kind: read_u16(bytes, 4).context("record kind")?,
        reserved: read_u16(bytes, 6).context("header reserved")?,
    };
    if header.schema_version != ABI_SCHEMA_VERSION {
        bail!(
            "unsupported schema version {} (expected {})",
            header.schema_version,
            ABI_SCHEMA_VERSION
        )
    }
    if usize::from(header.record_len) != bytes.len() {
        bail!(
            "declared record length {} != received {}",
            header.record_len,
            bytes.len()
        )
    }
    if header.reserved != 0 {
        bail!("schema v1 header reserved field is nonzero")
    }
    Ok(header)
}

fn print_event(bytes: &[u8]) -> Result<()> {
    let header = parse_header(bytes)?;
    let event_len = std::mem::size_of::<Event>();
    let connect_len = std::mem::size_of::<ConnectEvent>();
    let expected_len = if header.kind == kind::CONNECT {
        connect_len
    } else if kind::is_base_event(header.kind) {
        event_len
    } else {
        bail!("unknown record kind {}", header.kind)
    };
    if bytes.len() != expected_len {
        bail!(
            "kind {} requires {} bytes, received {}",
            header.kind,
            expected_len,
            bytes.len()
        )
    }
    let flags = read_u32(bytes, 64).context("flags")?;
    if flags & !EVENT_FLAGS_KNOWN != 0 {
        bail!("schema v1 unknown flags {flags:#x}")
    }
    if read_u32(bytes, 92).context("reserved tail")? != 0 {
        bail!("schema v1 reserved tail is nonzero")
    }

    let pid = read_u32(bytes, 48).context("pid")?;
    let cgroup = read_u64(bytes, 16).context("cgroup")?;
    if header.kind == kind::CONNECT {
        let address = read_u32(bytes, 96).context("IPv4 address")?;
        let port_be = read_u32(bytes, 100).context("port")?;
        println!(
            "connect schema={} pid={} cgroup={} dst={}:{}",
            header.schema_version,
            pid,
            cgroup,
            Ipv4Addr::from(u32::from_be(address)),
            u16::from_be(port_be as u16)
        );
        return Ok(());
    }

    let comm_bytes = bytes.get(76..92).context("comm")?;
    let comm = String::from_utf8_lossy(comm_bytes)
        .trim_end_matches('\0')
        .to_owned();
    println!(
        "event schema={} kind={} pid={} tid={} uid={} cgroup={} action={} reason={} generation={} value={} dev={} ino={} comm={}",
        header.schema_version,
        header.kind,
        pid,
        read_u32(bytes, 52).context("tid")?,
        read_u32(bytes, 56).context("uid")?,
        cgroup,
        read_u32(bytes, 60).context("action")?,
        read_u32(bytes, 68).context("reason")?,
        read_u32(bytes, 72).context("policy generation")?,
        read_u64(bytes, 24).context("value")?,
        read_u64(bytes, 32).context("device")?,
        read_u64(bytes, 40).context("inode")?,
        comm
    );
    Ok(())
}

fn per_cpu_array_total(ebpf: &Ebpf, map_name: &str, index: u32) -> Result<u64> {
    let counts: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.map(map_name)
            .with_context(|| format!("{map_name} map missing"))?,
    )?;
    Ok(counts.get(&index, 0)?.iter().copied().sum())
}

fn report_transport_metrics(ebpf: &Ebpf, parse_rejected: u64) -> Result<()> {
    let producer_dropped = per_cpu_array_total(ebpf, "DROPPED", 0)?;
    println!(
        "transport_metrics producer_reserve_dropped={producer_dropped} consumer_parse_rejected={parse_rejected} userspace_queue_dropped=0 intentional_sampling_skipped=0"
    );
    println!("transport_note no intermediate userspace queue and no intentional event sampling");
    Ok(())
}

fn report_map_errors(ebpf: &Ebpf) -> Result<()> {
    let counter_insert = per_cpu_array_total(ebpf, "MAP_ERRORS", metric::COUNTER_INSERT_FAILED)?;
    let lru_insert = per_cpu_array_total(ebpf, "MAP_ERRORS", metric::LRU_INSERT_FAILED)?;
    println!("map_errors counter_insert_failed={counter_insert} lru_insert_failed={lru_insert}");
    Ok(())
}

fn uses_ring(sample: &str) -> bool {
    matches!(
        sample,
        "03-exec-ringbuf"
            | "04-map-patterns"
            | "06-core-process-inspector"
            | "10-cgroup-connect-audit"
            | "11-container-attribution"
            | "12-lsm-file-audit"
            | "13-lsm-file-enforce"
            | "14-sentinel-capstone"
    )
}

#[allow(clippy::too_many_arguments)]
fn run(
    sample: &str,
    object: Option<&Path>,
    iface: Option<&str>,
    cgroup: Option<&Path>,
    protect: Option<&Path>,
    enforce: bool,
    target_btf_fixture: bool,
    policy_generation: u32,
    duration: u64,
) -> Result<()> {
    if sample == "07-scheduler-latency" {
        bail!(
            "07 is quarantined: the default object contains no scheduler-field decoder; generate and test a target tracepoint-format fixture rather than assuming offsets"
        )
    }
    if matches!(
        sample,
        "06-core-process-inspector"
            | "12-lsm-file-audit"
            | "13-lsm-file-enforce"
            | "14-sentinel-capstone"
    ) && !target_btf_fixture
    {
        bail!(
            "{sample} is quarantined from the default object; provide a target-generated/tested BTF object and --target-btf-fixture (the repository's manual vmlinux.rs is not proof)"
        )
    }

    require_root()?;
    let object = object_path(sample, object);
    let mut ebpf = Ebpf::load_file(&object).with_context(|| {
        format!(
            "load {}; run `cargo xtask build-ebpf` first",
            object.display()
        )
    })?;
    match sample {
        "01-tracepoint-hello" => {
            attach_tracepoint(&mut ebpf, "tracepoint_hello", "sched", "sched_switch")?
        }
        "02-syscall-counter" => {
            attach_tracepoint(&mut ebpf, "syscall_counter", "syscalls", "sys_enter_openat")?
        }
        "03-exec-ringbuf" => {
            attach_tracepoint(&mut ebpf, "exec_ringbuf", "sched", "sched_process_exec")?
        }
        "04-map-patterns" => {
            attach_tracepoint(&mut ebpf, "map_patterns", "syscalls", "sys_enter_openat")?
        }
        "06-core-process-inspector" => {
            let btf = Btf::from_sys_fs()?;
            let program: &mut BtfTracePoint = ebpf
                .program_mut("core_process_inspector")
                .context("program missing from target-BTF object")?
                .try_into()?;
            program.load("sched_process_fork", &btf)?;
            program.attach()?;
        }
        "08-page-fault-profiler" => {
            attach_tracepoint(
                &mut ebpf,
                "page_fault_user",
                "exceptions",
                "page_fault_user",
            )?;
            println!("page-fault scope=user only; kernel faults are not attached");
        }
        "09-xdp-packet-counter" => {
            let device = iface.ok_or_else(|| anyhow!("--iface is required"))?;
            let program: &mut Xdp = ebpf
                .program_mut("xdp_packet_counter")
                .context("program missing")?
                .try_into()?;
            program.load()?;
            program.attach(device, XdpMode::Skb)?;
        }
        "10-cgroup-connect-audit" => {
            let cgroup_file = File::open(cgroup.ok_or_else(|| anyhow!("--cgroup is required"))?)?;
            let program: &mut CgroupSockAddr = ebpf
                .program_mut("cgroup_connect_audit")
                .context("program missing")?
                .try_into()?;
            program.load()?;
            program.attach(cgroup_file, CgroupAttachMode::Single)?;
        }
        "11-container-attribution" => attach_tracepoint(
            &mut ebpf,
            "container_attribution",
            "syscalls",
            "sys_enter_execve",
        )?,
        "12-lsm-file-audit" => {
            if enforce {
                bail!("sample 12 is audit-only")
            }
            configure_policy(
                &mut ebpf,
                protect.context("--protect required")?,
                cgroup.context("--cgroup required")?,
                false,
                policy_generation,
            )?;
            attach_lsm(&mut ebpf, "lsm_file_audit")?;
        }
        "13-lsm-file-enforce" => {
            configure_policy(
                &mut ebpf,
                protect.context("--protect required")?,
                cgroup.context("--cgroup required")?,
                enforce,
                policy_generation,
            )?;
            attach_lsm(&mut ebpf, "lsm_file_enforce")?;
        }
        "14-sentinel-capstone" => {
            configure_policy(
                &mut ebpf,
                protect.context("--protect required")?,
                cgroup.context("--cgroup required")?,
                enforce,
                policy_generation,
            )?;
            attach_lsm(&mut ebpf, "sentinel_file_open")?;
        }
        _ => bail!("unknown or unavailable sample {sample}"),
    }

    let duration = duration.min(60);
    println!("attached {sample}; observing for {duration}s (owned-link drop detaches)");
    let end = Instant::now() + Duration::from_secs(duration);
    let mut parse_rejected = 0_u64;
    if uses_ring(sample) {
        let map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
        let mut ring = RingBuf::try_from(map)?;
        while Instant::now() < end {
            while let Some(item) = ring.next() {
                if let Err(error) = print_event(&item) {
                    parse_rejected = parse_rejected.wrapping_add(1);
                    eprintln!("rejected ring record: {error:#}");
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    } else {
        thread::sleep(Duration::from_secs(duration));
    }

    match sample {
        "01-tracepoint-hello" => {
            println!(
                "sched_switch_count={}",
                per_cpu_array_total(&ebpf, "SCHED_SWITCHES", 0)?
            );
        }
        "02-syscall-counter" | "04-map-patterns" => {
            let counts: aya::maps::PerCpuHashMap<_, u32, u64> = aya::maps::PerCpuHashMap::try_from(
                ebpf.map("COUNTERS").context("COUNTERS map missing")?,
            )?;
            for entry in counts.iter() {
                let (tgid, values) = entry?;
                println!("tgid={tgid} count={}", values.iter().copied().sum::<u64>());
            }
            report_map_errors(&ebpf)?;
            if sample == "04-map-patterns" {
                println!("bucket0={}", per_cpu_array_total(&ebpf, "BUCKETS", 0)?);
            }
        }
        "08-page-fault-profiler" => println!(
            "user_page_faults={}",
            per_cpu_array_total(&ebpf, "PAGE_FAULTS", 0)?
        ),
        "09-xdp-packet-counter" => {
            for index in 0..2 {
                println!(
                    "bucket={index} packets={}",
                    per_cpu_array_total(&ebpf, "PACKETS", index)?
                );
            }
        }
        _ => {}
    }
    if uses_ring(sample) {
        report_transport_metrics(&ebpf, parse_rejected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(kind: u16, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        bytes[0..2].copy_from_slice(&ABI_SCHEMA_VERSION.to_ne_bytes());
        bytes[2..4].copy_from_slice(&(len as u16).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes
    }

    #[test]
    fn rejects_unknown_schema() {
        let mut bytes = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        bytes[0..2].copy_from_slice(&(ABI_SCHEMA_VERSION + 1).to_ne_bytes());
        assert!(print_event(&bytes).is_err());
    }

    #[test]
    fn rejects_declared_length_mismatch() {
        let mut bytes = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        bytes[2..4].copy_from_slice(&8_u16.to_ne_bytes());
        assert!(print_event(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_kind_and_nonzero_reserved_fields() {
        let unknown = header_bytes(u16::MAX, std::mem::size_of::<Event>());
        assert!(print_event(&unknown).is_err());

        let mut reserved_header = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        reserved_header[6..8].copy_from_slice(&1_u16.to_ne_bytes());
        assert!(print_event(&reserved_header).is_err());

        let mut unknown_flags = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        unknown_flags[64..68].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(print_event(&unknown_flags).is_err());

        let mut reserved_tail = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        reserved_tail[92..96].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(print_event(&reserved_tail).is_err());
    }

    #[test]
    fn accepts_zero_reserved_base_record() {
        let bytes = header_bytes(kind::EXEC, std::mem::size_of::<Event>());
        assert!(print_event(&bytes).is_ok());
    }
}
