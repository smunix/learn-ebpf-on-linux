#![no_std]
#![no_main]

// These hand-maintained bindings and every program that depends on them are
// excluded from the default object. See src/vmlinux.rs and the affected READMEs.
#[cfg(feature = "target-btf")]
mod vmlinux;

use aya_ebpf::{
    bindings::{bpf_sock_addr, xdp_action},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_get_smp_processor_id, bpf_ktime_get_ns,
    },
    macros::{cgroup_sock_addr, map, tracepoint, xdp},
    maps::{LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext, XdpContext},
};
#[cfg(feature = "target-btf")]
use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, bpf_seq_write},
    macros::{btf_tracepoint, lsm},
    maps::{Array, HashMap},
    programs::{BtfTracePointContext, LsmContext},
};
use sentinel_common::{
    ABI_SCHEMA_VERSION, ConnectEvent, Event, RING_BYTES, RecordHeader, TelemetryCounter,
    TelemetryEvent, TelemetryKey, kind, metric,
};
#[cfg(feature = "target-btf")]
use sentinel_common::{EACCES, EnforcementConfig, FileIdentity, TelemetrySnapshot, reason};
#[cfg(feature = "target-btf")]
use vmlinux::{bpf_iter__bpf_map_elem, file, inode, super_block, task_struct};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static MAP_ERRORS: PerCpuArray<u64> = PerCpuArray::with_max_entries(metric::MAP_ERROR_SLOTS, 0);
#[map]
static COUNTERS: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(16384, 0);
#[map]
static RECENT: LruHashMap<u32, u64> = LruHashMap::with_max_entries(32768, 0);
#[map]
static BUCKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(32, 0);
#[map]
static PAGE_FAULTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
#[map]
static TELEMETRY: PerCpuHashMap<TelemetryKey, TelemetryCounter> =
    PerCpuHashMap::with_max_entries(4096, 0);
#[cfg(feature = "target-btf")]
#[map]
static TELEMETRY_EXPORT: HashMap<TelemetryKey, TelemetryCounter> =
    HashMap::with_max_entries(4096, 0);
#[cfg(feature = "target-btf")]
#[map]
static POLICY: HashMap<FileIdentity, u8> = HashMap::with_max_entries(128, 0);
#[cfg(feature = "target-btf")]
#[map]
static CONFIG: Array<EnforcementConfig> = Array::with_max_entries(1, 0);

#[inline(always)]
fn increment_array(map: &PerCpuArray<u64>, index: u32) {
    if let Some(ptr) = map.get_ptr_mut(index) {
        // PerCpuArray returns storage private to the executing CPU, so this
        // read-modify-write cannot race with another CPU's value.
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

#[inline(always)]
fn record_map_error(index: u32) {
    increment_array(&MAP_ERRORS, index);
}

#[inline(always)]
fn base(event_kind: u16, value: u64) -> Event {
    let ids = bpf_get_current_pid_tgid();
    Event {
        header: RecordHeader {
            schema_version: ABI_SCHEMA_VERSION,
            record_len: core::mem::size_of::<Event>() as u16,
            kind: event_kind,
            reserved: 0,
        },
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        value,
        pid: (ids >> 32) as u32,
        tid: ids as u32,
        uid: bpf_get_current_uid_gid() as u32,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        ..Event::default()
    }
}

#[inline(always)]
fn record_transport_drop() {
    increment_array(&DROPPED, 0);
}

#[inline(always)]
fn emit(event: Event) {
    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        slot.write(event);
        slot.submit(0);
    } else {
        record_transport_drop();
    }
}

#[inline(always)]
fn update_telemetry(key: &TelemetryKey, observed_bytes: u64, now: u64) {
    if let Some(value) = TELEMETRY.get_ptr_mut(key) {
        unsafe {
            (*value).events = (*value).events.wrapping_add(1);
            (*value).observed_bytes = (*value).observed_bytes.wrapping_add(observed_bytes);
            (*value).last_seen_ns = now;
        }
        return;
    }

    let initial = TelemetryCounter {
        events: 1,
        observed_bytes,
        last_seen_ns: now,
    };
    // A per-CPU hash insert creates the key and initializes this CPU's slot. If
    // a concurrent producer created the key, retry the current CPU's slot.
    if TELEMETRY.insert(key, &initial, 1).is_err() {
        if let Some(value) = TELEMETRY.get_ptr_mut(key) {
            unsafe {
                (*value).events = (*value).events.wrapping_add(1);
                (*value).observed_bytes = (*value).observed_bytes.wrapping_add(observed_bytes);
                (*value).last_seen_ns = now;
            }
        } else {
            record_map_error(metric::TELEMETRY_INSERT_FAILED);
        }
    }
}

#[inline(always)]
fn increment_hash(map: &PerCpuHashMap<u32, u64>, key: u32) {
    if let Some(ptr) = map.get_ptr_mut(&key) {
        // This value belongs to the executing CPU because the map is per-CPU.
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    } else if map.insert(&key, &1, 0).is_err() {
        record_map_error(metric::COUNTER_INSERT_FAILED);
    }
}

#[tracepoint]
pub fn syscall_counter(_ctx: TracePointContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    increment_hash(&COUNTERS, tgid);
    0
}

#[tracepoint]
pub fn exec_ringbuf(_ctx: TracePointContext) -> u32 {
    emit(base(kind::EXEC, 1));
    0
}

#[tracepoint]
pub fn map_patterns(_ctx: TracePointContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    increment_hash(&COUNTERS, tgid);
    increment_array(&BUCKETS, 0);
    if RECENT
        .insert(&tgid, &unsafe { bpf_ktime_get_ns() }, 0)
        .is_err()
    {
        record_map_error(metric::LRU_INSERT_FAILED);
    }
    emit(base(kind::SYSCALL, 1));
    0
}

#[tracepoint]
pub fn telemetry_sys_enter(_ctx: TracePointContext) -> u32 {
    let ids = bpf_get_current_pid_tgid();
    let key = TelemetryKey {
        tgid: (ids >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
    };
    let now = unsafe { bpf_ktime_get_ns() };
    update_telemetry(&key, 1, now);

    let event = TelemetryEvent {
        header: RecordHeader {
            schema_version: ABI_SCHEMA_VERSION,
            record_len: core::mem::size_of::<TelemetryEvent>() as u16,
            kind: kind::TELEMETRY,
            reserved: 0,
        },
        timestamp_ns: now,
        cgroup_id: key.cgroup_id,
        key,
        observed_bytes: 1,
        cpu: unsafe { bpf_get_smp_processor_id() },
        reserved: 0,
    };
    if let Some(mut slot) = EVENTS.reserve::<TelemetryEvent>(0) {
        slot.write(event);
        slot.submit(0);
    } else {
        record_transport_drop();
    }
    0
}

#[tracepoint]
pub fn page_fault_user(_ctx: TracePointContext) -> u32 {
    // Aggregate only. There is deliberately no record per fault.
    increment_array(&PAGE_FAULTS, 0);
    0
}

#[inline(always)]
fn packet_byte(ctx: &XdpContext, offset: usize) -> Option<u8> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start.checked_add(offset + 1)? > end {
        return None;
    }
    // u8 has alignment 1; this avoids an unaligned u16 load from Ethernet byte 12.
    Some(unsafe { *(start.wrapping_add(offset) as *const u8) })
}

#[xdp]
pub fn xdp_packet_counter(ctx: XdpContext) -> u32 {
    let Some(high) = packet_byte(&ctx, 12) else {
        return xdp_action::XDP_PASS;
    };
    let Some(low) = packet_byte(&ctx, 13) else {
        return xdp_action::XDP_PASS;
    };
    let ethertype = u16::from_be_bytes([high, low]);
    let index = if ethertype == 0x0800 { 0 } else { 1 };
    increment_array(&PACKETS, index);
    xdp_action::XDP_PASS
}

#[cgroup_sock_addr(connect4)]
pub fn cgroup_connect_audit(ctx: SockAddrContext) -> i32 {
    let sa: *mut bpf_sock_addr = ctx.sock_addr;
    let (address, port_be) = unsafe { ((*sa).user_ip4, (*sa).user_port) };
    let mut event = ConnectEvent {
        base: base(kind::CONNECT, 0),
        address,
        port_be,
    };
    event.base.header.record_len = core::mem::size_of::<ConnectEvent>() as u16;
    if let Some(mut slot) = EVENTS.reserve::<ConnectEvent>(0) {
        slot.write(event);
        slot.submit(0);
    } else {
        record_transport_drop();
    }
    1
}

#[tracepoint]
pub fn container_attribution(_ctx: TracePointContext) -> u32 {
    emit(base(kind::CONTAINER, unsafe {
        bpf_get_current_cgroup_id()
    }));
    0
}

// The following programs are intentionally absent from the default object.
// Enabling `target-btf` is only appropriate after replacing vmlinux.rs with
// bindings generated from the target BTF and inspecting/testing relocations.
#[cfg(feature = "target-btf")]
#[btf_tracepoint(function = "sched_process_fork")]
pub fn core_process_inspector(ctx: BtfTracePointContext) -> i32 {
    let child: *const task_struct = ctx.arg(1);
    let child_pid = unsafe { bpf_probe_read_kernel(&(*child).pid) }.unwrap_or(0);
    emit(base(kind::PROCESS, child_pid as u64));
    0
}

/// Kernel-executed iterator over one map selected by user space at link-create
/// time. It is target-BTF gated because the iterator context is kernel BTF.
#[cfg(feature = "target-btf")]
#[unsafe(link_section = "iter/bpf_map_elem")]
#[unsafe(no_mangle)]
pub fn telemetry_map_iter(ctx: *mut bpf_iter__bpf_map_elem) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let (meta, key, value) = unsafe { ((*ctx).meta, (*ctx).key, (*ctx).value) };
    if meta.is_null() || key.is_null() || value.is_null() {
        return 0;
    }
    // User space stages this ordinary export map after the observation loop.
    // No eBPF producer writes it, so values stay immutable for this session.
    let counter = unsafe { *(value.cast::<TelemetryCounter>()) };
    let snapshot = TelemetrySnapshot {
        key: unsafe { *(key.cast::<TelemetryKey>()) },
        counter,
        position: unsafe { (*meta).seq_num },
    };
    let seq = unsafe { (*meta).seq }.cast();
    unsafe {
        bpf_seq_write(
            seq,
            core::ptr::addr_of!(snapshot).cast(),
            core::mem::size_of::<TelemetrySnapshot>() as u32,
        ) as i32
    }
}

#[cfg(feature = "target-btf")]
#[inline(always)]
fn identity_from_file(file_ptr: *const file) -> Option<FileIdentity> {
    if file_ptr.is_null() {
        return None;
    }
    let inode_ptr: *mut inode = unsafe { bpf_probe_read_kernel(&(*file_ptr).f_inode).ok()? };
    if inode_ptr.is_null() {
        return None;
    }
    let inode_no = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_ino).ok()? };
    let sb_ptr: *mut super_block = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_sb).ok()? };
    if sb_ptr.is_null() {
        return None;
    }
    let device = unsafe { bpf_probe_read_kernel(&(*sb_ptr).s_dev).ok()? } as u64;
    Some(FileIdentity {
        device,
        inode: inode_no,
    })
}

#[cfg(feature = "target-btf")]
#[inline(always)]
fn file_decision(ctx: LsmContext, sample_kind: u16, may_deny: bool) -> i32 {
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        let mut event = base(sample_kind, previous as u64);
        event.reason = reason::PRIOR_LSM_DENIAL;
        emit(event);
        return previous;
    }

    let cfg = CONFIG.get(0).copied().unwrap_or_default();
    let file_ptr: *const file = ctx.arg(0);
    let Some(identity) = identity_from_file(file_ptr) else {
        let mut event = base(sample_kind, 0);
        event.reason = reason::IDENTITY_UNAVAILABLE;
        event.policy_generation = cfg.policy_generation;
        emit(event);
        return 0;
    };
    if unsafe { POLICY.get(&identity) }.is_none() {
        return 0;
    }

    let mut event = base(sample_kind, 0);
    event.device = identity.device;
    event.inode = identity.inode;
    event.policy_generation = cfg.policy_generation;
    let scoped = cfg.enforce == 1 && cfg.cgroup_id != 0 && cfg.cgroup_id == event.cgroup_id;
    if scoped && may_deny {
        event.action = 1;
        event.reason = reason::POLICY_MATCH_ENFORCE;
    } else if cfg.enforce == 1 && may_deny {
        event.reason = reason::POLICY_MATCH_OUT_OF_SCOPE;
    } else {
        event.reason = reason::POLICY_MATCH_AUDIT;
    }
    emit(event);
    if scoped && may_deny { -EACCES } else { 0 }
}

#[cfg(feature = "target-btf")]
#[lsm(hook = "file_open")]
pub fn lsm_file_audit(ctx: LsmContext) -> i32 {
    file_decision(ctx, kind::FILE, false)
}

#[cfg(feature = "target-btf")]
#[lsm(hook = "file_open")]
pub fn lsm_file_enforce(ctx: LsmContext) -> i32 {
    file_decision(ctx, kind::FILE, true)
}

#[cfg(feature = "target-btf")]
#[lsm(hook = "file_open")]
pub fn sentinel_file_open(ctx: LsmContext) -> i32 {
    file_decision(ctx, kind::SENTINEL, true)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
