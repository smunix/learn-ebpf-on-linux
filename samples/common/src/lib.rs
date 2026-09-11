#![cfg_attr(not(feature = "user"), no_std)]

pub const TASK_COMM_LEN: usize = 16;
pub const RING_BYTES: u32 = 256 * 1024;
pub const EACCES: i32 = 13;
pub const ABI_SCHEMA_VERSION: u16 = 1;
pub const EVENT_FLAGS_KNOWN: u32 = 0;

pub mod kind {
    pub const HELLO: u16 = 1;
    pub const SYSCALL: u16 = 2;
    pub const EXEC: u16 = 3;
    pub const PROCESS: u16 = 4;
    pub const SCHED_LATENCY: u16 = 5;
    pub const PAGE_FAULT: u16 = 6;
    pub const PACKET: u16 = 7;
    pub const CONNECT: u16 = 8;
    pub const CONTAINER: u16 = 9;
    pub const FILE: u16 = 10;
    pub const SENTINEL: u16 = 11;
    pub const TELEMETRY: u16 = 12;

    pub const fn is_base_event(value: u16) -> bool {
        matches!(
            value,
            HELLO
                | SYSCALL
                | EXEC
                | PROCESS
                | SCHED_LATENCY
                | PAGE_FAULT
                | PACKET
                | CONTAINER
                | FILE
                | SENTINEL
        )
    }
}

pub mod reason {
    pub const NONE: u32 = 0;
    pub const POLICY_MATCH_AUDIT: u32 = 1;
    pub const POLICY_MATCH_ENFORCE: u32 = 2;
    pub const POLICY_MATCH_OUT_OF_SCOPE: u32 = 3;
    pub const IDENTITY_UNAVAILABLE: u32 = 4;
    pub const PRIOR_LSM_DENIAL: u32 = 5;
}

pub mod metric {
    pub const COUNTER_INSERT_FAILED: u32 = 0;
    pub const LRU_INSERT_FAILED: u32 = 1;
    pub const TELEMETRY_INSERT_FAILED: u32 = 2;
    pub const MAP_ERROR_SLOTS: u32 = 3;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordHeader {
    /// Same-host teaching ABI. Consumers reject versions they do not understand.
    pub schema_version: u16,
    /// Total bytes in this record, including this header.
    pub record_len: u16,
    pub kind: u16,
    /// Must be zero for schema version 1.
    pub reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnforcementConfig {
    /// 0 is audit-only. 1 is enforcement enabled.
    pub enforce: u32,
    /// User-space supplied generation copied into decision telemetry.
    pub policy_generation: u32,
    /// Must equal the current cgroup v2 id before a denial is possible.
    pub cgroup_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Event {
    /// The header is deliberately first so consumers can validate before dispatch.
    pub header: RecordHeader,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub value: u64,
    pub device: u64,
    pub inode: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub action: u32,
    pub flags: u32,
    pub reason: u32,
    pub policy_generation: u32,
    pub comm: [u8; TASK_COMM_LEN],
    /// Must be zero for schema version 1. It also makes all tail bytes explicit.
    pub reserved_tail: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectEvent {
    pub base: Event,
    pub address: u32,
    pub port_be: u32,
}

/// Stable key for the telemetry teaching sample. The control-group identifier
/// prevents equal process identifiers in different containers from colliding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryKey {
    pub tgid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
}

/// Per-CPU counter tuple. User space merges one value from every possible CPU.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryCounter {
    pub events: u64,
    pub observed_bytes: u64,
    pub last_seen_ns: u64,
}

/// Loss-sensitive real-time record transported through the ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryEvent {
    pub header: RecordHeader,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub key: TelemetryKey,
    pub observed_bytes: u64,
    pub cpu: u32,
    pub reserved: u32,
}

/// Binary record emitted by the optional kernel BPF map-element iterator.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetrySnapshot {
    pub key: TelemetryKey,
    pub counter: TelemetryCounter,
    pub position: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileIdentity {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EnforcementConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TelemetryKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TelemetryCounter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_audit_by_default() {
        assert_eq!(EnforcementConfig::default().enforce, 0);
        assert_eq!(EnforcementConfig::default().cgroup_id, 0);
    }

    #[test]
    fn abi_layout_has_no_implicit_tail_bytes() {
        assert_eq!(core::mem::offset_of!(Event, header), 0);
        assert_eq!(core::mem::size_of::<RecordHeader>(), 8);
        assert_eq!(core::mem::size_of::<Event>(), 96);
        assert_eq!(core::mem::size_of::<ConnectEvent>(), 104);
        assert_eq!(core::mem::size_of::<TelemetryKey>(), 16);
        assert_eq!(core::mem::size_of::<TelemetryCounter>(), 24);
        assert_eq!(core::mem::size_of::<TelemetryEvent>(), 56);
        assert_eq!(core::mem::size_of::<TelemetrySnapshot>(), 48);
        assert_eq!(
            core::mem::size_of::<Event>() % core::mem::align_of::<Event>(),
            0
        );
    }
}
