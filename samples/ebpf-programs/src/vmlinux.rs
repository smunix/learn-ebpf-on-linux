//! QUARANTINED MANUAL LAYOUT FIXTURE — NOT GENERATED BINDINGS AND NOT PROVEN CO-RE.
//!
//! The default eBPF object does not compile this module. Before enabling the
//! `target-btf` feature, replace this entire file with bindings generated from
//! the exact target BTF, inspect `.BTF.ext` relocations, and record target
//! load/attach/detach results. These definitions only make the dependency explicit.
#![allow(non_camel_case_types, non_snake_case, dead_code)]

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct super_block {
    pub s_dev: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct inode {
    pub i_mode: u16,
    pub i_opflags: u16,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_flags: u32,
    pub i_ino: u64,
    pub i_sb: *mut super_block,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct file {
    pub f_u: [u64; 2],
    pub f_path: [u64; 2],
    pub f_inode: *mut inode,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct task_struct {
    pub thread_info: [u64; 4],
    pub __state: u32,
    pub saved_state: u32,
    pub stack: *mut ::aya_ebpf::cty::c_void,
    pub usage: i32,
    pub flags: u32,
    pub ptrace: u32,
    pub on_cpu: i32,
    pub wake_entry: [u64; 2],
    pub wakee_flips: u32,
    pub wakee_flip_decay_ts: u64,
    pub last_wakee: *mut task_struct,
    pub recent_used_cpu: i32,
    pub wake_cpu: i32,
    pub on_rq: i32,
    pub prio: i32,
    pub static_prio: i32,
    pub normal_prio: i32,
    pub rt_priority: u32,
    pub se: [u8; 256],
    pub rt: [u8; 128],
    pub dl: [u8; 256],
    pub sched_class: *const ::aya_ebpf::cty::c_void,
    pub core_node: [u64; 4],
    pub core_cookie: u64,
    pub core_occupation: u32,
    pub sched_task_group: *mut ::aya_ebpf::cty::c_void,
    pub uclamp_req: [u64; 2],
    pub uclamp: [u64; 2],
    pub stats: [u8; 128],
    pub sched_info: [u64; 8],
    pub tasks: [u64; 2],
    pub pushable_tasks: [u64; 3],
    pub pushable_dl_tasks: [u64; 3],
    pub mm: *mut ::aya_ebpf::cty::c_void,
    pub active_mm: *mut ::aya_ebpf::cty::c_void,
    pub exit_state: i32,
    pub exit_code: i32,
    pub exit_signal: i32,
    pub pdeath_signal: i32,
    pub jobctl: u64,
    pub personality: u32,
    pub sched_reset_on_fork: u32,
    pub pid: i32,
    pub tgid: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct seq_file {
    pub _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter_meta {
    pub seq: *mut seq_file,
    pub session_id: u64,
    pub seq_num: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_map {
    pub _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_iter__bpf_map_elem {
    pub meta: *mut bpf_iter_meta,
    pub map: *mut bpf_map,
    pub key: *mut ::aya_ebpf::cty::c_void,
    pub value: *mut ::aya_ebpf::cty::c_void,
}
