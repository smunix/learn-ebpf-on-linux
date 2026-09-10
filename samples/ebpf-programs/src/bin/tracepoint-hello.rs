#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

#[map]
static SCHED_SWITCHES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_hello(_ctx: TracePointContext) -> u32 {
    if let Some(ptr) = SCHED_SWITCHES.get_ptr_mut(0) {
        // The value belongs to this CPU, so no cross-CPU atomic is required.
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
