#![no_std]
#![no_main]
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[xdp]
fn bounded_xdp(ctx: XdpContext) -> u32 {
    if ctx.data() + core::mem::size_of::<u16>() > ctx.data_end() { return xdp_action::XDP_ABORTED; }
    let _word = unsafe { *(ctx.data() as *const u16) };
    xdp_action::XDP_PASS
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
#[unsafe(link_section="license")] #[unsafe(no_mangle)] static LICENSE: [u8;13] = *b"Dual MIT/GPL\0";
