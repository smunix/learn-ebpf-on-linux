# 09-xdp-packet-counter

## Purpose and packet policy

This sample counts IPv4 versus other Ethernet EtherTypes on an explicitly named interface. It checks each byte against `data_end` and reads bytes through `*const u8`, whose alignment is one; it does not perform an unaligned `u16` dereference. Short frames, unsupported formats, and all ordinary frames return `XDP_PASS`. The program never drops or redirects traffic.

## Build and run

Use only an isolated disposable veth and generic (`Skb`) mode:

```console
cargo xtask build-ebpf
cargo build -p sample-runner
sudo ./target/debug/sample-runner run 09-xdp-packet-counter --iface veth-ebpf0 --duration 10
```

Validate short, VLAN, unknown-EtherType, IPv4, and ordinary frames before making any native-mode claim. Counters are per-CPU and summed by the runner. Object drop detaches; then delete only the disposable veth. Network-administration authority may be required independently of BPF load authority.
