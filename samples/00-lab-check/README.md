# 00-lab-check

## Purpose and safety

This command performs read-only checks. It loads no BPF object, changes no mount or sysctl, and creates no pin. It reports **present**, **absent**, or **unknown** for readable BTF, active BPF LSM state, mounts, selected local tracepoint formats, UID, and effective-capability text. A present prerequisite is not proof that a program will pass the verifier or attach.

## Build and run

```console
cargo build -p sample-runner
./target/debug/sample-runner lab-check
```

No elevated authority is needed. No cleanup is required. An inaccessible securityfs or tracefs is reported as unknown rather than unsupported. cgroup v2 is checked as a mount in the current mount namespace, not merely as a filesystem supported by the kernel.
