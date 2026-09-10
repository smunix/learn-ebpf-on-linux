# 05-verifier-lab

## Quarantine status

The `rejected/` crate is an intentional negative fixture and is outside the workspace. Do not merge it into the default BPF object or attach it to a production interface. Its purpose is to preserve examples that should fail verifier review, paired with the bounded-access source in `corrected/`.

Default workspace checks do not prove a verifier rejection because no object is loaded. Reproduce rejection only in an isolated disposable VM with a recorded kernel, object hash, exact loader command, and verifier log. Compile as an ordinary user; elevate only the already-built loader if the VM policy requires it. The fixture creates no persistent resource unless an external loader pins one.
