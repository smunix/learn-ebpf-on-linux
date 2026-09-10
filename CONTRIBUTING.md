# Contributing

Contributions should make the Rust, Aya, NixOS, and Linux security material easier to reproduce without weakening host safety. The project is **NixOS-first** and supports `x86_64-linux`; a change that depends on another platform must be isolated behind an explicit, documented boundary rather than silently broadening the support claim.

## Development workflow

Enter the pinned environment before editing Nix, Rust, shell, Typst, or diagrams:

```sh
nix develop
just check
```

`just check` is the required non-privileged baseline. It parses shell scripts, validates repository-local Markdown links, parses supported documentation snippets without executing them, and evaluates flake outputs with `--no-build`. It does not load an eBPF program or require `sudo`.

Use focused commands during development:

| Change type | Required command | Notes |
|---|---|---|
| Nix foundation | `nix fmt` and `nix flake check --no-build` | Keep the flake scoped to `x86_64-linux`. |
| Shell helper | `bash -n scripts/*.sh` | Scripts must be `set -euo pipefail`, audit-first, feature-gated, and idempotent. |
| Markdown | `./scripts/verify-links.sh --offline README.md CONTRIBUTING.md` | CI does not depend on external URL availability. |
| Documentation snippets | `./scripts/verify-snippets.sh README.md CONTRIBUTING.md` | The verifier parses snippets only; it never executes them. |
| Diagram source | `./scripts/render-diagrams.sh --check` | Commit both the D2 source and regenerated SVG consumed by Typst. |
| Book build | `nix build .#book` | This compiles the current Typst entry point. |
| Sample source tree | `nix build .#samples` | Builds/tests userspace and eBPF artifacts; it does not attach them. |

Do not claim a check passed unless you ran it in the stated environment and it completed. If an unavailable host feature prevents a check, describe the limitation in the pull request rather than substituting a claim of verification.

## Adding a sample or chapter

Keep runnable source under `samples/` and make the book refer to that canonical source. Add the chapter-to-sample path to the README map when the sample exists. A new sample must state its kernel version range, required BPF features, expected capabilities, input/output behavior, and cleanup behavior. A new book section must identify which sample revision it describes.

Avoid embedding untracked generated code or copying examples by hand into documentation. If a code excerpt differs intentionally from the sample, label it as pseudocode and explain the difference.

## Kernel-facing and BPF LSM work

Kernel-facing contributions have a higher review threshold. The default path is **observe first, enforce later**. Every proposed loader, smoke test, or operational helper must:

1. Perform read-only capability and environment checks before any mutation.
2. Fail closed when a required feature, privilege, or explicit opt-in flag is absent.
3. State whether it can load, attach, pin, modify maps, or change policy.
4. Be idempotent, including cleanup and repeated invocation behavior.
5. Offer a non-privileged parsing or fixture-based validation route suitable for CI.
6. Target a disposable NixOS VM by default, never a production host.

For BPF LSM examples, distinguish the compiled kernel setting from the runtime LSM order. A lab needs `CONFIG_BPF_LSM=y`, BTF, and `bpf` present in `/sys/kernel/security/lsm`; the audit script reports these separately. Use `./scripts/check-kernel.sh` to inspect a host without changing it. Any feature probe that may require BPF-related privilege must require an explicit acknowledgement such as `--allow-privileged`.

The provided NixOS module is intentionally opt-in:

```nix
{
  imports = [ ./nix/nixos-ebpf-lab.nix ];
  services.learn-ebpf-lab.enable = true;
}
```

Use it only for a disposable lab. It configures the kernel feature request and LSM boot order but does not attach a program at activation.

## CI and dependency policy

CI must stay non-privileged. The reviewed template is `ci/github-actions.yml`; install it as `.github/workflows/ci.yml` only with a GitHub credential authorized to manage workflows. Do not add `sudo`, a privileged Docker container, `pull_request_target`, repository write permissions, ambient secrets, or a step that loads/attaches eBPF programs. GitHub recommends pinning third-party actions to a full-length commit SHA because that is the immutable form of an action reference.[1]

Keep `permissions` minimal and add a comment that records the human-readable action release next to each SHA. New external tooling should be available through the Nix development shell; do not download an unpinned binary in CI.

## Style and review

Follow [.editorconfig](.editorconfig), run the Nix formatter, and keep changes narrowly scoped. Regenerate SVGs from their D2 sources rather than hand-editing them. Preserve the license boundary: source and configuration are dual-licensed MIT OR Apache-2.0, while original prose, diagrams, and visual assets use Creative Commons Attribution-ShareAlike 4.0. Attribute and document third-party material before adding it.

A pull request description should explain the learning goal, the validation actually run, kernel and privilege assumptions, and any unresolved constraints. Reviewers may request a smaller, audit-only first change when a proposal combines new policy enforcement with new documentation.

## References

[1]: https://docs.github.com/en/actions/reference/security/secure-use "GitHub Actions secure use reference"
