{ config, lib, pkgs, ... }:
let
  cfg = config.services.learn-ebpf-lab;
in
{
  options.services.learn-ebpf-lab = {
    enable = lib.mkEnableOption "an isolated eBPF and BPF LSM learning lab";

    lsmOrder = lib.mkOption {
      type = lib.types.str;
      default = "landlock,lockdown,yama,integrity,apparmor,bpf";
      description = ''
        Kernel LSM order for the dedicated lab. The BPF LSM must be present in
        the runtime LSM list; this setting deliberately belongs only in a
        disposable VM or other isolated learning host.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
        message = "learn-ebpf-lab supports x86_64-linux only.";
      }
      {
        assertion = lib.versionAtLeast pkgs.linux.version "5.7";
        message = "BPF LSM requires a Linux kernel new enough to provide it (5.7 or later).";
      }
    ];

    # This module is intentionally opt-in. It compiles the kernel features used
    # by the lab and does not install or attach any eBPF program at activation.
    boot.kernelPackages = lib.mkDefault pkgs.linuxPackages_latest;
    boot.kernelPatches = [
      {
        name = "learn-ebpf-btf-and-bpf-lsm";
        patch = null;
        structuredExtraConfig = with lib.kernel; {
          BPF = yes;
          BPF_SYSCALL = yes;
          BPF_JIT = yes;
          BPF_EVENTS = yes;
          KPROBES = yes;
          SECURITY = yes;
          SECURITYFS = yes;
          DEBUG_INFO = yes;
          DEBUG_INFO_BTF = yes;
          DEBUG_INFO_BTF_MODULES = yes;
          BPF_LSM = yes;
        };
      }
    ];

    # A lab user must deliberately use a suitably privileged loader. Keep
    # unprivileged BPF disabled rather than widening the host attack surface.
    boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 1;
    security.lsm = lib.splitString "," cfg.lsmOrder;

    environment.systemPackages = with pkgs; [
      bpftools
      pahole
      clang
      llvm
    ];
  };
}
