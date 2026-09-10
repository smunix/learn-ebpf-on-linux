{ pkgs, ebpfLabModule }:
pkgs.testers.nixosTest {
  name = "learn-ebpf-lab-audit";

  nodes.lab = { ... }: {
    imports = [ ebpfLabModule ];
    services.learn-ebpf-lab.enable = true;
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    start_all()
    lab.wait_for_unit("multi-user.target")
    lab.succeed("test -r /sys/kernel/btf/vmlinux")
    lab.succeed("grep -qw bpf /sys/kernel/security/lsm")
    lab.succeed("bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head -n 1")
  '';
}
