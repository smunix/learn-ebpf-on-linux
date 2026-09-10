{
  description = "Learning eBPF on Linux: a reproducible Rust, Aya, and NixOS lab";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, rust-overlay, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      foundation = import ./nix/packages.nix { inherit pkgs; };
      ebpfLabModule = import ./nix/nixos-ebpf-lab.nix;
      vmTest = import ./nix/vm-test.nix {
        inherit pkgs;
        inherit ebpfLabModule;
      };
    in
    {
      formatter.${system} = pkgs.nixfmt-rfc-style;

      packages.${system} = foundation.packages;
      devShells.${system}.default = import ./nix/devshell.nix { inherit pkgs; };
      checks.${system} = foundation.checks // {
        vm-test = vmTest;
      };

      nixosModules = {
        default = ebpfLabModule;
        ebpf-lab = ebpfLabModule;
      };

      nixosConfigurations.ebpf-lab = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ebpfLabModule
          ({ ... }: {
            services.learn-ebpf-lab.enable = true;
            networking.hostName = "learn-ebpf-lab";
            boot.loader.grub.device = "/dev/vda";
            fileSystems."/" = {
              device = "/dev/disk/by-label/nixos";
              fsType = "ext4";
            };
            system.stateVersion = "24.11";
            virtualisation.vmVariant.virtualisation.graphics = false;
          })
        ];
      };
    };
}
