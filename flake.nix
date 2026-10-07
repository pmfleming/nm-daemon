{
  description = "NetworkManager JSON/JSONL adapter and user D-Bus daemon";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # Co-development: one live sibling framework; no per-daemon revision pins.
  # Use ../daemon-framework/tools/local-build for Nix builds/checks.
  inputs.daemonFramework = {
    url = "git+file:../daemon-framework";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      daemonFramework,
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        system: pkgs:
        let
          nmDaemon = daemonFramework.lib.buildRustPackage pkgs {
            pname = "nm-daemon";
            version = "0.1.0";
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./.cargo/config.toml
                ./build.rs
                ./src
                ./test_support
                ./config
                ./data
              ];
            };
            postUnpack = ''
              cp -R --no-preserve=mode ${daemonFramework.lib.daemonSource pkgs} "$(dirname "$sourceRoot")/daemon-framework"
            '';
            cargoLock.lockFile = ./Cargo.lock;
            checkFlags = [ "--test-threads=1" ];
            nativeBuildInputs = with pkgs; [ pkg-config ];
            nativeCheckInputs = [ pkgs.dbus ];
            postInstall = ''
              install -Dm644 ${./packaging/systemd/nm-daemon.service} $out/share/systemd/user/nm-daemon.service
              install -Dm644 ${./packaging/dbus/org.laufan.NmDaemon.service} \
                $out/share/dbus-1/services/org.laufan.NmDaemon.service
              install -Dm644 ${./packaging/systemd/nm-cast-policy.service} \
                $out/lib/systemd/system/nm-cast-policy.service
              install -Dm644 ${./packaging/dbus/org.laufan.NmCastPolicy.conf} \
                $out/share/dbus-1/system.d/org.laufan.NmCastPolicy.conf
              install -Dm755 ${./packaging/NetworkManager/90-nm-cast-policy} \
                $out/lib/NetworkManager/dispatcher.d/90-nm-cast-policy
              substituteInPlace $out/lib/systemd/system/nm-cast-policy.service \
                --replace-fail @out@ $out \
                --replace-fail @nft@ ${pkgs.nftables}/bin/nft
              substituteInPlace $out/lib/NetworkManager/dispatcher.d/90-nm-cast-policy \
                --replace-fail @out@ $out
              patchShebangs $out/lib/NetworkManager/dispatcher.d/90-nm-cast-policy
              substituteInPlace \
                $out/share/systemd/user/nm-daemon.service \
                $out/share/dbus-1/services/org.laufan.NmDaemon.service \
                --replace-fail @out@ $out
            '';
            meta = {
              description = "NetworkManager JSON/JSONL adapter and user D-Bus daemon";
              mainProgram = "nm-daemon";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = nmDaemon;
          networkmanagerStable = import ./nix/networkmanager.nix { inherit pkgs; };
          connectParityProbe = pkgs.writeShellApplication {
            name = "nm-daemon-connect-parity-probe";
            runtimeInputs = [
              pkgs.coreutils
              pkgs.jq
              pkgs.networkmanager
              nmDaemon
            ];
            checkPhase = ''
              runHook preCheck
              ${pkgs.stdenv.shellDryRun} "$target"
              ${pkgs.shellcheck}/bin/shellcheck --exclude=SC2016 "$target"
              runHook postCheck
            '';
            text = builtins.readFile ./tools/connect-parity-probe.sh;
            meta = {
              description = "Compare nm-daemon and nmcli Wi-Fi connection behavior for visible networks";
              mainProgram = "nm-daemon-connect-parity-probe";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        }
      );

      nixosModules.default = import ./nix/nixos.nix { inherit self; };
      nixosModules.networkManager = import ./nix/nixos-networkmanager.nix { inherit self; };

      checks = forAllSystems (
        system: pkgs: {
          package = self.packages.${system}.default;
          connectParityProbe = self.packages.${system}.connectParityProbe;
          castPolicy = import ./nix/tests/cast-policy.nix { inherit self pkgs; };
          enterprise = import ./nix/tests/enterprise.nix { inherit self pkgs; };
        }
      );

      apps = forAllSystems (
        system: pkgs: {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/nm-daemon";
            meta.description = "Run the nm-daemon NetworkManager adapter/service";
          };
          connectParityProbe = {
            type = "app";
            program = "${self.packages.${system}.connectParityProbe}/bin/nm-daemon-connect-parity-probe";
            meta.description = "Compare nm-daemon and nmcli Wi-Fi connection behavior";
          };
        }
      );

      devShells = forAllSystems (
        system: pkgs: {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              cargo-llvm-cov
              cargo-machete
              clippy
              gcc
              heaptrack
              just
              llvmPackages.llvm
              pkg-config
              python3
              rust-analyzer
              rustc
              rustfmt
            ];

            LLVM_COV = "${pkgs.llvmPackages.llvm}/bin/llvm-cov";
            LLVM_PROFDATA = "${pkgs.llvmPackages.llvm}/bin/llvm-profdata";
            RUST_BACKTRACE = "1";

            shellHook = ''
              ${pkgs.bash}/bin/bash "$PWD/tools/trim-target.sh"
            '';
          };
        }
      );

      formatter = forAllSystems (system: pkgs: pkgs.nixpkgs-fmt);
    };
}
