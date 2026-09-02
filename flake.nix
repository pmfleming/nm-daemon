{
  description = "NetworkManager JSON/JSONL adapter and user D-Bus daemon";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.daemonFramework = {
    url = "git+file:../daemon-framework?ref=main";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, daemonFramework }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (system: pkgs:
        let
          nmDaemon = pkgs.rustPlatform.buildRustPackage {
            pname = "nm-daemon";
            version = "0.1.0";
            src = ./.;
            postUnpack = ''
              cp -R --no-preserve=mode ${daemonFramework} "$(dirname "$sourceRoot")/daemon-framework"
            '';
            cargoLock.lockFile = ./Cargo.lock;
            checkFlags = [ "--test-threads=1" ];
            nativeBuildInputs = with pkgs; [ pkg-config ];
            postInstall = ''
              install -Dm644 ${./packaging/systemd/nm-daemon.service} $out/share/systemd/user/nm-daemon.service
              install -Dm644 ${./packaging/dbus/org.laufan.NmDaemon.service} \
                $out/share/dbus-1/services/org.laufan.NmDaemon.service
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
        });

      checks = forAllSystems (system: pkgs: {
        package = self.packages.${system}.default;
        connectParityProbe = self.packages.${system}.connectParityProbe;
      });

      apps = forAllSystems (system: pkgs: {
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
      });

      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            cargo-llvm-cov
            clippy
            gcc
            just
            llvmPackages.llvm
            pkg-config
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
      });

      formatter = forAllSystems (system: pkgs: pkgs.nixpkgs-fmt);
    };
}
