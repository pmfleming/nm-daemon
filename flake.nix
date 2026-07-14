{
  description = "NetworkManager JSON/JSONL adapter and user D-Bus daemon";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
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
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = with pkgs; [ pkg-config ];
            postInstall = ''
              install -Dm644 ${./packaging/systemd/nm-daemon.service} $out/share/systemd/user/nm-daemon.service
              substituteInPlace $out/share/systemd/user/nm-daemon.service --replace-fail @out@ $out
            '';
            meta = {
              description = "NetworkManager JSON/JSONL adapter and user D-Bus daemon";
              mainProgram = "nm-daemon";
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
            clippy
            gcc
            just
            pkg-config
            rust-analyzer
            rustc
            rustfmt
          ];

          RUST_BACKTRACE = "1";
        };
      });

      formatter = forAllSystems (system: pkgs: pkgs.nixpkgs-fmt);
    };
}
