{
  description = "NetworkManager D-Bus Wi-Fi helper";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (system: pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "nm-wifi";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = with pkgs; [ makeWrapper pkg-config ];
          postInstall = ''
            wrapProgram $out/bin/nm-wifi --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.iw ]}
          '';
          meta = {
            description = "NetworkManager D-Bus Wi-Fi helper";
            mainProgram = "nm-wifi";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      apps = forAllSystems (system: pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nm-wifi";
          meta.description = "Run the nm-wifi NetworkManager helper";
        };
      });

      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            clippy
            gcc
            iw
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
