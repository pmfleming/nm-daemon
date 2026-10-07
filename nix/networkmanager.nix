# Production baseline: released 1.58.1 plus narrowly scoped upstream fixes.
# Importing this derivation never changes the host's running service.
{ pkgs }:
let
  revision = "7406dfbcc35beed79bf2734e3e7376ead320bd99";
  fixes = [
    {
      revision = "f84bd5115485a78a5f8c12e910c5b7a0674bd0e3";
      hash = "sha256-8B4MwgbkKyVqyylKp0zRyG3gy6dfWhLwtsMURAtEf0k=";
      purpose = "Create new IWD mirrored profiles atomically with mode 0600";
    }
    {
      revision = "cca7761701c6c727bcfdf2e7517a73220ba6df4c";
      hash = "sha256-NQcPQKBZEW86+bwSnieUU/ln9Hp/GR65k7CvbyGcds8=";
      purpose = "Accept peaplabel=0 in supplicant configuration verification";
    }
  ];
  # BPF cannot accept the host compiler wrapper's stack/zero-register hardening
  # flags. Only this BPF compiler drops them; NM's native C build stays hardened.
  bpfClang = pkgs.writeShellScript "clang-bpf" ''
    NIX_HARDENING_ENABLE= exec ${pkgs.clang}/bin/clang "$@"
  '';
  provenance = pkgs.writeText "networkmanager-provenance.json" (
    builtins.toJSON {
      version = "1.58.1";
      inherit revision fixes;
      upstream = "https://github.com/NetworkManager/NetworkManager";
    }
  );
in
pkgs.networkmanager.overrideAttrs (old: {
  version = "1.58.1";
  src = pkgs.fetchurl {
    name = "NetworkManager-1.58.1.tar.gz";
    url = "https://codeload.github.com/NetworkManager/NetworkManager/tar.gz/${revision}";
    hash = "sha256-hDMGrVSjAG73pgumKTKjogFcyH1GvUOP1ayQbZUsiNY=";
  };
  patches =
    (builtins.filter (patch: !(pkgs.lib.hasSuffix "-fix-paths.patch" (toString patch))) (
      old.patches or [ ]
    ))
    ++ [
      (pkgs.replaceVars ./networkmanager-fix-paths.patch {
        inherit (pkgs) runtimeShell ethtool gnused;
      })
    ]
    ++ map (
      fix:
      pkgs.fetchpatch {
        url = "https://github.com/NetworkManager/NetworkManager/commit/${fix.revision}.patch";
        # Development release notes do not apply to the released stable tree.
        excludes = [ "NEWS" ];
        inherit (fix) hash;
      }
    ) fixes;
  # 1.58 enables CLAT by default; retain it rather than disabling new features
  # just to reuse the older Nixpkgs recipe.
  buildInputs = old.buildInputs ++ [
    pkgs.libbpf
    pkgs.slang
  ];
  nativeBuildInputs = old.nativeBuildInputs ++ [
    pkgs.clang
    pkgs.bpftools
  ];
  mesonFlags = builtins.filter (flag: flag != "-Dtests=no") old.mesonFlags ++ [ "-Dtests=yes" ];
  postPatch = (old.postPatch or "") + ''
    substituteInPlace src/core/bpf/meson.build \
      --replace-fail "find_program('clang'," "find_program('${bpfClang}',"
  '';
  # Only this pure upstream suite: the full suite requires privileged networking.
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    meson test --no-rebuild --print-errorlogs supplicant/test-supplicant-config
    runHook postCheck
  '';
  postInstall = (old.postInstall or "") + ''
    install -Dm444 ${provenance} $out/share/nm-daemon/networkmanager-provenance.json
  '';
  passthru = (old.passthru or { }) // {
    nmDaemonProvenance = { inherit revision fixes; };
  };
})
