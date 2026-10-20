# Stable production baseline or pinned development compatibility target.
# Importing this derivation never changes the host's running service.
{
  pkgs,
  development ? false,
}:
let
  version = if development then "1.59.2-dev" else "1.58.1";
  revision =
    if development then
      "ed279d788f3b1443254f8ba5a8a3217cf1cf9596"
    else
      "7406dfbcc35beed79bf2734e3e7376ead320bd99";
  fixes =
    if development then
      [ ]
    else
      [
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
        {
          revision = "f772ae0108d80741c485a3847793cf1a5d6c4e1a";
          hash = "sha256-WILKnk2oHNu4Yg1TPeHqEQky1r55xF94gEJyJdJi0Eg=";
          purpose = "Keep devices alive throughout queued state transitions";
        }
        {
          revision = "38698689ccf33229e427bcfcf1041ddf31aa0430";
          hash = "sha256-FFCzAX7Kg6afywO5HPAtjFqIOlxC2/+Qv/xSdbYXgqE=";
          purpose = "Use the inner IPv6 pseudo-header for CLAT ICMP checksums";
        }
        {
          revision = "03ab223b9da95e423ea3e236b368caf6308efb50";
          hash = "sha256-ChOoqvRMChbJeyqdNll28Hf1SN+ZwYiDz+vcyTWHLUI=";
          purpose = "Preserve CLAT ICMP checksums with truncated inner L4 headers";
        }
        {
          revision = "ab4c4c62762ec1b92aae7c2c5f4128858be448f5";
          hash = "sha256-8roerGBS23Yd8RFmdZ8Nq359uvNHzCaWwEBck6sTZfE=";
          purpose = "Handle zero-checksum UDP packets quoted inside CLAT ICMP";
        }
      ];
  # BPF cannot accept the host compiler wrapper's stack/zero-register hardening
  # flags. Only this BPF compiler drops them; NM's native C build stays hardened.
  bpfClang = pkgs.writeShellScript "clang-bpf" ''
    NIX_HARDENING_ENABLE= exec ${pkgs.clang}/bin/clang "$@"
  '';
  provenance = pkgs.writeText "networkmanager-provenance.json" (
    builtins.toJSON {
      inherit version revision fixes;
      upstream = "https://github.com/NetworkManager/NetworkManager";
    }
  );
in
pkgs.networkmanager.overrideAttrs (old: {
  inherit version;
  src = pkgs.fetchurl {
    name = "NetworkManager-${version}.tar.gz";
    url = "https://codeload.github.com/NetworkManager/NetworkManager/tar.gz/${revision}";
    hash =
      if development then
        "sha256-0KnO1cFXDFZEPht1dczHdIz1AuKpukQcla6UyWS4bbU="
      else
        "sha256-hDMGrVSjAG73pgumKTKjogFcyH1GvUOP1ayQbZUsiNY=";
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
  # 1.58 builds CLAT by default (runtime opt-in); retain it rather than disabling
  # new features just to reuse the older Nixpkgs recipe.
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
  # Pure upstream suites: the full suite requires privileged networking.
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    meson test --no-rebuild --print-errorlogs supplicant/test-supplicant-config test-devices-wifi
    runHook postCheck
  '';
  postInstall = (old.postInstall or "") + ''
    install -Dm444 ${provenance} $out/share/nm-daemon/networkmanager-provenance.json
  '';
  passthru = (old.passthru or { }) // {
    nmDaemonProvenance = {
      inherit
        version
        revision
        fixes
        development
        ;
    };
  };
})
