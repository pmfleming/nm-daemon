# Explicit opt-in: selecting the companion module alone does not change NM.
{ self }:
{ lib, pkgs, ... }:
{
  networking.networkmanager.package =
    lib.mkDefault
      self.packages.${pkgs.stdenv.hostPlatform.system}.networkmanagerStable;
}
