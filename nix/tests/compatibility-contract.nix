# Cheap source-contract guard: catch fixture/client/export drift before VM use.
# The VMs remain the authoritative runtime check; this is not a Rust/Nix parser.
{ pkgs }:
pkgs.runCommand "nm-compatibility-interface-contract" { } ''
  ${pkgs.python3}/bin/python3 -B - <<'PY'
  import re
  from pathlib import Path

  def check(protocol, daemon, compatibility, writer):
      def constant(name):
          matches = re.findall(r'const ' + name + r': &str = "([^"]+)";', protocol)
          if len(matches) != 1:
              raise ValueError("src/protocol.rs: missing or ambiguous " + name)
          return matches[0]

      interface = constant("DBUS_INTERFACE")
      export = '#[zbus::interface(name = "' + interface + '")]\nimpl NmDaemonInterface'
      if export not in daemon:
          raise ValueError("src/daemon.rs: export differs from client interface")
      call = " ".join([constant("DBUS_BUS_NAME"), constant("DBUS_OBJECT_PATH"), interface, "Call ss"])
      if call not in compatibility:
          raise ValueError("nix/tests/compatibility.nix: busctl endpoint differs from client")
      if '"' + interface + '"' not in writer:
          raise ValueError("nix/tests/credential-writer.py: interface differs from client")

  sources = [Path(path).read_text() for path in [
      "${../../src/protocol.rs}", "${../../src/daemon.rs}",
      "${./compatibility.nix}", "${./credential-writer.py}",
  ]]
  check(*sources)
  # Prove the guard catches the retired-v1 regression in every independent
  # declaration, including accidental drift in the supposedly authoritative one.
  for index in range(len(sources)):
      mutated = sources.copy()
      mutated[index] = mutated[index].replace("org.laufan.NmDaemon2", "org.laufan.NmDaemon1")
      if mutated[index] == sources[index]:
          raise ValueError("update the mutation fixture when intentionally changing the ABI")
      try:
          check(*mutated)
      except ValueError:
          pass
      else:
          raise AssertionError("accepted interface drift in source " + str(index))
  for before, after in [("DBUS_INTERFACE", "MISSING_INTERFACE"), ("/org/laufan/NmDaemon", "/retired/path")]:
      mutated = sources.copy()
      mutated[0] = mutated[0].replace(before, after)
      try:
          check(*mutated)
      except ValueError:
          pass
      else:
          raise AssertionError("accepted missing or mismatched endpoint")
  print("PASS client/export/VM endpoint agreement and six negative drift cases")
  PY
  touch $out
''
