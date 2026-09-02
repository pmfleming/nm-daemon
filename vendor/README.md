# Vendored daemon framework

The `shelllist-daemon-core` and `shelllist-daemon-tokio` crates are vendored
from `pmfleming/daemon-framework` commit
`2b964619deeb9c7b10b77c83bde91fc80f8b640c`.

They are kept in-tree so a standalone nm-daemon checkout builds without an
adjacent daemon-framework repository. To update them, copy both crate `src/`
directories from one reviewed framework commit, preserve the standalone
package manifests here, update the commit above, and run the full Cargo and
Nix checks.
