set dotenv-load := false

check:
    cargo fmt -- --check
    cargo clippy -- -D warnings
    cargo test

fmt:
    cargo fmt

run *args:
    cargo run -- {{args}}

list:
    cargo run -- wifi networks

scan:
    cargo run -- wifi scan --timeout 20

daemon:
    cargo run -- daemon

connect-parity-probe *args:
    nix run .#connectParityProbe -- {{args}}
