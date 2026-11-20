# Rust
Manifests: `Cargo.toml`, `Cargo.lock`. Tests: `cargo test`. Audit: `cargo audit`, osv-scanner.
Upgrade: `cargo update -p NAME --precise VERSION`; transitive pins via `[patch]`. Review `unsafe` blocks flagged by semgrep manually.
