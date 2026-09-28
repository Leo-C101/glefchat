# AGENTS.md

## Project
GlefChat is a desktop chat application written in Rust. The client UI uses Slint, and the authenticated server uses Tokio and TLS. Serde-backed JSON messages are defined in `src/protocol.rs` and used by both binaries. The Slint interface is in `ui/main-window.slint` and is compiled by `build.rs`.

## Build and Run
- Build all targets: `cargo check --all-targets`
- Run tests: `cargo test --all-targets`
- Check formatting: `cargo fmt --all -- --check`
- Run the client: `cargo run --bin glefchat`
- Run the server: `cargo run --bin server`

Run the server and client in separate terminals. On Windows, use the stable Rust MSVC toolchain and install the Visual Studio C++ Build Tools workload required by Slint. See `README.md` for TLS setup, server configuration, and platform-specific data paths.

## Code Conventions
- Follow idiomatic Rust and the existing module structure. Keep the client, server, protocol, and Slint UI responsibilities in their current layers.
- Keep UI changes in Slint and preserve the existing property/callback interface between `src/main.rs` and `ui/main-window.slint`.
- Add focused unit tests alongside Rust logic; the project currently keeps tests inline in the relevant source files.
- Avoid unrelated refactors and new dependencies. Ask before adding a dependency.

## Security Boundaries
- Never hardcode credentials, private keys, or other secrets. Configure deployment-specific values through the existing `CHAT_*` environment variables; see `README.md`.
- Keep authentication, authorization, password hashing, TLS certificate verification, and private-file handling on their existing secure paths. Do not weaken validation or expose server-only settings to the client.
- Treat client messages and persisted JSON as untrusted input; validate them at the boundary and preserve the protocol's serialization compatibility.
