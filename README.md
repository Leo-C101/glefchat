# GlefChat
## Description
A chat application for me and my friends.

I made this using generative AI. It should not be used as a measure of my skills.

## Running

Start the authenticated server with `cargo run --bin server`, then start the client with `cargo run --bin glefchat`. The server listens only on `127.0.0.1:8080` by default. It creates a local TLS certificate and private key, plus its Argon2 password-hash database, under the platform config directory in `glefchat/`. The key and account database are restricted to the current OS user on Unix. Account passwords must be at least 12 bytes.

For another client on the same machine, the client trusts the generated certificate at `~/.config/glefchat/server-cert.pem` on Linux. On other platforms, use the corresponding platform config directory. The first run requires starting the server once so it can generate the certificate.

For a network deployment, configure the server with `CHAT_BIND_ADDR` (for example, `0.0.0.0:8080`) and provide a certificate and key whose names match the server address using `CHAT_TLS_CERT` and `CHAT_TLS_KEY`. Configure clients with `CHAT_ADDR=host:8080`, `CHAT_TLS_CERT` pointing to that certificate or its issuing CA, and optionally `CHAT_TLS_SERVER_NAME` when the certificate name differs from the address. Distribute the trust certificate through a trusted channel; do not expose the loopback self-signed certificate as a public server certificate.

Authentication and chat state are server-side. Existing local-only accounts are not imported; register them again against the server. Local theme preferences are retained per username.

## User roles

New accounts are members by default. Set the server-only `CHAT_ADMIN_USERNAMES` environment variable to a comma-separated list of usernames to grant administrator status at registration and restore it at server startup. For example, start the server with `CHAT_ADMIN_USERNAMES=alice,bob cargo run --bin server`. Register those accounts after configuring the variable. Do not expose this setting to clients.

Administrators can assign member, moderator, or admin roles from a user's profile. Moderators and administrators can ban or unban users below their own role; administrators can also moderate moderators. Bans reject future logins and end active sessions. The current permission model includes separate channel-management and server-information permissions for future text-channel and server-setting controls, but those features are not implemented yet.