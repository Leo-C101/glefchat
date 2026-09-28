use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use base64::Engine;
use protocol::{
    ClientMessage, MAX_PROFILE_IMAGE_SIZE, Permission, ServerMessage, UserProfile, UserRole,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio_rustls::TlsAcceptor;

#[path = "../protocol.rs"]
mod protocol;

const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 1024;
const MAX_MESSAGE_LENGTH: usize = 4096;
const MAX_REQUEST_LENGTH: usize = 1_500_000;
const MAX_CONNECTIONS: usize = 128;

#[derive(Default, Serialize, Deserialize)]
struct UserStore {
    users: HashMap<String, String>,
    #[serde(default)]
    profiles: HashMap<String, UserProfile>,
    #[serde(default)]
    roles: HashMap<String, UserRole>,
    #[serde(default)]
    banned_users: HashSet<String>,
    #[serde(skip)]
    bootstrap_admins: HashSet<String>,
}

#[derive(Clone)]
enum Broadcast {
    ChatMessage { author: String, content: String },
    ProfileUpdated(UserProfile),
}

fn valid_profile_image(image: &Option<String>) -> bool {
    image.as_ref().is_none_or(|image| {
        base64::engine::general_purpose::STANDARD
            .decode(image)
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_PROFILE_IMAGE_SIZE)
    })
}

fn user_profile(store: &UserStore, username: &str) -> UserProfile {
    let mut profile = store
        .profiles
        .get(username)
        .cloned()
        .unwrap_or_else(|| UserProfile {
            username: username.to_string(),
            picture: None,
            banner: None,
            role: UserRole::Member,
            banned: false,
        });
    profile.role = store.roles.get(username).copied().unwrap_or_default();
    profile.banned = store.banned_users.contains(username);
    profile
}

fn parse_admin_usernames(value: &str) -> HashSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|username| valid_username(username))
        .map(str::to_string)
        .collect()
}

fn configured_admin_usernames() -> HashSet<String> {
    std::env::var("CHAT_ADMIN_USERNAMES")
        .map(|value| parse_admin_usernames(&value))
        .unwrap_or_default()
}

fn can_moderate_user(actor: UserRole, target: UserRole) -> bool {
    actor.has_permission(Permission::BanUsers) && target.level() < actor.level()
}

fn role_change_error(
    actor: &str,
    actor_role: UserRole,
    target: &str,
    target_role: UserRole,
    new_role: UserRole,
    admin_count: usize,
) -> Option<&'static str> {
    if !actor_role.has_permission(Permission::ManageRoles) {
        Some("Only administrators can change roles.")
    } else if actor == target {
        Some("You cannot change your own role.")
    } else if target_role == UserRole::Admin && new_role != UserRole::Admin && admin_count <= 1 {
        Some("The last administrator cannot be demoted.")
    } else {
        None
    }
}

impl UserStore {
    fn load() -> io::Result<Self> {
        let path = users_file_path()?;
        let mut store = match fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).map_err(io::Error::other)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(err) => return Err(err),
        };
        store.bootstrap_admins = configured_admin_usernames();
        let mut changed = false;
        for username in store.bootstrap_admins.clone() {
            if store.users.contains_key(&username)
                && store.roles.insert(username, UserRole::Admin) != Some(UserRole::Admin)
            {
                changed = true;
            }
        }
        if changed {
            store.save()?;
        }
        Ok(store)
    }

    fn save(&self) -> io::Result<()> {
        let path = users_file_path()?;
        ensure_private_directory(path.parent().expect("users path has a parent"))?;
        write_private_file(
            &path,
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }
}

fn app_data_dir() -> io::Result<PathBuf> {
    dirs::config_dir()
        .map(|path| path.join("glefchat"))
        .ok_or_else(|| io::Error::other("could not locate the user config directory"))
}

fn users_file_path() -> io::Result<PathBuf> {
    Ok(app_data_dir()?.join("server-users.json"))
}

fn tls_paths() -> io::Result<(PathBuf, PathBuf)> {
    let default_dir = app_data_dir()?;
    let cert = std::env::var_os("CHAT_TLS_CERT")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_dir.join("server-cert.pem"));
    let key = std::env::var_os("CHAT_TLS_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_dir.join("server-key.pem"));
    Ok((cert, key))
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_directory(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn tls_acceptor() -> io::Result<TlsAcceptor> {
    let (cert_path, key_path) = tls_paths()?;
    tls_acceptor_with_paths(&cert_path, &key_path)
}

fn tls_acceptor_with_paths(cert_path: &Path, key_path: &Path) -> io::Result<TlsAcceptor> {
    match (cert_path.exists(), key_path.exists()) {
        (false, false) => {
            let certified = rcgen::generate_simple_self_signed([
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ])
            .map_err(io::Error::other)?;
            write_private_file(cert_path, certified.cert.pem().as_bytes())?;
            write_private_file(key_path, certified.signing_key.serialize_pem().as_bytes())?;
        }
        (true, true) => {}
        _ => {
            return Err(io::Error::other(
                "TLS certificate and key must be provided together",
            ));
        }
    }

    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(io::Error::other)?;
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(key_path)?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if certs.is_empty() || keys.len() != 1 {
        return Err(io::Error::other(
            "TLS files must contain certificates and one PKCS#8 key",
        ));
    }

    let key = PrivateKeyDer::Pkcs8(keys.remove(0));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

async fn read_request_line(
    reader: &mut (impl AsyncBufRead + Unpin),
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(1024);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let line_end = available.iter().position(|byte| *byte == b'\n');
        let take = line_end.map_or(available.len(), |index| index + 1);
        if line.len() + take > MAX_REQUEST_LENGTH + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request is too large",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line_end.is_some() {
            return Ok(Some(line));
        }
    }
}

async fn send_response(
    writer: &mut (impl AsyncWriteExt + Unpin),
    response: ServerMessage,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(&response).map_err(io::Error::other)?;
    line.push(b'\n');
    writer.write_all(&line).await
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let tls = tls_acceptor()?;
    let users = Arc::new(Mutex::new(UserStore::load()?));
    let bind_addr =
        std::env::var("CHAT_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&bind_addr).await?;
    let (tx, _) = broadcast::channel::<Broadcast>(100);
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    println!("GlefChat server listening on {bind_addr} with TLS");
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection: {addr}");
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            drop(stream);
            eprintln!("connection limit reached; rejected {addr}");
            continue;
        };
        let rx = tx.subscribe();
        let tls = tls.clone();
        let tx = tx.clone();
        let users = users.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(std::time::Duration::from_secs(10), tls.accept(stream)).await
            {
                Ok(Ok(stream)) => {
                    if let Err(err) = handle_connection(stream, addr, tx, rx, users).await {
                        eprintln!("connection {addr} failed: {err}");
                    }
                }
                Ok(Err(err)) => eprintln!("TLS handshake failed for {addr}: {err}"),
                Err(_) => eprintln!("TLS handshake timed out for {addr}"),
            }
        });
    }
}

async fn handle_connection(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    addr: SocketAddr,
    tx: broadcast::Sender<Broadcast>,
    mut rx: broadcast::Receiver<Broadcast>,
    users: Arc<Mutex<UserStore>>,
) -> io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = AsyncBufReader::new(reader);
    let mut authenticated_user: Option<String> = None;

    loop {
        tokio::select! {
            result = read_request_line(&mut reader) => {
                let mut line = match result {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(err) => return Err(err),
                };
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                let line = match String::from_utf8(line) {
                    Ok(line) => line,
                    Err(_) => {
                        send_response(&mut writer, ServerMessage::Error {
                            message: "Request must be UTF-8.".to_string(),
                        }).await?;
                        continue;
                    }
                };

                let request = serde_json::from_str::<ClientMessage>(&line);
                let Ok(request) = request else {
                    send_response(&mut writer, ServerMessage::Error {
                        message: "Invalid request.".to_string(),
                    }).await?;
                    continue;
                };

                match request {
                    ClientMessage::Register { username, password } => {
                        if authenticated_user.is_some() {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Log out before changing accounts.".to_string(),
                            }).await?;
                        } else if !valid_username(&username) {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Username must be 3-32 letters, digits, dots, dashes, or underscores.".to_string(),
                            }).await?;
                        } else if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&password.len()) {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Password must be 8-1024 bytes long.".to_string(),
                            }).await?;
                        } else {
                            let password_to_hash = password.clone();
                            let hash = tokio::task::spawn_blocking(move || hash_password(&password_to_hash))
                                .await
                                .map_err(io::Error::other)?
                                .map_err(io::Error::other)?;
                            let mut store = users.lock().await;
                            if store.users.contains_key(&username) {
                                send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                    message: "That username is already taken.".to_string(),
                                }).await?;
                            } else {
                                store.users.insert(username.clone(), hash);
                                let role = if store.bootstrap_admins.contains(&username) {
                                    UserRole::Admin
                                } else {
                                    UserRole::Member
                                };
                                store.roles.insert(username.clone(), role);
                                if let Err(err) = store.save() {
                                    store.users.remove(&username);
                                    store.roles.remove(&username);
                                    return Err(err);
                                }
                                authenticated_user = Some(username.clone());
                                let profile = user_profile(&store, &username);
                                send_response(&mut writer, ServerMessage::Authenticated {
                                    username,
                                    picture: profile.picture,
                                    banner: profile.banner,
                                    role: profile.role,
                                }).await?;
                            }
                        }
                    }
                    ClientMessage::Login { username, password } => {
                        if authenticated_user.is_some() {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Log out before changing accounts.".to_string(),
                            }).await?;
                            continue;
                        }
                        if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&password.len()) {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Invalid username or password.".to_string(),
                            }).await?;
                            continue;
                        }
                        let hash = users.lock().await.users.get(&username).cloned();
                        let password_to_verify = password.clone();
                        let valid = tokio::task::spawn_blocking(move || {
                            hash.is_some_and(|hash| verify_password(&password_to_verify, &hash))
                        })
                        .await
                        .map_err(io::Error::other)?;
                        if valid {
                            let store = users.lock().await;
                            if store.banned_users.contains(&username) {
                                send_response(&mut writer, ServerMessage::AccountBanned {
                                    message: "This account is banned.".to_string(),
                                }).await?;
                                continue;
                            }
                            authenticated_user = Some(username.clone());
                            let profile = user_profile(&store, &username);
                            send_response(&mut writer, ServerMessage::Authenticated {
                                username,
                                picture: profile.picture,
                                banner: profile.banner,
                                role: profile.role,
                            }).await?;
                        } else {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Invalid username or password.".to_string(),
                            }).await?;
                        }
                    }
                    ClientMessage::Logout => {
                        authenticated_user = None;
                        send_response(&mut writer, ServerMessage::LoggedOut).await?;
                    }
                    ClientMessage::SendMessage { content } => {
                        let Some(author) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before sending messages.".to_string(),
                            }).await?;
                            continue;
                        };
                        if content.is_empty() || content.len() > MAX_MESSAGE_LENGTH {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Messages must contain 1-4096 bytes.".to_string(),
                            }).await?;
                        } else {
                            let _ = tx.send(Broadcast::ChatMessage {
                                author: author.clone(),
                                content,
                            });
                        }
                    }
                    ClientMessage::GetProfile { username } => {
                        if authenticated_user.is_none() {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before viewing profiles.".to_string(),
                            }).await?;
                        } else {
                            let store = users.lock().await;
                            send_response(&mut writer, ServerMessage::Profile(user_profile(&store, &username))).await?;
                        }
                    }
                    ClientMessage::UpdateProfile { picture, banner } => {
                        let Some(username) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before updating your profile.".to_string(),
                            }).await?;
                            continue;
                        };
                        if !valid_profile_image(&picture) || !valid_profile_image(&banner) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Profile images must be valid base64 and no larger than 512 KiB.".to_string(),
                            }).await?;
                            continue;
                        }
                        let mut store = users.lock().await;
                        let mut profile = user_profile(&store, username);
                        profile.picture = picture;
                        profile.banner = banner;
                        let previous = store.profiles.insert(username.clone(), profile.clone());
                        if let Err(err) = store.save() {
                            if let Some(previous) = previous {
                                store.profiles.insert(username.clone(), previous);
                            } else {
                                store.profiles.remove(username);
                            }
                            return Err(err);
                        }
                        drop(store);
                        let _ = tx.send(Broadcast::ProfileUpdated(profile));
                    }
                    ClientMessage::SetUserRole { username, role } => {
                        let Some(actor) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before managing roles.".to_string(),
                            }).await?;
                            continue;
                        };
                        let mut store = users.lock().await;
                        let actor_role = store.roles.get(actor).copied().unwrap_or_default();
                        let previous = store.roles.get(&username).copied().unwrap_or_default();
                        let admin_count = store.roles.values().filter(|role| **role == UserRole::Admin).count();
                        if let Some(message) = role_change_error(
                            actor,
                            actor_role,
                            &username,
                            previous,
                            role,
                            admin_count,
                        ) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: message.to_string(),
                            }).await?;
                            continue;
                        }
                        if !store.users.contains_key(&username) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "That user does not exist.".to_string(),
                            }).await?;
                            continue;
                        }
                        store.roles.insert(username.clone(), role);
                        if let Err(err) = store.save() {
                            store.roles.insert(username.clone(), previous);
                            return Err(err);
                        }
                        let profile = user_profile(&store, &username);
                        drop(store);
                        let _ = tx.send(Broadcast::ProfileUpdated(profile));
                    }
                    ClientMessage::SetUserBanned { username, banned } => {
                        let Some(actor) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before moderating users.".to_string(),
                            }).await?;
                            continue;
                        };
                        let mut store = users.lock().await;
                        let actor_role = store.roles.get(actor).copied().unwrap_or_default();
                        let target_role = store.roles.get(&username).copied().unwrap_or_default();
                        if !actor_role.has_permission(Permission::BanUsers) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "You do not have permission to ban users.".to_string(),
                            }).await?;
                            continue;
                        }
                        if actor == &username || !can_moderate_user(actor_role, target_role) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "You cannot moderate this account.".to_string(),
                            }).await?;
                            continue;
                        }
                        if !store.users.contains_key(&username) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "That user does not exist.".to_string(),
                            }).await?;
                            continue;
                        }
                        let was_banned = store.banned_users.contains(&username);
                        if banned {
                            store.banned_users.insert(username.clone());
                        } else {
                            store.banned_users.remove(&username);
                        }
                        if let Err(err) = store.save() {
                            if was_banned {
                                store.banned_users.insert(username.clone());
                            } else {
                                store.banned_users.remove(&username);
                            }
                            return Err(err);
                        }
                        let profile = user_profile(&store, &username);
                        drop(store);
                        let _ = tx.send(Broadcast::ProfileUpdated(profile));
                    }
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(Broadcast::ChatMessage { author, content }) => {
                        if authenticated_user.is_some() {
                            send_response(&mut writer, ServerMessage::ChatMessage { author, content }).await?;
                        }
                    }
                    Ok(Broadcast::ProfileUpdated(profile)) => {
                        if profile.banned
                            && authenticated_user.as_deref() == Some(profile.username.as_str())
                        {
                            send_response(&mut writer, ServerMessage::AccountBanned {
                                message: "Your account has been banned.".to_string(),
                            }).await?;
                            break;
                        }
                        if authenticated_user.is_some() {
                            send_response(&mut writer, ServerMessage::ProfileUpdated(profile)).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("Client lagged; skipped {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    println!("Connection closed: {addr}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        UserStore, can_moderate_user, handle_connection, hash_password, parse_admin_usernames,
        role_change_error, tls_acceptor_with_paths, valid_profile_image, valid_username,
        verify_password,
    };
    use crate::protocol::{ClientMessage, ServerMessage, UserProfile};
    use crate::protocol::{MAX_PROFILE_IMAGE_SIZE, Permission, UserRole};
    use base64::Engine;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use serde::Serialize;
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io::{self, BufReader};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{
        AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader as AsyncBufReader,
    };
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex, broadcast};
    use tokio_rustls::TlsConnector;

    async fn send_message(
        writer: &mut (impl AsyncWrite + Unpin),
        message: &impl Serialize,
    ) -> io::Result<()> {
        let mut line = serde_json::to_vec(message).map_err(io::Error::other)?;
        line.push(b'\n');
        writer.write_all(&line).await
    }

    async fn read_message(reader: &mut (impl AsyncBufRead + Unpin)) -> io::Result<ServerMessage> {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        serde_json::from_str(&line).map_err(io::Error::other)
    }

    #[test]
    fn username_validation_rejects_control_characters() {
        assert!(valid_username("alice_42"));
        assert!(!valid_username("al"));
        assert!(!valid_username("alice\t42"));
    }

    #[test]
    fn roles_grant_only_their_configured_permissions() {
        assert!(!UserRole::Member.has_permission(Permission::BanUsers));
        assert!(UserRole::Moderator.has_permission(Permission::BanUsers));
        assert!(!UserRole::Moderator.has_permission(Permission::ManageRoles));
        assert!(UserRole::Admin.has_permission(Permission::ManageRoles));
        assert!(UserRole::Admin.has_permission(Permission::ManageChannels));
        assert!(UserRole::Admin.has_permission(Permission::ManageServerInfo));
    }

    #[test]
    fn moderators_can_only_moderate_lower_roles() {
        assert!(can_moderate_user(UserRole::Moderator, UserRole::Member));
        assert!(!can_moderate_user(UserRole::Moderator, UserRole::Moderator));
        assert!(!can_moderate_user(UserRole::Moderator, UserRole::Admin));
        assert!(can_moderate_user(UserRole::Admin, UserRole::Moderator));
        assert!(!can_moderate_user(UserRole::Admin, UserRole::Admin));
        assert!(!can_moderate_user(UserRole::Member, UserRole::Member));
    }

    #[test]
    fn role_changes_require_admin_and_protect_self_and_last_admin() {
        assert_eq!(
            role_change_error(
                "alice",
                UserRole::Moderator,
                "bob",
                UserRole::Member,
                UserRole::Moderator,
                1,
            ),
            Some("Only administrators can change roles.")
        );
        assert_eq!(
            role_change_error(
                "alice",
                UserRole::Admin,
                "alice",
                UserRole::Admin,
                UserRole::Member,
                1,
            ),
            Some("You cannot change your own role.")
        );
        assert_eq!(
            role_change_error(
                "alice",
                UserRole::Admin,
                "bob",
                UserRole::Admin,
                UserRole::Member,
                1,
            ),
            Some("The last administrator cannot be demoted.")
        );
        assert_eq!(
            role_change_error(
                "alice",
                UserRole::Admin,
                "bob",
                UserRole::Admin,
                UserRole::Moderator,
                2,
            ),
            None
        );
    }

    #[test]
    fn admin_bootstrap_list_is_trimmed_and_validated() {
        let admins = parse_admin_usernames(" alice, invalid name, bob_2, al ");
        assert_eq!(
            admins,
            HashSet::from(["alice".to_string(), "bob_2".to_string()])
        );
    }

    #[test]
    fn legacy_profiles_default_to_members() {
        let profile: UserProfile =
            serde_json::from_str(r#"{"username":"alice","picture":null,"banner":null}"#).unwrap();
        assert_eq!(profile.role, UserRole::Member);
        assert!(!profile.banned);
    }

    #[test]
    fn profile_images_are_limited_by_decoded_size() {
        let within_limit = vec![0; MAX_PROFILE_IMAGE_SIZE];
        let too_large = vec![0; MAX_PROFILE_IMAGE_SIZE + 1];
        assert!(valid_profile_image(&Some(
            base64::engine::general_purpose::STANDARD.encode(within_limit)
        )));
        assert!(!valid_profile_image(&Some(
            base64::engine::general_purpose::STANDARD.encode(too_large)
        )));
        assert!(!valid_profile_image(&Some("not base64".to_string())));
        assert!(valid_profile_image(&None));
    }

    #[test]
    fn password_hash_is_salted_and_verifiable() {
        let first = hash_password("correct horse battery staple").unwrap();
        let second = hash_password("correct horse battery staple").unwrap();
        assert_ne!(first, second);
        assert!(verify_password("correct horse battery staple", &first));
        assert!(!verify_password("wrong password", &first));
    }

    #[tokio::test]
    async fn tls_authenticates_users_and_server_assigns_message_authors() -> io::Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("glefchat-tls-test-{nonce}"));
        let cert_path = test_dir.join("server-cert.pem");
        let key_path = test_dir.join("server-key.pem");
        let acceptor = tls_acceptor_with_paths(&cert_path, &key_path)?;

        let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(&cert_path)?))
            .collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).map_err(io::Error::other)?;
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (tx, _) = broadcast::channel(8);
        let users = Arc::new(Mutex::new(UserStore {
            users: HashMap::from([(
                "alice".to_string(),
                hash_password("correct horse battery staple").unwrap(),
            )]),
            profiles: HashMap::new(),
            roles: HashMap::new(),
            banned_users: HashSet::new(),
            bootstrap_admins: HashSet::new(),
        }));
        let server_tx = tx.clone();
        let server_users = users.clone();
        let server = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await?;
            let stream = acceptor.accept(stream).await?;
            handle_connection(
                stream,
                addr,
                server_tx.clone(),
                server_tx.subscribe(),
                server_users,
            )
            .await
        });

        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let stream = connector.connect(server_name, stream).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = AsyncBufReader::new(reader);

        send_message(
            &mut writer,
            &ClientMessage::SendMessage {
                content: "spoof attempt".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::AuthenticationFailed { .. }
        ));

        send_message(
            &mut writer,
            &ClientMessage::Login {
                username: "alice".to_string(),
                password: "correct horse battery staple".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::Authenticated { username, role, .. }
                if username == "alice" && role == UserRole::Member
        ));

        send_message(
            &mut writer,
            &ClientMessage::SetUserRole {
                username: "alice".to_string(),
                role: UserRole::Admin,
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::Error { message } if message == "Only administrators can change roles."
        ));

        send_message(
            &mut writer,
            &ClientMessage::SetUserBanned {
                username: "bob".to_string(),
                banned: true,
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::Error { message } if message == "You do not have permission to ban users."
        ));

        let picture = base64::engine::general_purpose::STANDARD.encode(b"avatar");
        let banner = base64::engine::general_purpose::STANDARD.encode(b"banner");
        send_message(
            &mut writer,
            &ClientMessage::UpdateProfile {
                picture: Some(picture.clone()),
                banner: Some(banner.clone()),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::ProfileUpdated(profile)
                if profile.username == "alice"
                    && profile.picture.as_deref() == Some(picture.as_str())
                    && profile.banner.as_deref() == Some(banner.as_str())
        ));

        send_message(
            &mut writer,
            &ClientMessage::GetProfile {
                username: "alice".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::Profile(profile)
                if profile.username == "alice"
                    && profile.picture.as_deref() == Some(picture.as_str())
                    && profile.banner.as_deref() == Some(banner.as_str())
        ));

        send_message(
            &mut writer,
            &ClientMessage::SendMessage {
                content: "authenticated message".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::ChatMessage { author, content }
                if author == "alice" && content == "authenticated message"
        ));

        drop(writer);
        drop(reader);
        server.await.map_err(io::Error::other)??;

        std::fs::remove_dir_all(test_dir)?;
        Ok(())
    }
}
