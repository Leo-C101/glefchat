use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use base64::Engine;
use protocol::{
    Channel, ChatServer, ChatServerView, ClientMessage, DEFAULT_CHAT_SERVER_ID,
    MAX_PROFILE_IMAGE_SIZE, Permission, ServerMessage, UserProfile, UserRole,
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
const MAX_CHANNELS: usize = 100;
const MAX_CHAT_SERVER_MEMBERS: usize = 100;
const MAX_CHANNEL_NAME_LENGTH: usize = 32;
const MAX_CHANNEL_TOPIC_LENGTH: usize = 160;
const MAX_CHAT_SERVER_NAME_LENGTH: usize = 32;

fn default_chat_server() -> ChatServer {
    ChatServer {
        id: DEFAULT_CHAT_SERVER_ID.to_string(),
        name: "GlefChat".to_string(),
        icon: None,
    }
}

fn default_channels() -> Vec<Channel> {
    vec![Channel {
        id: protocol::DEFAULT_CHANNEL_ID.to_string(),
        server_id: DEFAULT_CHAT_SERVER_ID.to_string(),
        name: "general".to_string(),
        topic: "General conversation".to_string(),
    }]
}

fn default_next_channel_id() -> u64 {
    2
}

fn default_next_chat_server_id() -> u64 {
    2
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct UserStore {
    users: HashMap<String, String>,
    #[serde(default)]
    profiles: HashMap<String, UserProfile>,
    #[serde(default)]
    roles: HashMap<String, UserRole>,
    #[serde(default)]
    banned_users: HashSet<String>,
    #[serde(default)]
    session_tokens: HashMap<String, String>,
    #[serde(default)]
    channels: Vec<Channel>,
    #[serde(default)]
    chat_servers: Vec<ChatServer>,
    #[serde(default)]
    server_members: HashMap<String, HashSet<String>>,
    #[serde(default = "default_next_channel_id")]
    next_channel_id: u64,
    #[serde(default = "default_next_chat_server_id")]
    next_chat_server_id: u64,
    #[serde(skip)]
    bootstrap_admins: HashSet<String>,
    #[serde(skip)]
    store_path: Option<PathBuf>,
}

#[derive(Clone)]
enum Broadcast {
    ChatMessage {
        server_id: String,
        channel_id: String,
        author: String,
        content: String,
    },
    Channels {
        server_id: String,
        channels: Vec<Channel>,
    },
    ChatServers,
    ProfileUpdated(UserProfile),
    UserJoined {
        server_id: String,
        username: String,
    },
    UserLeft {
        server_id: String,
        username: String,
    },
}

struct OnlinePresence {
    sender: broadcast::Sender<Broadcast>,
    identity: Option<(String, String)>,
}

impl OnlinePresence {
    fn new(sender: broadcast::Sender<Broadcast>) -> Self {
        Self {
            sender,
            identity: None,
        }
    }

    fn joined(&mut self, server_id: String, username: String) {
        self.left();
        self.identity = Some((server_id.clone(), username.clone()));
        let _ = self.sender.send(Broadcast::UserJoined {
            server_id,
            username,
        });
    }

    fn left(&mut self) {
        if let Some((server_id, username)) = self.identity.take() {
            let _ = self.sender.send(Broadcast::UserLeft {
                server_id,
                username,
            });
        }
    }
}

impl Drop for OnlinePresence {
    fn drop(&mut self) {
        self.left();
    }
}

fn valid_profile_image(image: &Option<String>) -> bool {
    image.as_ref().is_none_or(|image| {
        base64::engine::general_purpose::STANDARD
            .decode(image)
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_PROFILE_IMAGE_SIZE)
    })
}

fn valid_channel_name(name: &str) -> bool {
    (1..=MAX_CHANNEL_NAME_LENGTH).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_channel_topic(topic: &str) -> bool {
    topic.len() <= MAX_CHANNEL_TOPIC_LENGTH && !topic.chars().any(char::is_control)
}

fn valid_chat_server_name(name: &str) -> bool {
    (2..=MAX_CHAT_SERVER_NAME_LENGTH).contains(&name.len()) && !name.chars().any(char::is_control)
}

fn chat_server_views(store: &UserStore, username: &str) -> Vec<ChatServerView> {
    store
        .chat_servers
        .iter()
        .map(|server| {
            let members = store.server_members.get(&server.id);
            ChatServerView {
                id: server.id.clone(),
                name: server.name.clone(),
                icon: server.icon.clone(),
                member_count: members.map_or(0, |members| members.len() as u32),
                is_member: members.is_some_and(|members| members.contains(username)),
            }
        })
        .collect()
}

fn preferred_chat_server(store: &UserStore, username: &str) -> Option<String> {
    store
        .chat_servers
        .iter()
        .find(|server| {
            store
                .server_members
                .get(&server.id)
                .is_some_and(|members| members.contains(username))
        })
        .map(|server| server.id.clone())
}

fn server_channels(store: &UserStore, server_id: &str) -> Vec<Channel> {
    store
        .channels
        .iter()
        .filter(|channel| channel.server_id == server_id)
        .cloned()
        .collect()
}

fn add_chat_server_member(
    store: &mut UserStore,
    server_id: &str,
    username: &str,
) -> Result<bool, &'static str> {
    if !store
        .chat_servers
        .iter()
        .any(|server| server.id == server_id)
    {
        return Err("That server does not exist.");
    }
    let members = store
        .server_members
        .entry(server_id.to_string())
        .or_default();
    if members.contains(username) {
        return Ok(false);
    }
    if members.len() >= MAX_CHAT_SERVER_MEMBERS {
        return Err("That server is full (100 members maximum).");
    }
    members.insert(username.to_string());
    Ok(true)
}

fn remove_chat_server_member(store: &mut UserStore, server_id: &str, username: &str) -> bool {
    store
        .server_members
        .get_mut(server_id)
        .is_some_and(|members| members.remove(username))
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
        Self::load_from(&path, configured_admin_usernames())
    }

    fn load_from(path: &Path, bootstrap_admins: HashSet<String>) -> io::Result<Self> {
        let mut store = match fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).map_err(io::Error::other)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(err) => return Err(err),
        };
        store.bootstrap_admins = bootstrap_admins;
        store.store_path = Some(path.to_owned());
        let mut changed = false;
        for username in store.bootstrap_admins.clone() {
            if store.users.contains_key(&username)
                && store.roles.insert(username, UserRole::Admin) != Some(UserRole::Admin)
            {
                changed = true;
            }
        }
        if store.chat_servers.is_empty() {
            store.chat_servers.push(default_chat_server());
            changed = true;
        }
        if store.channels.is_empty() {
            store.channels = default_channels();
            changed = true;
        }
        if store
            .server_members
            .get(DEFAULT_CHAT_SERVER_ID)
            .is_none_or(HashSet::is_empty)
            && !store.users.is_empty()
        {
            let mut usernames: Vec<_> = store.users.keys().cloned().collect();
            usernames.sort();
            let members = store
                .server_members
                .entry(DEFAULT_CHAT_SERVER_ID.to_string())
                .or_default();
            for username in usernames.into_iter().take(MAX_CHAT_SERVER_MEMBERS) {
                members.insert(username);
            }
            changed = true;
        }
        if store.next_channel_id == 0 {
            store.next_channel_id = default_next_channel_id();
            changed = true;
        }
        if store.next_chat_server_id == 0 {
            store.next_chat_server_id = default_next_chat_server_id();
            changed = true;
        }
        if changed {
            store.save()?;
        }
        Ok(store)
    }

    fn save(&self) -> io::Result<()> {
        let path = match &self.store_path {
            Some(path) => path.clone(),
            None => users_file_path()?,
        };
        self.save_to(&path)
    }

    fn save_to(&self, path: &Path) -> io::Result<()> {
        ensure_private_directory(path.parent().expect("users path has a parent"))?;
        write_private_file(
            path,
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }
}

fn app_data_dir() -> io::Result<PathBuf> {
    dirs::config_dir()
        .map(|path| path.join("oxide"))
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

fn new_session_token() -> io::Result<String> {
    let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.serialize_der()))
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

    println!("Oxide server listening on {bind_addr} with TLS");
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
    let mut authenticated_session_hash: Option<String> = None;
    let mut active_server_id: Option<String> = None;
    let mut presence = OnlinePresence::new(tx.clone());

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
                            let session_token = new_session_token()?;
                            let session_token_for_hash = session_token.clone();
                            let session_hash = tokio::task::spawn_blocking(move || hash_password(&session_token_for_hash))
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
                                let members = store
                                    .server_members
                                    .entry(DEFAULT_CHAT_SERVER_ID.to_string())
                                    .or_default();
                                let joined_default = members.len() < MAX_CHAT_SERVER_MEMBERS;
                                if joined_default {
                                    members.insert(username.clone());
                                }
                                let previous_session = store.session_tokens.insert(username.clone(), session_hash.clone());
                                if let Err(err) = store.save() {
                                    store.users.remove(&username);
                                    store.roles.remove(&username);
                                    if let Some(previous_session) = previous_session {
                                        store.session_tokens.insert(username.clone(), previous_session);
                                    } else {
                                        store.session_tokens.remove(&username);
                                    }
                                    if joined_default {
                                        remove_chat_server_member(
                                            &mut store,
                                            DEFAULT_CHAT_SERVER_ID,
                                            &username,
                                        );
                                    }
                                    return Err(err);
                                }
                                authenticated_user = Some(username.clone());
                                authenticated_session_hash = Some(session_hash);
                                active_server_id = preferred_chat_server(&store, &username);
                                if let Some(server_id) = active_server_id.as_ref() {
                                    presence.joined(server_id.clone(), username.clone());
                                }
                                let profile = user_profile(&store, &username);
                                send_response(&mut writer, ServerMessage::Authenticated {
                                    username: username.clone(),
                                    picture: profile.picture,
                                    banner: profile.banner,
                                    role: profile.role,
                                    session_token,
                                }).await?;
                                send_response(&mut writer, ServerMessage::ChatServers {
                                    servers: chat_server_views(&store, &username),
                                    active_server_id: active_server_id.clone().unwrap_or_default(),
                                }).await?;
                                if let Some(server_id) = active_server_id.as_ref() {
                                    send_response(&mut writer, ServerMessage::Channels {
                                        server_id: server_id.clone(),
                                        channels: server_channels(&store, server_id),
                                    }).await?;
                                }
                                let _ = tx.send(Broadcast::ChatServers);
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
                            let session_token = new_session_token()?;
                            let session_token_for_hash = session_token.clone();
                            let session_hash = tokio::task::spawn_blocking(move || hash_password(&session_token_for_hash))
                                .await
                                .map_err(io::Error::other)?
                                .map_err(io::Error::other)?;
                            let mut store = users.lock().await;
                            if store.banned_users.contains(&username) {
                                send_response(&mut writer, ServerMessage::AccountBanned {
                                    message: "This account is banned.".to_string(),
                                }).await?;
                                continue;
                            }
                            let previous_session = store.session_tokens.insert(username.clone(), session_hash.clone());
                            if let Err(err) = store.save() {
                                if let Some(previous_session) = previous_session {
                                    store.session_tokens.insert(username.clone(), previous_session);
                                } else {
                                    store.session_tokens.remove(&username);
                                }
                                return Err(err);
                            }
                            authenticated_user = Some(username.clone());
                            authenticated_session_hash = Some(session_hash);
                            active_server_id = preferred_chat_server(&store, &username);
                            if let Some(server_id) = active_server_id.as_ref() {
                                presence.joined(server_id.clone(), username.clone());
                            }
                            let profile = user_profile(&store, &username);
                            send_response(&mut writer, ServerMessage::Authenticated {
                                username: username.clone(),
                                picture: profile.picture,
                                banner: profile.banner,
                                role: profile.role,
                                session_token,
                            }).await?;
                            send_response(&mut writer, ServerMessage::ChatServers {
                                servers: chat_server_views(&store, &username),
                                active_server_id: active_server_id.clone().unwrap_or_default(),
                            }).await?;
                            if let Some(server_id) = active_server_id.as_ref() {
                                send_response(&mut writer, ServerMessage::Channels {
                                    server_id: server_id.clone(),
                                    channels: server_channels(&store, server_id),
                                }).await?;
                            }
                        } else {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Invalid username or password.".to_string(),
                            }).await?;
                        }
                    }
                    ClientMessage::ResumeSession { username, session_token } => {
                        if authenticated_user.is_some() {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Log out before changing accounts.".to_string(),
                            }).await?;
                            continue;
                        }
                        if session_token.is_empty() || session_token.len() > 512 {
                            send_response(&mut writer, ServerMessage::SessionExpired {
                                message: "Your saved session has expired. Please sign in again.".to_string(),
                            }).await?;
                            continue;
                        }
                        let saved_hash = users.lock().await.session_tokens.get(&username).cloned();
                        let verified_hash = saved_hash.clone();
                        let token_to_verify = session_token.clone();
                        let valid = tokio::task::spawn_blocking(move || {
                            verified_hash.as_deref().is_some_and(|hash| verify_password(&token_to_verify, hash))
                        })
                        .await
                        .map_err(io::Error::other)?;
                        if !valid {
                            send_response(&mut writer, ServerMessage::SessionExpired {
                                message: "Your saved session has expired. Please sign in again.".to_string(),
                            }).await?;
                            continue;
                        }
                        let store = users.lock().await;
                        if store.banned_users.contains(&username) {
                            send_response(&mut writer, ServerMessage::AccountBanned {
                                message: "This account is banned.".to_string(),
                            }).await?;
                            continue;
                        }
                        let Some(session_hash) = saved_hash.filter(|hash| {
                            store.session_tokens.get(&username) == Some(hash)
                        }) else {
                            send_response(&mut writer, ServerMessage::SessionExpired {
                                message: "Your saved session has expired. Please sign in again.".to_string(),
                            }).await?;
                            continue;
                        };
                        authenticated_user = Some(username.clone());
                        authenticated_session_hash = Some(session_hash);
                        active_server_id = preferred_chat_server(&store, &username);
                        if let Some(server_id) = active_server_id.as_ref() {
                            presence.joined(server_id.clone(), username.clone());
                        }
                        let profile = user_profile(&store, &username);
                        send_response(&mut writer, ServerMessage::Authenticated {
                            username: username.clone(),
                            picture: profile.picture,
                            banner: profile.banner,
                            role: profile.role,
                            session_token,
                        }).await?;
                        send_response(&mut writer, ServerMessage::ChatServers {
                            servers: chat_server_views(&store, &username),
                            active_server_id: active_server_id.clone().unwrap_or_default(),
                        }).await?;
                        if let Some(server_id) = active_server_id.as_ref() {
                            send_response(&mut writer, ServerMessage::Channels {
                                server_id: server_id.clone(),
                                channels: server_channels(&store, server_id),
                            }).await?;
                        }
                    }
                    ClientMessage::Logout => {
                        presence.left();
                        if let (Some(username), Some(session_hash)) = (
                            authenticated_user.as_ref(),
                            authenticated_session_hash.as_ref(),
                        ) {
                            let mut store = users.lock().await;
                            if store.session_tokens.get(username) == Some(session_hash) {
                                store.session_tokens.remove(username);
                                store.save()?;
                            }
                        }
                        authenticated_user = None;
                        authenticated_session_hash = None;
                        active_server_id = None;
                        send_response(&mut writer, ServerMessage::LoggedOut).await?;
                    }
                    ClientMessage::CreateChatServer { name, icon } => {
                        let Some(username) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before creating a server.".to_string(),
                            }).await?;
                            continue;
                        };
                        let name = name.trim().to_string();
                        if !valid_chat_server_name(&name) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Server names must contain 2-32 characters and no control characters.".to_string(),
                            }).await?;
                            continue;
                        }
                        if !valid_profile_image(&icon) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Server icons must be valid images no larger than 512 KiB.".to_string(),
                            }).await?;
                            continue;
                        }
                        let mut store = users.lock().await;
                        if store.chat_servers.iter().any(|server| server.name.eq_ignore_ascii_case(&name)) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "A server with that name already exists.".to_string(),
                            }).await?;
                            continue;
                        }
                        let previous_server_id = store.next_chat_server_id;
                        let previous_channel_id = store.next_channel_id;
                        let (Some(next_server_id), Some(next_channel_id)) = (
                            previous_server_id.checked_add(1),
                            previous_channel_id.checked_add(1),
                        ) else {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "No more server or channel IDs are available.".to_string(),
                            }).await?;
                            continue;
                        };
                        let server_id = previous_server_id.to_string();
                        let channel_id = previous_channel_id.to_string();
                        store.chat_servers.push(ChatServer { id: server_id.clone(), name, icon });
                        store.server_members.insert(server_id.clone(), HashSet::from([username.clone()]));
                        store.channels.push(Channel {
                            id: channel_id,
                            server_id: server_id.clone(),
                            name: "general".to_string(),
                            topic: "General conversation".to_string(),
                        });
                        store.next_chat_server_id = next_server_id;
                        store.next_channel_id = next_channel_id;
                        let views = chat_server_views(&store, username);
                        let channels = server_channels(&store, &server_id);
                        let snapshot = store.clone();
                        drop(store);
                        if let Err(err) = tokio::task::spawn_blocking(move || snapshot.save())
                            .await
                            .map_err(io::Error::other)?
                        {
                            let mut store = users.lock().await;
                            store.chat_servers.retain(|server| server.id != server_id);
                            store.server_members.remove(&server_id);
                            store.channels.retain(|channel| channel.server_id != server_id);
                            store.next_chat_server_id = previous_server_id;
                            store.next_channel_id = previous_channel_id;
                            return Err(err);
                        }
                        active_server_id = Some(server_id.clone());
                        presence.joined(server_id.clone(), username.clone());
                        let _ = tx.send(Broadcast::ChatServers);
                        send_response(&mut writer, ServerMessage::ChatServers {
                            servers: views,
                            active_server_id: server_id.clone(),
                        }).await?;
                        send_response(&mut writer, ServerMessage::Channels { server_id, channels }).await?;
                    }
                    ClientMessage::JoinChatServer { server_id } => {
                        let Some(username) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before joining a server.".to_string(),
                            }).await?;
                            continue;
                        };
                        let mut store = users.lock().await;
                        let added = match add_chat_server_member(&mut store, &server_id, username) {
                            Ok(added) => added,
                            Err(message) => {
                                send_response(&mut writer, ServerMessage::Error { message: message.to_string() }).await?;
                                continue;
                            }
                        };
                        if added {
                            let snapshot = store.clone();
                            drop(store);
                            if let Err(err) = tokio::task::spawn_blocking(move || snapshot.save())
                                .await
                                .map_err(io::Error::other)?
                            {
                                let mut store = users.lock().await;
                                remove_chat_server_member(&mut store, &server_id, username);
                                return Err(err);
                            }
                            store = users.lock().await;
                        }
                        let views = chat_server_views(&store, username);
                        let channels = server_channels(&store, &server_id);
                        drop(store);
                        if active_server_id.as_deref() != Some(server_id.as_str()) {
                            active_server_id = Some(server_id.clone());
                            presence.joined(server_id.clone(), username.clone());
                        }
                        if added {
                            let _ = tx.send(Broadcast::ChatServers);
                        }
                        send_response(&mut writer, ServerMessage::ChatServers {
                            servers: views,
                            active_server_id: server_id.clone(),
                        }).await?;
                        send_response(&mut writer, ServerMessage::Channels { server_id, channels }).await?;
                    }
                    ClientMessage::SelectChatServer { server_id } => {
                        let Some(username) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before switching servers.".to_string(),
                            }).await?;
                            continue;
                        };
                        let store = users.lock().await;
                        if !store.server_members.get(&server_id).is_some_and(|members| members.contains(username)) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join that server before switching to it.".to_string(),
                            }).await?;
                            continue;
                        }
                        let views = chat_server_views(&store, username);
                        let channels = server_channels(&store, &server_id);
                        drop(store);
                        if active_server_id.as_deref() != Some(server_id.as_str()) {
                            active_server_id = Some(server_id.clone());
                            presence.joined(server_id.clone(), username.clone());
                        }
                        send_response(&mut writer, ServerMessage::ChatServers {
                            servers: views,
                            active_server_id: server_id.clone(),
                        }).await?;
                        send_response(&mut writer, ServerMessage::Channels { server_id, channels }).await?;
                    }
                    ClientMessage::LeaveChatServer { server_id } => {
                        let Some(username) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before leaving a server.".to_string(),
                            }).await?;
                            continue;
                        };
                        let mut store = users.lock().await;
                        if !remove_chat_server_member(&mut store, &server_id, username) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "You are not a member of that server.".to_string(),
                            }).await?;
                            continue;
                        }
                        let snapshot = store.clone();
                        if let Err(err) = snapshot.save() {
                            add_chat_server_member(&mut store, &server_id, username).ok();
                            return Err(err);
                        }
                        let was_active = active_server_id.as_deref() == Some(server_id.as_str());
                        if was_active {
                            presence.left();
                            active_server_id = preferred_chat_server(&store, username);
                            if let Some(next_server) = active_server_id.as_ref() {
                                presence.joined(next_server.clone(), username.clone());
                            }
                        }
                        let views = chat_server_views(&store, username);
                        let next_id = active_server_id.clone().unwrap_or_default();
                        let channels = active_server_id.as_deref().map_or_else(Vec::new, |id| server_channels(&store, id));
                        drop(store);
                        let _ = tx.send(Broadcast::ChatServers);
                        send_response(&mut writer, ServerMessage::ChatServers {
                            servers: views,
                            active_server_id: next_id.clone(),
                        }).await?;
                        send_response(&mut writer, ServerMessage::Channels {
                            server_id: next_id,
                            channels,
                        }).await?;
                    }
                    ClientMessage::SendMessage { server_id, channel_id, content } => {
                        let Some(author) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before sending messages.".to_string(),
                            }).await?;
                            continue;
                        };
                        let store = users.lock().await;
                        let is_member = store.server_members.get(&server_id)
                            .is_some_and(|members| members.contains(author));
                        if active_server_id.as_deref() != Some(server_id.as_str()) || !is_member {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join that server before sending messages.".to_string(),
                            }).await?;
                        } else if !store.channels.iter().any(|channel| channel.server_id == server_id && channel.id == channel_id) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "That channel does not exist.".to_string(),
                            }).await?;
                        } else if content.is_empty() || content.len() > MAX_MESSAGE_LENGTH {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Messages must contain 1-4096 bytes.".to_string(),
                            }).await?;
                        } else {
                            let _ = tx.send(Broadcast::ChatMessage {
                                server_id,
                                channel_id,
                                author: author.clone(),
                                content,
                            });
                        }
                    }
                    ClientMessage::CreateChannel { name, topic } => {
                        let Some(actor) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before managing channels.".to_string(),
                            }).await?;
                            continue;
                        };
                        let Some(server_id) = active_server_id.as_ref() else {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join a server before managing channels.".to_string(),
                            }).await?;
                            continue;
                        };
                        let name = name.trim().to_ascii_lowercase();
                        let topic = topic.trim().to_string();
                        let mut store = users.lock().await;
                        if !store.server_members.get(server_id).is_some_and(|members| members.contains(actor)) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join that server before managing its channels.".to_string(),
                            }).await?;
                            continue;
                        }
                        let actor_role = store.roles.get(actor).copied().unwrap_or_default();
                        if !actor_role.has_permission(Permission::ManageChannels) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "You do not have permission to manage channels.".to_string(),
                            }).await?;
                            continue;
                        }
                        if !valid_channel_name(&name) || !valid_channel_topic(&topic) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Channel names must be 1-32 lowercase letters, numbers, dashes, or underscores; topics may contain up to 160 characters.".to_string(),
                            }).await?;
                            continue;
                        }
                        if store.channels.iter().filter(|channel| channel.server_id == *server_id).count() >= MAX_CHANNELS {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "This server has reached its channel limit.".to_string(),
                            }).await?;
                            continue;
                        }
                        if store.channels.iter().any(|channel| channel.server_id == *server_id && channel.name == name) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "A channel with that name already exists.".to_string(),
                            }).await?;
                            continue;
                        }
                        let previous_next_id = store.next_channel_id;
                        let Some(next_id) = previous_next_id.checked_add(1) else {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "No more channel IDs are available.".to_string(),
                            }).await?;
                            continue;
                        };
                        store.channels.push(Channel {
                            id: previous_next_id.to_string(),
                            server_id: server_id.clone(),
                            name,
                            topic,
                        });
                        store.next_channel_id = next_id;
                        let snapshot = store.clone();
                        let channels = server_channels(&store, server_id);
                        drop(store);
                        if let Err(err) = tokio::task::spawn_blocking(move || snapshot.save())
                            .await
                            .map_err(io::Error::other)?
                        {
                            let mut store = users.lock().await;
                            store.channels.pop();
                            store.next_channel_id = previous_next_id;
                            return Err(err);
                        }
                            let _ = tx.send(Broadcast::Channels { server_id: server_id.clone(), channels });
                    }
                    ClientMessage::EditChannel { channel_id, name, topic } => {
                        let Some(actor) = authenticated_user.as_ref() else {
                            send_response(&mut writer, ServerMessage::AuthenticationFailed {
                                message: "Sign in before managing channels.".to_string(),
                            }).await?;
                            continue;
                        };
                        let Some(server_id) = active_server_id.as_ref() else {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join a server before managing channels.".to_string(),
                            }).await?;
                            continue;
                        };
                        let name = name.trim().to_ascii_lowercase();
                        let topic = topic.trim().to_string();
                        let mut store = users.lock().await;
                        if !store.server_members.get(server_id).is_some_and(|members| members.contains(actor)) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Join that server before managing its channels.".to_string(),
                            }).await?;
                            continue;
                        }
                        let actor_role = store.roles.get(actor).copied().unwrap_or_default();
                        if !actor_role.has_permission(Permission::ManageChannels) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "You do not have permission to manage channels.".to_string(),
                            }).await?;
                            continue;
                        }
                        if !valid_channel_name(&name) || !valid_channel_topic(&topic) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "Channel names must be 1-32 lowercase letters, numbers, dashes, or underscores; topics may contain up to 160 characters.".to_string(),
                            }).await?;
                            continue;
                        }
                        let Some(index) = store.channels.iter().position(|channel| channel.server_id == *server_id && channel.id == channel_id) else {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "That channel does not exist.".to_string(),
                            }).await?;
                            continue;
                        };
                        if store.channels.iter().any(|channel| channel.server_id == *server_id && channel.id != channel_id && channel.name == name) {
                            send_response(&mut writer, ServerMessage::Error {
                                message: "A channel with that name already exists.".to_string(),
                            }).await?;
                            continue;
                        }
                        let previous = store.channels[index].clone();
                        store.channels[index].name = name.clone();
                        store.channels[index].topic = topic.clone();
                        let snapshot = store.clone();
                        let channels = server_channels(&store, server_id);
                        drop(store);
                        if let Err(err) = tokio::task::spawn_blocking(move || snapshot.save())
                            .await
                            .map_err(io::Error::other)?
                        {
                            let mut store = users.lock().await;
                            if let Some(channel) = store.channels.iter_mut().find(|channel| channel.id == channel_id) {
                                if channel.name == name && channel.topic == topic {
                                    *channel = previous;
                                }
                            }
                            return Err(err);
                        }
                        let _ = tx.send(Broadcast::Channels { server_id: server_id.clone(), channels });
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
                    Ok(Broadcast::ChatMessage { server_id, channel_id, author, content }) => {
                        if active_server_id.as_deref() == Some(server_id.as_str()) {
                            send_response(&mut writer, ServerMessage::ChatMessage { server_id, channel_id, author, content }).await?;
                        }
                    }
                    Ok(Broadcast::Channels { server_id, channels }) => {
                        if active_server_id.as_deref() == Some(server_id.as_str()) {
                            send_response(&mut writer, ServerMessage::Channels { server_id, channels }).await?;
                        }
                    }
                    Ok(Broadcast::ChatServers) => {
                        if let Some(username) = authenticated_user.as_deref() {
                            let store = users.lock().await;
                            send_response(&mut writer, ServerMessage::ChatServers {
                                servers: chat_server_views(&store, username),
                                active_server_id: active_server_id.clone().unwrap_or_default(),
                            }).await?;
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
                    Ok(Broadcast::UserJoined { server_id, username }) => {
                        if active_server_id.as_deref() == Some(server_id.as_str()) {
                            send_response(&mut writer, ServerMessage::UserJoined { server_id, username }).await?;
                        }
                    }
                    Ok(Broadcast::UserLeft { server_id, username }) => {
                        if active_server_id.as_deref() == Some(server_id.as_str()) {
                            send_response(&mut writer, ServerMessage::UserLeft { server_id, username }).await?;
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
        UserStore, add_chat_server_member, can_moderate_user, default_channels,
        default_chat_server, default_next_channel_id, default_next_chat_server_id,
        handle_connection, hash_password, parse_admin_usernames, role_change_error,
        tls_acceptor_with_paths, valid_channel_name, valid_channel_topic, valid_profile_image,
        valid_username, verify_password,
    };
    use crate::protocol::{
        ClientMessage, DEFAULT_CHANNEL_ID, DEFAULT_CHAT_SERVER_ID, ServerMessage, UserProfile,
    };
    use crate::protocol::{MAX_PROFILE_IMAGE_SIZE, Permission, UserRole};
    use base64::Engine;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use serde::Serialize;
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io::{self, BufReader};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;
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

    async fn read_until(
        reader: &mut (impl AsyncBufRead + Unpin),
        mut matches: impl FnMut(&ServerMessage) -> bool,
    ) -> io::Result<ServerMessage> {
        loop {
            let message = read_message(reader).await?;
            if matches(&message) {
                return Ok(message);
            }
        }
    }

    struct TestServer {
        address: SocketAddr,
        connector: TlsConnector,
        handle: tokio::task::JoinHandle<io::Result<()>>,
    }

    impl TestServer {
        async fn start(test_dir: &Path, roles: HashMap<String, UserRole>) -> io::Result<Self> {
            let cert_path = test_dir.join("server-cert.pem");
            let key_path = test_dir.join("server-key.pem");
            let users_path = test_dir.join("server-users.json");
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

            let mut users_map = HashMap::new();
            for username in roles.keys() {
                users_map.insert(
                    username.clone(),
                    hash_password("correct horse battery staple").unwrap(),
                );
            }
            let default_members = roles.keys().cloned().collect();
            let users = Arc::new(Mutex::new(UserStore {
                users: users_map,
                profiles: HashMap::new(),
                roles,
                banned_users: HashSet::new(),
                session_tokens: HashMap::new(),
                channels: default_channels(),
                chat_servers: vec![default_chat_server()],
                server_members: HashMap::from([(
                    DEFAULT_CHAT_SERVER_ID.to_string(),
                    default_members,
                )]),
                next_channel_id: default_next_channel_id(),
                next_chat_server_id: default_next_chat_server_id(),
                bootstrap_admins: HashSet::new(),
                store_path: Some(users_path.clone()),
            }));
            let server_tx = tx.clone();
            let server_users = users.clone();
            let user_count = 4;
            let handle = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                for _ in 0..user_count {
                    let (stream, addr) = listener.accept().await?;
                    let stream = acceptor.accept(stream).await?;
                    let connection_tx = server_tx.clone();
                    let connection_rx = connection_tx.subscribe();
                    let connection_users = server_users.clone();
                    connections.spawn(async move {
                        handle_connection(
                            stream,
                            addr,
                            connection_tx,
                            connection_rx,
                            connection_users,
                        )
                        .await
                    });
                }
                while let Some(result) = connections.join_next().await {
                    result.map_err(io::Error::other)??;
                }
                Ok::<(), io::Error>(())
            });

            Ok(Self {
                address,
                connector,
                handle,
            })
        }

        async fn connect(
            &self,
        ) -> io::Result<(
            AsyncBufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
            tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
        )> {
            let stream = TcpStream::connect(self.address).await?;
            let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
            let stream = self.connector.connect(server_name, stream).await?;
            let (reader, writer) = tokio::io::split(stream);
            Ok((AsyncBufReader::new(reader), writer))
        }
    }

    async fn login_as(
        reader: &mut (impl AsyncBufRead + Unpin),
        writer: &mut (impl AsyncWrite + Unpin),
        username: &str,
    ) -> io::Result<()> {
        send_message(
            writer,
            &ClientMessage::Login {
                username: username.to_string(),
                password: "correct horse battery staple".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(reader).await?,
            ServerMessage::Authenticated { .. }
        ));
        assert!(matches!(
            read_message(reader).await?,
            ServerMessage::ChatServers { .. }
        ));
        assert!(matches!(
            read_message(reader).await?,
            ServerMessage::Channels { .. }
        ));
        assert!(matches!(
            read_message(reader).await?,
            ServerMessage::UserJoined { .. }
        ));
        Ok(())
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
        assert!(UserRole::Moderator.has_permission(Permission::ManageChannels));
        assert!(!UserRole::Moderator.has_permission(Permission::ManageRoles));
        assert!(UserRole::Admin.has_permission(Permission::ManageRoles));
        assert!(UserRole::Admin.has_permission(Permission::ManageChannels));
        assert!(UserRole::Admin.has_permission(Permission::ManageServerInfo));
    }

    #[test]
    fn channel_names_and_topics_are_bounded_and_safe() {
        assert!(valid_channel_name("general-2"));
        assert!(!valid_channel_name("General"));
        assert!(!valid_channel_name("two words"));
        assert!(!valid_channel_name(&"a".repeat(33)));
        assert!(valid_channel_topic("A useful topic"));
        assert!(!valid_channel_topic("line\nbreak"));
        assert!(!valid_channel_topic(&"a".repeat(161)));
    }

    #[test]
    fn chat_servers_never_exceed_one_hundred_members() {
        let mut store = UserStore {
            chat_servers: vec![default_chat_server()],
            ..UserStore::default()
        };
        for index in 0..100 {
            assert!(
                add_chat_server_member(
                    &mut store,
                    DEFAULT_CHAT_SERVER_ID,
                    &format!("user-{index}")
                )
                .unwrap()
            );
        }
        assert_eq!(store.server_members[DEFAULT_CHAT_SERVER_ID].len(), 100);
        assert_eq!(
            add_chat_server_member(&mut store, DEFAULT_CHAT_SERVER_ID, "overflow"),
            Err("That server is full (100 members maximum).")
        );
        assert_eq!(store.server_members[DEFAULT_CHAT_SERVER_ID].len(), 100);
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

    #[test]
    fn account_hash_survives_store_save_and_reload() -> io::Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("oxide-store-test-{nonce}"));
        let store_path = test_dir.join("server-users.json");
        let password = "correct horse battery staple";
        let mut store = UserStore::default();
        store
            .users
            .insert("alice".to_string(), hash_password(password).unwrap());
        store.store_path = Some(store_path.clone());
        store.save()?;

        let restored = UserStore::load_from(&store_path, HashSet::new())?;
        let hash = restored.users.get("alice").expect("account was persisted");
        assert!(verify_password(password, hash));
        assert_eq!(restored.channels, default_channels());
        assert_eq!(restored.next_channel_id, default_next_channel_id());
        assert_eq!(restored.chat_servers, vec![default_chat_server()]);
        assert_eq!(restored.server_members[DEFAULT_CHAT_SERVER_ID].len(), 1);

        std::fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn tls_authenticates_users_and_server_assigns_message_authors() -> io::Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("oxide-tls-test-{nonce}"));
        let cert_path = test_dir.join("server-cert.pem");
        let key_path = test_dir.join("server-key.pem");
        let users_path = test_dir.join("server-users.json");
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
            roles: HashMap::from([("alice".to_string(), UserRole::Member)]),
            banned_users: HashSet::new(),
            session_tokens: HashMap::new(),
            channels: default_channels(),
            chat_servers: vec![default_chat_server()],
            server_members: HashMap::from([(
                DEFAULT_CHAT_SERVER_ID.to_string(),
                HashSet::from(["alice".to_string()]),
            )]),
            next_channel_id: default_next_channel_id(),
            next_chat_server_id: default_next_chat_server_id(),
            bootstrap_admins: HashSet::new(),
            store_path: Some(users_path.clone()),
        }));
        let server_tx = tx.clone();
        let server_users = users.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (stream, addr) = listener.accept().await?;
                let stream = acceptor.accept(stream).await?;
                let connection_tx = server_tx.clone();
                let connection_rx = connection_tx.subscribe();
                let connection_users = server_users.clone();
                connections.spawn(async move {
                    handle_connection(stream, addr, connection_tx, connection_rx, connection_users)
                        .await
                });
            }
            while let Some(result) = connections.join_next().await {
                result.map_err(io::Error::other)??;
            }
            Ok::<(), io::Error>(())
        });

        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let stream = connector.connect(server_name, stream).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = AsyncBufReader::new(reader);

        send_message(
            &mut writer,
            &ClientMessage::SendMessage {
                server_id: DEFAULT_CHAT_SERVER_ID.to_string(),
                channel_id: DEFAULT_CHANNEL_ID.to_string(),
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
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::ChatServers { .. }
        ));
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::Channels { channels, .. }
                if channels == default_channels()
        ));
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::UserJoined { username, .. } if username == "alice"
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
                server_id: DEFAULT_CHAT_SERVER_ID.to_string(),
                channel_id: DEFAULT_CHANNEL_ID.to_string(),
                content: "authenticated message".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut reader).await?,
            ServerMessage::ChatMessage { author, content, .. }
                if author == "alice" && content == "authenticated message"
        ));

        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let stream = connector.connect(server_name, stream).await?;
        let (bob_reader, mut bob_writer) = tokio::io::split(stream);
        let mut bob_reader = AsyncBufReader::new(bob_reader);
        send_message(
            &mut bob_writer,
            &ClientMessage::Register {
                username: "bob".to_string(),
                password: "another correct horse".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_message(&mut bob_reader).await?,
            ServerMessage::Authenticated { username, .. } if username == "bob"
        ));
        assert!(matches!(
            read_message(&mut bob_reader).await?,
            ServerMessage::ChatServers { .. }
        ));
        assert!(matches!(
            read_message(&mut bob_reader).await?,
            ServerMessage::Channels { channels, .. }
                if channels == default_channels()
        ));
        assert!(matches!(
            read_until(&mut bob_reader, |message| matches!(
                message,
                ServerMessage::UserJoined { username, .. } if username == "bob"
            )).await?,
            ServerMessage::UserJoined { username, .. } if username == "bob"
        ));
        assert!(matches!(
            read_until(&mut reader, |message| matches!(
                message,
                ServerMessage::UserJoined { username, .. } if username == "bob"
            )).await?,
            ServerMessage::UserJoined { username, .. } if username == "bob"
        ));

        send_message(
            &mut writer,
            &ClientMessage::CreateChatServer {
                name: "Side Room".to_string(),
                icon: None,
            },
        )
        .await?;
        let created_server_directory = read_until(&mut reader, |message| {
            matches!(message, ServerMessage::ChatServers { servers, .. }
                if servers.iter().any(|server| server.name == "Side Room"))
                || matches!(message, ServerMessage::Error { .. })
        })
        .await?;
        let side_server_id = match created_server_directory {
            ServerMessage::ChatServers {
                active_server_id,
                servers,
            } => {
                assert!(servers.iter().any(|server| server.name == "Side Room"));
                active_server_id
            }
            message => panic!("expected server directory, received {message:?}"),
        };
        let side_channel_id = match read_message(&mut reader).await? {
            ServerMessage::Channels {
                server_id,
                channels,
            } => {
                assert_eq!(server_id, side_server_id);
                assert_eq!(channels.len(), 1);
                assert_eq!(channels[0].name, "general");
                assert_eq!(channels[0].server_id, side_server_id);
                channels[0].id.clone()
            }
            message => panic!("expected server channels, received {message:?}"),
        };
        let directory_for_bob = read_until(&mut bob_reader, |message| {
            matches!(message, ServerMessage::ChatServers { servers, .. }
                if servers.iter().any(|server| server.id == side_server_id && !server.is_member))
        })
        .await?;
        assert!(matches!(
            directory_for_bob,
            ServerMessage::ChatServers { ref servers, .. }
                if servers.iter().any(|server| server.id == side_server_id && server.member_count == 1)
        ));

        send_message(
            &mut bob_writer,
            &ClientMessage::SendMessage {
                server_id: side_server_id.clone(),
                channel_id: side_channel_id.clone(),
                content: "outsider message".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_until(&mut bob_reader, |message| matches!(message, ServerMessage::Error { .. })).await?,
            ServerMessage::Error { message } if message == "Join that server before sending messages."
        ));

        send_message(
            &mut bob_writer,
            &ClientMessage::JoinChatServer {
                server_id: side_server_id.clone(),
            },
        )
        .await?;
        assert!(matches!(
            read_until(&mut bob_reader, |message| matches!(message,
                ServerMessage::ChatServers { active_server_id, .. }
                    if active_server_id == &side_server_id
            ))
            .await?,
            ServerMessage::ChatServers { .. }
        ));
        assert!(matches!(
            read_until(&mut bob_reader, |message| matches!(message,
                ServerMessage::Channels { server_id, .. } if server_id == &side_server_id
            ))
            .await?,
            ServerMessage::Channels { .. }
        ));
        send_message(
            &mut bob_writer,
            &ClientMessage::SendMessage {
                server_id: side_server_id.clone(),
                channel_id: side_channel_id,
                content: "community-only message".to_string(),
            },
        )
        .await?;
        assert!(matches!(
            read_until(&mut reader, |message| matches!(message,
                ServerMessage::ChatMessage { content, .. } if content == "community-only message"
            )).await?,
            ServerMessage::ChatMessage { server_id, author, .. }
                if server_id == side_server_id && author == "bob"
        ));

        send_message(&mut bob_writer, &ClientMessage::Logout).await?;
        assert!(matches!(
            read_until(&mut bob_reader, |message| matches!(
                message,
                ServerMessage::LoggedOut
            ))
            .await?,
            ServerMessage::LoggedOut
        ));
        assert!(matches!(
            read_until(&mut reader, |message| matches!(message,
                ServerMessage::UserLeft { username, .. } if username == "bob"
            )).await?,
            ServerMessage::UserLeft { username, .. } if username == "bob"
        ));

        drop(bob_writer);
        drop(bob_reader);
        drop(writer);
        drop(reader);
        server.await.map_err(io::Error::other)??;

        let restored = UserStore::load_from(&users_path, HashSet::new())?;
        assert!(restored.users.contains_key("alice"));
        assert!(restored.users.contains_key("bob"));
        assert!(verify_password(
            "another correct horse",
            &restored.users["bob"]
        ));
        assert_eq!(
            restored.profiles["alice"].picture.as_deref(),
            Some(picture.as_str())
        );

        std::fs::remove_dir_all(test_dir)?;
        Ok(())
    }
}
