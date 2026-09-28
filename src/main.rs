use base64::Engine;
use protocol::{ClientMessage, ServerMessage};
use protocol::{MAX_PROFILE_IMAGE_SIZE, UserProfile, UserRole};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use slint::{Color, Model, ModelRc, VecModel, Weak};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader as StdBufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

mod protocol;
fn user_role_from_label(label: &str) -> Option<UserRole> {
    match label {
        "Member" => Some(UserRole::Member),
        "Moderator" => Some(UserRole::Moderator),
        "Admin" => Some(UserRole::Admin),
        _ => None,
    }
}

slint::include_modules!();

const DEFAULT_CHAT_ADDR: &str = "127.0.0.1:8080";

fn chat_address() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_CHAT_ADDR.to_string())
}

#[derive(Default, Serialize, Deserialize)]
struct UserStore {
    #[serde(default)]
    themes: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    profiles: HashMap<String, UserProfile>,
}

const MAX_STORED_MESSAGES: usize = 500;

#[derive(Clone, Serialize, Deserialize)]
struct StoredMessage {
    author: String,
    content: String,
    timestamp: String,
}

impl From<&StoredMessage> for Message {
    fn from(stored: &StoredMessage) -> Self {
        Message {
            author: stored.author.clone().into(),
            content: stored.content.clone().into(),
            timestamp: stored.timestamp.clone().into(),
            profile_picture: slint::Image::default(),
        }
    }
}

fn profile_image(encoded: &Option<String>) -> slint::Image {
    encoded
        .as_ref()
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .and_then(|bytes| slint::Image::load_from_data(&bytes, None).ok())
        .unwrap_or_default()
}

const DEFAULT_THEME: [(&str, &str); 26] = [
    ("rosewater", "#f5e0dc"),
    ("flamingo", "#f2cdcd"),
    ("pink", "#f5c2e7"),
    ("mauve", "#cba6f7"),
    ("red", "#f38ba8"),
    ("maroon", "#eba0ac"),
    ("peach", "#fab387"),
    ("yellow", "#f9e2af"),
    ("green", "#a6e3a1"),
    ("teal", "#94e2d5"),
    ("sky", "#89dceb"),
    ("sapphire", "#74c7ec"),
    ("blue", "#89b4fa"),
    ("lavender", "#b4befe"),
    ("text", "#cdd6f4"),
    ("subtext1", "#bac2de"),
    ("subtext0", "#a6adc8"),
    ("overlay2", "#9399b2"),
    ("overlay1", "#7f849c"),
    ("overlay0", "#6c7086"),
    ("surface2", "#585b70"),
    ("surface1", "#45475a"),
    ("surface0", "#313244e0"),
    ("base", "#1e1e2eca"),
    ("mantle", "#181825"),
    ("crust", "#11111b"),
];

const EDITABLE_THEME: [(&str, &str); 8] = [
    ("base", "Background"),
    ("surface0", "Panel background"),
    ("mantle", "Chat area background"),
    ("surface1", "Message background"),
    ("text", "Main text"),
    ("subtext0", "Secondary text"),
    ("overlay0", "Muted text"),
    ("surface2", "Raised surface"),
];

const ACCENT_KEYS: [&str; 14] = [
    "rosewater",
    "flamingo",
    "pink",
    "mauve",
    "red",
    "maroon",
    "peach",
    "yellow",
    "green",
    "teal",
    "sky",
    "sapphire",
    "blue",
    "lavender",
];

const ACCENT_OPTIONS: [(&str, &str); 8] = [
    ("Lavender", "#b4befe"),
    ("Blue", "#89b4fa"),
    ("Sapphire", "#74c7ec"),
    ("Teal", "#94e2d5"),
    ("Green", "#a6e3a1"),
    ("Yellow", "#f9e2af"),
    ("Peach", "#fab387"),
    ("Pink", "#f5c2e7"),
];

const PREFERRED_ACCENT_KEY: &str = "__preferred_accent";

fn parse_theme_color(value: &str) -> Option<(String, Color)> {
    let hex = value.trim().strip_prefix('#').unwrap_or(value.trim());
    if !hex.is_ascii() {
        return None;
    }
    let (red, green, blue, alpha) = match hex.len() {
        6 => (
            u8::from_str_radix(&hex[0..2], 16).ok()?,
            u8::from_str_radix(&hex[2..4], 16).ok()?,
            u8::from_str_radix(&hex[4..6], 16).ok()?,
            255,
        ),
        8 => (
            u8::from_str_radix(&hex[0..2], 16).ok()?,
            u8::from_str_radix(&hex[2..4], 16).ok()?,
            u8::from_str_radix(&hex[4..6], 16).ok()?,
            u8::from_str_radix(&hex[6..8], 16).ok()?,
        ),
        _ => return None,
    };
    let normalized = format!("#{hex}").to_ascii_lowercase();
    Some((normalized, Color::from_argb_u8(alpha, red, green, blue)))
}

fn theme_colors(overrides: Option<&HashMap<String, String>>) -> Vec<ThemeColor> {
    let mut colors: Vec<_> = DEFAULT_THEME
        .iter()
        .map(|(name, default_hex)| {
            let (hex, value) = overrides
                .and_then(|overrides| overrides.get(*name))
                .filter(|_| !ACCENT_KEYS.contains(name))
                .and_then(|hex| parse_theme_color(hex))
                .or_else(|| parse_theme_color(default_hex))
                .expect("default theme colors must be valid");
            ThemeColor {
                name: (*name).into(),
                key: (*name).into(),
                hex: hex.into(),
                value,
            }
        })
        .collect();
    let (_, accent_hex) = preferred_accent(overrides);
    let (accent_hex, accent_value) = parse_theme_color(accent_hex).unwrap();
    for index in [3, 13] {
        colors[index].hex = accent_hex.clone().into();
        colors[index].value = accent_value;
    }
    colors
}

fn editable_theme_colors(overrides: Option<&HashMap<String, String>>) -> Vec<ThemeColor> {
    let palette = theme_colors(overrides);
    EDITABLE_THEME
        .iter()
        .map(|(key, label)| {
            let mut color = palette
                .iter()
                .find(|color| color.key == *key)
                .expect("editable theme keys must exist in the palette")
                .clone();
            color.name = (*label).into();
            color
        })
        .collect()
}

fn preferred_accent(overrides: Option<&HashMap<String, String>>) -> (&'static str, &'static str) {
    let requested = overrides.and_then(|overrides| overrides.get(PREFERRED_ACCENT_KEY));
    ACCENT_OPTIONS
        .iter()
        .find(|(name, _)| Some(*name) == requested.map(String::as_str))
        .copied()
        .unwrap_or(ACCENT_OPTIONS[0])
}

fn users_file_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("glefchat").join("users.json")
}

fn load_user_store() -> UserStore {
    std::fs::read_to_string(users_file_path())
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_user_store(store: &UserStore) -> std::io::Result<()> {
    let path = users_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(store)?)
}

fn messages_file_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("glefchat").join("messages.json")
}

fn load_messages() -> Vec<StoredMessage> {
    std::fs::read_to_string(messages_file_path())
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_messages(messages: &[StoredMessage]) -> std::io::Result<()> {
    let path = messages_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(messages)?)
}

fn tls_certificate_path() -> PathBuf {
    std::env::var_os("CHAT_TLS_CERT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("glefchat")
                .join("server-cert.pem")
        })
}

fn server_name(addr: &str) -> io::Result<ServerName<'static>> {
    let host = std::env::var("CHAT_TLS_SERVER_NAME").unwrap_or_else(|_| {
        let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_string()
    });
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }
}

fn tls_connector() -> io::Result<TlsConnector> {
    let cert_file = File::open(tls_certificate_path())?;
    let certs = rustls_pemfile::certs(&mut StdBufReader::new(cert_file))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(io::Error::other)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;

    let user_store = Arc::new(Mutex::new(load_user_store()));
    let stored_messages = Arc::new(Mutex::new(load_messages()));
    let profiles = user_store.lock().unwrap().profiles.clone();
    let messages: Vec<Message> = stored_messages
        .lock()
        .unwrap()
        .iter()
        .map(|stored| {
            let mut message = Message::from(stored);
            if let Some(profile) = profiles.get(&stored.author) {
                message.profile_picture = profile_image(&profile.picture);
            }
            message
        })
        .collect();

    let model_rc: ModelRc<Message> = ModelRc::new(VecModel::from(messages));
    main_window.set_messages(model_rc);
    main_window.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(None))));
    main_window
        .set_editable_theme_colors(ModelRc::new(VecModel::from(editable_theme_colors(None))));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<ClientMessage>();

    if let Err(err) = save_user_store(&user_store.lock().unwrap()) {
        eprintln!("failed to migrate local preferences: {err}");
    }
    runtime.spawn(connect_to_server(
        chat_address(),
        main_window.as_weak(),
        user_store.clone(),
        stored_messages.clone(),
        outgoing_tx.clone(),
        outgoing_rx,
    ));
    let runtime_handle = runtime.handle().clone();

    {
        let window = main_window.as_weak();
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_login(move |username, password| {
            let Some(win) = window.upgrade() else { return };
            let username = username.to_string();
            if !valid_username(&username) {
                win.set_auth_error(
                    "Username must be 3-32 letters, digits, dots, dashes, or underscores.".into(),
                );
            } else if outgoing_tx
                .send(ClientMessage::Login {
                    username,
                    password: password.to_string(),
                })
                .is_err()
            {
                win.set_auth_error("Not connected to the chat server.".into());
            } else {
                win.set_auth_error("".into());
            }
        });
    }

    {
        let window = main_window.as_weak();
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_register(move |username, password| {
            let Some(win) = window.upgrade() else { return };
            let username = username.to_string();
            if !valid_username(&username) {
                win.set_auth_error(
                    "Username must be 3-32 letters, digits, dots, dashes, or underscores.".into(),
                );
                return;
            }
            if !(8..=1024).contains(&password.len()) {
                win.set_auth_error("Password must be 8-1024 bytes long.".into());
                return;
            }
            if outgoing_tx
                .send(ClientMessage::Register {
                    username,
                    password: password.to_string(),
                })
                .is_err()
            {
                win.set_auth_error("Not connected to the chat server.".into());
            } else {
                win.set_auth_error("".into());
            }
        });
    }

    {
        let window = main_window.as_weak();
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_log_out(move || {
            let Some(win) = window.upgrade() else { return };
            let _ = outgoing_tx.send(ClientMessage::Logout);
            win.set_logged_in(false);
            win.set_username("".into());
            win.set_viewed_profile_open(false);
            win.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(None))));
            win.set_editable_theme_colors(ModelRc::new(VecModel::from(editable_theme_colors(
                None,
            ))));
            win.set_accent_name(ACCENT_OPTIONS[0].0.into());
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        main_window.on_set_theme_color(move |index, hex| {
            let Some(win) = window.upgrade() else { return };
            let Some((normalized, value)) = parse_theme_color(&hex) else {
                win.set_theme_error("Use #RRGGBB or #RRGGBBAA.".into());
                return;
            };
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            let model = win.get_editable_theme_colors();
            let Some(colors) = model.as_any().downcast_ref::<VecModel<ThemeColor>>() else {
                return;
            };
            let Some(mut color) = colors.row_data(index) else {
                return;
            };
            color.hex = normalized.clone().into();
            color.value = value;
            colors.set_row_data(index, color);

            let model = win.get_theme_colors();
            let Some(palette) = model.as_any().downcast_ref::<VecModel<ThemeColor>>() else {
                return;
            };
            for palette_index in 0..palette.row_count() {
                let Some(mut palette_color) = palette.row_data(palette_index) else {
                    continue;
                };
                if palette_color.key == colors.row_data(index).unwrap().key {
                    palette_color.hex = normalized.clone().into();
                    palette_color.value = value;
                    palette.set_row_data(palette_index, palette_color);
                    break;
                }
            }
            win.set_theme_error("".into());

            let username = win.get_username().to_string();
            let mut store = user_store.lock().unwrap();
            store
                .themes
                .entry(username)
                .or_default()
                .insert(colors.row_data(index).unwrap().key.to_string(), normalized);
            if let Err(err) = save_user_store(&store) {
                eprintln!("failed to save user theme: {err}");
                win.set_theme_error("Theme updated, but could not be saved.".into());
            }
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        let outgoing_tx = outgoing_tx.clone();
        let runtime_handle = runtime_handle.clone();
        main_window.on_choose_profile_picture(move || {
            launch_profile_image_picker(
                window.clone(),
                runtime_handle.clone(),
                user_store.clone(),
                outgoing_tx.clone(),
                false,
            );
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_show_user_profile(move |username| {
            let Some(window) = window.upgrade() else {
                return;
            };
            let username = username.to_string();
            if username == window.get_username().as_str() {
                return;
            }

            window.set_viewed_profile_username(username.clone().into());
            window.set_viewed_profile_open(true);
            window.set_viewed_profile_loading(true);
            window.set_privilege_error("".into());
            let cached_profile = user_store.lock().unwrap().profiles.get(&username).cloned();
            if let Some(profile) = cached_profile {
                window.set_viewed_profile_picture(profile_image(&profile.picture));
                window.set_viewed_profile_banner(profile_image(&profile.banner));
                window.set_viewed_profile_role(profile.role.label().into());
                window.set_viewed_profile_banned(profile.banned);
            } else {
                window.set_viewed_profile_picture(slint::Image::default());
                window.set_viewed_profile_banner(slint::Image::default());
                window.set_viewed_profile_role(UserRole::Member.label().into());
                window.set_viewed_profile_banned(false);
            }
            if outgoing_tx
                .send(ClientMessage::GetProfile { username })
                .is_err()
            {
                window.set_viewed_profile_loading(false);
            }
        });
    }

    {
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_set_user_role(move |username, role_label| {
            let Some(role) = user_role_from_label(role_label.as_str()) else {
                return;
            };
            let _ = outgoing_tx.send(ClientMessage::SetUserRole {
                username: username.to_string(),
                role,
            });
        });
    }

    {
        let outgoing_tx = outgoing_tx.clone();
        main_window.on_set_user_banned(move |username, banned| {
            let _ = outgoing_tx.send(ClientMessage::SetUserBanned {
                username: username.to_string(),
                banned,
            });
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        let outgoing_tx = outgoing_tx.clone();
        let runtime_handle = runtime_handle.clone();
        main_window.on_choose_profile_banner(move || {
            launch_profile_image_picker(
                window.clone(),
                runtime_handle.clone(),
                user_store.clone(),
                outgoing_tx.clone(),
                true,
            );
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        main_window.on_set_theme_accent(move |accent| {
            let Some(win) = window.upgrade() else { return };
            let Some((accent_name, _)) = ACCENT_OPTIONS
                .iter()
                .find(|(name, _)| *name == accent.as_str())
                .copied()
            else {
                return;
            };

            let username = win.get_username().to_string();
            let mut store = user_store.lock().unwrap();
            let overrides = store.themes.entry(username).or_default();
            overrides.insert(PREFERRED_ACCENT_KEY.to_string(), accent_name.to_string());
            win.set_accent_name(accent_name.into());
            win.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(Some(overrides)))));
            win.set_theme_error("".into());
            if let Err(err) = save_user_store(&store) {
                eprintln!("failed to save user theme: {err}");
                win.set_theme_error("Theme updated, but could not be saved.".into());
            }
        });
    }

    {
        let window = main_window.as_weak();
        main_window.on_send_message(move |content| {
            let content = content.to_string();
            if content.is_empty() || content.len() > 4096 {
                return;
            }
            let Some(win) = window.upgrade() else { return };
            if win.get_logged_in() {
                let _ = outgoing_tx.send(ClientMessage::SendMessage { content });
            }
        });
    }

    main_window.run()
}

fn launch_profile_image_picker(
    window: Weak<MainWindow>,
    runtime: tokio::runtime::Handle,
    user_store: Arc<Mutex<UserStore>>,
    outgoing_tx: mpsc::UnboundedSender<ClientMessage>,
    is_banner: bool,
) {
    runtime.spawn(async move {
        let selected = tokio::task::spawn_blocking(|| {
            rfd::FileDialog::new()
                .add_filter("Image files", &["png", "jpg", "jpeg", "webp"])
                .pick_file()
        })
        .await;
        let path = match selected {
            Ok(Some(path)) => path,
            Ok(None) => return,
            Err(err) => {
                set_profile_error(&window, format!("Could not open image picker: {err}"));
                return;
            }
        };

        let bytes = match async {
            let metadata = tokio::fs::metadata(&path)
                .await
                .map_err(|err| err.to_string())?;
            if metadata.len() > MAX_PROFILE_IMAGE_SIZE as u64 {
                return Err("Choose an image no larger than 512 KiB.".to_string());
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|err| err.to_string())?;
            if bytes.is_empty() || bytes.len() > MAX_PROFILE_IMAGE_SIZE {
                return Err("Choose an image no larger than 512 KiB.".to_string());
            }
            slint::Image::load_from_data(&bytes, None)
                .map_err(|_| "Choose a valid PNG, JPEG, or WebP image.".to_string())?;
            Ok::<_, String>(bytes)
        }
        .await
        {
            Ok(bytes) => bytes,
            Err(message) => {
                set_profile_error(&window, message);
                return;
            }
        };

        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let _ = slint::invoke_from_event_loop(move || {
            let Some(window) = window.upgrade() else {
                return;
            };
            let username = window.get_username().to_string();
            if username.is_empty() {
                window.set_profile_error("Sign in before editing your profile.".into());
                return;
            }
            let mut store = user_store.lock().unwrap();
            let profile = store
                .profiles
                .entry(username.clone())
                .or_insert_with(|| UserProfile {
                    username,
                    picture: None,
                    banner: None,
                    role: UserRole::Member,
                    banned: false,
                });
            if is_banner {
                profile.banner = Some(encoded.clone());
            } else {
                profile.picture = Some(encoded.clone());
            }
            let picture = profile.picture.clone();
            let banner = profile.banner.clone();
            drop(store);

            if outgoing_tx
                .send(ClientMessage::UpdateProfile { picture, banner })
                .is_err()
            {
                window.set_profile_error("Could not send the profile update.".into());
                return;
            }
            let image = profile_image(&Some(encoded));
            if is_banner {
                window.set_profile_banner(image);
            } else {
                window.set_profile_picture(image);
            }
            window.set_profile_error("".into());
        });
    });
}

fn set_profile_error(window: &Weak<MainWindow>, message: String) {
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = window.upgrade() {
            window.set_profile_error(message.into());
        }
    });
}

async fn connect_to_server(
    addr: String,
    window: Weak<MainWindow>,
    user_store: Arc<Mutex<UserStore>>,
    stored_messages: Arc<Mutex<Vec<StoredMessage>>>,
    outgoing_tx: mpsc::UnboundedSender<ClientMessage>,
    mut outgoing_rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    let stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("failed to connect to {addr}: {err}");
            set_auth_error(&window, "Could not connect to the chat server.");
            return;
        }
    };
    let connector = match tls_connector() {
        Ok(connector) => connector,
        Err(err) => {
            eprintln!("failed to load trusted chat server certificate: {err}");
            set_auth_error(&window, "Could not load the trusted server certificate.");
            return;
        }
    };
    let name = match server_name(&addr) {
        Ok(name) => name,
        Err(err) => {
            eprintln!("invalid chat server name: {err}");
            set_auth_error(&window, "Invalid chat server address.");
            return;
        }
    };
    let stream = match connector.connect(name, stream).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("TLS connection to {addr} failed: {err}");
            set_auth_error(&window, "Secure connection to the chat server failed.");
            return;
        }
    };
    println!("securely connected to chat server at {addr}");

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();
    let mut requested_profiles = HashSet::new();
    loop {
        tokio::select! {
            command = outgoing_rx.recv() => {
                let Some(command) = command else { break };
                let mut line = match serde_json::to_vec(&command) {
                    Ok(line) => line,
                    Err(err) => {
                        eprintln!("failed to encode chat request: {err}");
                        continue;
                    }
                };
                line.push(b'\n');
                if let Err(err) = write_half.write_all(&line).await {
                    eprintln!("failed to send chat request: {err}");
                    break;
                }
            }
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => match serde_json::from_str::<ServerMessage>(&line) {
                        Ok(message) => {
                            match &message {
                                ServerMessage::Authenticated { username, .. } => {
                                    requested_profiles.insert(username.clone());
                                    let mut authors: HashSet<_> = user_store
                                        .lock()
                                        .unwrap()
                                        .profiles
                                        .keys()
                                        .cloned()
                                        .collect();
                                    authors.extend(stored_messages
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .map(|stored| stored.author.clone())
                                    );
                                    for author in authors {
                                        if author != *username
                                            && requested_profiles.insert(author.clone())
                                        {
                                            let _ = outgoing_tx.send(ClientMessage::GetProfile { username: author });
                                        }
                                    }
                                }
                                ServerMessage::ChatMessage { author, .. } => {
                                    let cached = user_store.lock().unwrap();
                                    if !cached.profiles.contains_key(author)
                                        && requested_profiles.insert(author.clone())
                                    {
                                        let _ = outgoing_tx.send(ClientMessage::GetProfile {
                                            username: author.clone(),
                                        });
                                    }
                                }
                                _ => {}
                            }
                            apply_server_message(&window, &user_store, &stored_messages, message)
                        }
                        Err(err) => eprintln!("ignored invalid server response: {err}"),
                    },
                    Ok(None) => break,
                    Err(err) => {
                        eprintln!("error reading from chat server: {err}");
                        break;
                    }
                }
            }
        }
    }
    set_connection_lost(&window);
}

fn set_auth_error(window: &Weak<MainWindow>, message: &'static str) {
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = window.upgrade() {
            window.set_auth_error(message.into());
        }
    });
}

fn set_connection_lost(window: &Weak<MainWindow>) {
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = window.upgrade() {
            let account_banned = window.get_auth_error().to_string().contains("banned");
            window.set_logged_in(false);
            window.set_username("".into());
            window.set_viewed_profile_open(false);
            window.set_account_role(UserRole::Member.label().into());
            window.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(None))));
            window.set_editable_theme_colors(ModelRc::new(VecModel::from(editable_theme_colors(
                None,
            ))));
            window.set_accent_name(ACCENT_OPTIONS[0].0.into());
            window.set_profile_picture(slint::Image::default());
            window.set_profile_banner(slint::Image::default());
            if !account_banned {
                window.set_auth_error("Connection to the chat server was lost.".into());
            }
        }
    });
}

fn refresh_message_avatars(window: &MainWindow, profiles: &HashMap<String, UserProfile>) {
    let model = window.get_messages();
    let Some(messages) = model.as_any().downcast_ref::<VecModel<Message>>() else {
        return;
    };
    for index in 0..messages.row_count() {
        let Some(mut message) = messages.row_data(index) else {
            continue;
        };
        message.profile_picture = profiles
            .get(message.author.as_str())
            .map(|profile| profile_image(&profile.picture))
            .unwrap_or_default();
        messages.set_row_data(index, message);
    }
}

fn apply_server_message(
    window: &Weak<MainWindow>,
    user_store: &Arc<Mutex<UserStore>>,
    stored_messages: &Arc<Mutex<Vec<StoredMessage>>>,
    message: ServerMessage,
) {
    let window = window.clone();
    let user_store = user_store.clone();
    let stored_messages = stored_messages.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(window) = window.upgrade() else {
            return;
        };
        match message {
            ServerMessage::Authenticated {
                username,
                picture,
                banner,
                role,
            } => {
                let profile = UserProfile {
                    username: username.clone(),
                    picture,
                    banner,
                    role,
                    banned: false,
                };
                let mut store = user_store.lock().unwrap();
                store.profiles.insert(username.clone(), profile.clone());
                let overrides = store.themes.get(&username);
                window.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(overrides))));
                window.set_editable_theme_colors(ModelRc::new(VecModel::from(
                    editable_theme_colors(overrides),
                )));
                window.set_accent_name(preferred_accent(overrides).0.into());
                window.set_profile_picture(profile_image(&profile.picture));
                window.set_profile_banner(profile_image(&profile.banner));
                window.set_username(username.into());
                window.set_auth_error("".into());
                window.set_profile_error("".into());
                window.set_logged_in(true);
                refresh_message_avatars(&window, &store.profiles);
                window.set_account_role(profile.role.label().into());
                if let Err(err) = save_user_store(&store) {
                    eprintln!("failed to cache user profile: {err}");
                }
            }
            ServerMessage::AuthenticationFailed { message } => {
                window.set_auth_error(message.into());
            }
            ServerMessage::AccountBanned { message } => {
                window.set_logged_in(false);
                window.set_username("".into());
                window.set_viewed_profile_open(false);
                window.set_account_role(UserRole::Member.label().into());
                window.set_auth_error(message.into());
            }
            ServerMessage::Error { message } => {
                if window.get_viewed_profile_open() {
                    window.set_viewed_profile_loading(false);
                    window.set_privilege_error(message.clone().into());
                }
                window.set_auth_error(message.into());
            }
            ServerMessage::LoggedOut => {
                window.set_logged_in(false);
                window.set_username("".into());
                window.set_viewed_profile_open(false);
                window.set_profile_picture(slint::Image::default());
                window.set_profile_banner(slint::Image::default());
                window.set_theme_colors(ModelRc::new(VecModel::from(theme_colors(None))));
                window.set_editable_theme_colors(ModelRc::new(VecModel::from(
                    editable_theme_colors(None),
                )));
                window.set_account_role(UserRole::Member.label().into());
                window.set_accent_name(ACCENT_OPTIONS[0].0.into());
            }
            ServerMessage::Profile(profile) | ServerMessage::ProfileUpdated(profile) => {
                let mut store = user_store.lock().unwrap();
                store
                    .profiles
                    .insert(profile.username.clone(), profile.clone());
                refresh_message_avatars(&window, &store.profiles);
                if profile.username == window.get_username().as_str() {
                    window.set_profile_picture(profile_image(&profile.picture));
                    window.set_profile_banner(profile_image(&profile.banner));
                    window.set_account_role(profile.role.label().into());
                }
                if window.get_viewed_profile_open()
                    && profile.username == window.get_viewed_profile_username().as_str()
                {
                    window.set_viewed_profile_picture(profile_image(&profile.picture));
                    window.set_viewed_profile_role(profile.role.label().into());
                    window.set_viewed_profile_banned(profile.banned);
                    window.set_viewed_profile_loading(false);
                }
                if let Err(err) = save_user_store(&store) {
                    eprintln!("failed to cache user profile: {err}");
                }
            }
            ServerMessage::ChatMessage { author, content } => {
                let stored = StoredMessage {
                    author: author.clone(),
                    content: content.clone(),
                    timestamp: current_timestamp(),
                };
                let model = window.get_messages();
                if let Some(vec_model) = model.as_any().downcast_ref::<VecModel<Message>>() {
                    let mut message = Message::from(&stored);
                    if let Some(profile) = user_store.lock().unwrap().profiles.get(&author) {
                        message.profile_picture = profile_image(&profile.picture);
                    }
                    vec_model.push(message);
                }

                let mut messages = stored_messages.lock().unwrap();
                messages.push(stored);
                let overflow = messages.len().saturating_sub(MAX_STORED_MESSAGES);
                if overflow > 0 {
                    messages.drain(0..overflow);
                }
                if let Err(err) = save_messages(&messages) {
                    eprintln!("failed to save chat history: {err}");
                }
            }
        }
    });
}

fn current_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60)
}

#[cfg(test)]
mod tests {
    use super::{
        PREFERRED_ACCENT_KEY, UserStore, editable_theme_colors, parse_theme_color, theme_colors,
    };
    use std::collections::HashMap;

    #[test]
    fn parses_rgb_and_rgba_colors() {
        assert!(parse_theme_color("#A1B2C3").is_some());
        assert!(parse_theme_color("#A1B2C3D4").is_some());
    }

    #[test]
    fn rejects_invalid_theme_colors() {
        assert!(parse_theme_color("#xyzxyz").is_none());
        assert!(parse_theme_color("#ééé").is_none());
    }

    #[test]
    fn loads_legacy_user_store_without_retaining_local_credentials() {
        let store: UserStore =
            serde_json::from_str(r#"{"users":{"alice":"hash"},"last_session":"alice"}"#).unwrap();
        assert!(store.themes.is_empty());
    }

    #[test]
    fn keeps_background_customization_and_uses_selected_accent() {
        let overrides = HashMap::from([
            ("base".to_string(), "#123456".to_string()),
            ("mauve".to_string(), "#010203".to_string()),
            (PREFERRED_ACCENT_KEY.to_string(), "Teal".to_string()),
        ]);
        let palette = theme_colors(Some(&overrides));

        assert_eq!(palette[23].hex.to_string(), "#123456");
        assert_eq!(palette[3].hex.to_string(), "#94e2d5");
        assert_eq!(palette[13].hex.to_string(), "#94e2d5");
    }

    #[test]
    fn editor_exposes_plain_language_color_roles() {
        let editable = editable_theme_colors(None);
        let labels: Vec<_> = editable
            .iter()
            .map(|color| color.name.to_string())
            .collect();

        assert!(labels.contains(&"Background".to_string()));
        assert!(labels.contains(&"Chat area background".to_string()));
        assert!(!labels.contains(&"Lavender".to_string()));
    }
}
