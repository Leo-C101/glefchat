use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use slint::{Model, ModelRc, VecModel, Weak};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

slint::include_modules!();

const DEFAULT_CHAT_ADDR: &str = "127.0.0.1:8080";

// Address can be overridden with `glefchat <host:port>` or the CHAT_ADDR env var
// so friends can point at your public address instead of localhost.
fn chat_address() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_CHAT_ADDR.to_string())
}

#[derive(Default, Serialize, Deserialize)]
struct UserStore {
    // username -> Argon2 password hash
    users: HashMap<String, String>,
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

fn hash_password(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;

    let messages = Vec::new();

    let model_rc: ModelRc<Message> = ModelRc::new(VecModel::from(messages));
    main_window.set_messages(model_rc);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<String>();
    runtime.spawn(connect_to_server(chat_address(), main_window.as_weak(), outgoing_rx));

    let user_store = Arc::new(Mutex::new(load_user_store()));

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        main_window.on_login(move |username, password| {
            let Some(win) = window.upgrade() else { return };
            let username = username.to_string();
            let store = user_store.lock().unwrap();
            match store.users.get(&username) {
                Some(hash) if verify_password(&password, hash) => {
                    win.set_username(username.into());
                    win.set_auth_error("".into());
                    win.set_logged_in(true);
                }
                _ => win.set_auth_error("Invalid username or password.".into()),
            }
        });
    }

    {
        let window = main_window.as_weak();
        let user_store = user_store.clone();
        main_window.on_register(move |username, password| {
            let Some(win) = window.upgrade() else { return };
            let username = username.to_string();
            if username.is_empty() {
                win.set_auth_error("Username can't be empty.".into());
                return;
            }
            if password.len() < 4 {
                win.set_auth_error("Password must be at least 4 characters.".into());
                return;
            }

            let mut store = user_store.lock().unwrap();
            if store.users.contains_key(&username) {
                win.set_auth_error("That username is already taken.".into());
                return;
            }

            let hash = match hash_password(&password) {
                Ok(hash) => hash,
                Err(_) => {
                    win.set_auth_error("Failed to create profile.".into());
                    return;
                }
            };
            store.users.insert(username.clone(), hash);
            if let Err(err) = save_user_store(&store) {
                eprintln!("failed to save user store: {err}");
            }

            win.set_username(username.into());
            win.set_auth_error("".into());
            win.set_logged_in(true);
        });
    }

    {
        let window = main_window.as_weak();
        main_window.on_log_out(move || {
            let Some(win) = window.upgrade() else { return };
            win.set_logged_in(false);
            win.set_username("".into());
        });
    }

    {
        let window = main_window.as_weak();
        main_window.on_send_message(move |content| {
            let content = content.to_string();
            if content.is_empty() {
                return;
            }
            let Some(win) = window.upgrade() else { return };
            let author = win.get_username().to_string();
            let _ = outgoing_tx.send(format!("{author}\t{content}\n"));
            append_message(&window, author, content);
        });
    }

    main_window.run()
}

async fn connect_to_server(
    addr: String,
    window: Weak<MainWindow>,
    mut outgoing_rx: mpsc::UnboundedReceiver<String>,
) {
    let stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("failed to connect to {addr}: {err}");
            return;
        }
    };
    println!("connected to chat server at {addr}");

    let (read_half, mut write_half) = tokio::io::split(stream);
    tokio::spawn(read_incoming_messages(read_half, window));

    while let Some(line) = outgoing_rx.recv().await {
        if let Err(err) = write_half.write_all(line.as_bytes()).await {
            eprintln!("failed to send message: {err}");
            break;
        }
    }
}

async fn read_incoming_messages(read_half: impl tokio::io::AsyncRead + Unpin, window: Weak<MainWindow>) {
    let mut lines = BufReader::new(read_half).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let (author, content) = split_message(&line);
                append_message(&window, author, content);
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("error reading from server: {err}");
                break;
            }
        }
    }
}

fn split_message(line: &str) -> (String, String) {
    match line.split_once('\t') {
        Some((author, content)) => (author.to_string(), content.to_string()),
        None => ("Unknown".to_string(), line.to_string()),
    }
}

fn append_message(window: &Weak<MainWindow>, author: String, content: String) {
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = window.upgrade() {
            let model = window.get_messages();
            if let Some(vec_model) = model.as_any().downcast_ref::<VecModel<Message>>() {
                vec_model.push(Message {
                    content: content.into(),
                    timestamp: current_timestamp().into(),
                    author: author.into(),
                });
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