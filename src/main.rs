use slint::{Model, ModelRc, VecModel, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

slint::include_modules!();

const DEFAULT_CHAT_ADDR: &str = "127.0.0.1:8080";
const LOCAL_AUTHOR: &str = "Me";

// Address can be overridden with `glefchat <host:port>` or the CHAT_ADDR env var
// so friends can point at your public address instead of localhost.
fn chat_address() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CHAT_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_CHAT_ADDR.to_string())
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

    {
        let window = main_window.as_weak();
        main_window.on_send_message(move |content| {
            let content = content.to_string();
            if content.is_empty() {
                return;
            }
            let Some(win) = window.upgrade() else { return };
            let nickname = win.get_nickname().to_string();
            let author = if nickname.is_empty() { LOCAL_AUTHOR.to_string() } else { nickname };
            let _ = outgoing_tx.send(format!("{author}\t{content}\n"));
            append_message(&window, author, content);
        });
    }

    main_window.run()
}

// Connects to the chat server once, then forwards outgoing lines and appends incoming ones.
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