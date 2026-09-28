use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Register { username: String, password: String },
    Login { username: String, password: String },
    Logout,
    SendMessage { content: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Authenticated { username: String },
    AuthenticationFailed { message: String },
    LoggedOut,
    ChatMessage { author: String, content: String },
    Error { message: String },
}
