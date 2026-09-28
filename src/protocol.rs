use serde::{Deserialize, Serialize};

pub const MAX_PROFILE_IMAGE_SIZE: usize = 512 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Register {
        username: String,
        password: String,
    },
    Login {
        username: String,
        password: String,
    },
    Logout,
    SendMessage {
        content: String,
    },
    GetProfile {
        username: String,
    },
    UpdateProfile {
        picture: Option<String>,
        banner: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub picture: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Authenticated {
        username: String,
        picture: Option<String>,
        banner: Option<String>,
    },
    AuthenticationFailed {
        message: String,
    },
    LoggedOut,
    ChatMessage {
        author: String,
        content: String,
    },
    ProfileUpdated(UserProfile),
    Profile(UserProfile),
    Error {
        message: String,
    },
}
