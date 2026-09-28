use serde::{Deserialize, Serialize};

pub const MAX_PROFILE_IMAGE_SIZE: usize = 512 * 1024;
pub const DEFAULT_CHANNEL_ID: &str = "1";
pub const DEFAULT_CHAT_SERVER_ID: &str = "1";

pub fn default_channel_id() -> String {
    DEFAULT_CHANNEL_ID.to_string()
}

pub fn default_chat_server_id() -> String {
    DEFAULT_CHAT_SERVER_ID.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ChatServer {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatServerView {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
    pub member_count: u32,
    pub is_member: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    #[serde(default = "default_chat_server_id")]
    pub server_id: String,
    pub name: String,
    pub topic: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    #[default]
    Member,
    Moderator,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Permission {
    BanUsers,
    ManageRoles,
    ManageChannels,
    ManageServerInfo,
}

impl UserRole {
    #[allow(dead_code)]
    pub fn has_permission(self, permission: Permission) -> bool {
        match self {
            Self::Member => false,
            Self::Moderator => matches!(
                permission,
                Permission::BanUsers | Permission::ManageChannels
            ),
            Self::Admin => true,
        }
    }

    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::Member => "Member",
            Self::Moderator => "Moderator",
            Self::Admin => "Admin",
        }
    }

    #[allow(dead_code)]
    pub fn level(self) -> u8 {
        match self {
            Self::Member => 0,
            Self::Moderator => 1,
            Self::Admin => 2,
        }
    }
}

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
    ResumeSession {
        username: String,
        session_token: String,
    },
    Logout,
    CreateChatServer {
        name: String,
        #[serde(default)]
        icon: Option<String>,
    },
    JoinChatServer {
        server_id: String,
    },
    SelectChatServer {
        server_id: String,
    },
    LeaveChatServer {
        server_id: String,
    },
    SendMessage {
        #[serde(default = "default_chat_server_id")]
        server_id: String,
        #[serde(default = "default_channel_id")]
        channel_id: String,
        content: String,
    },
    CreateChannel {
        name: String,
        topic: String,
    },
    EditChannel {
        channel_id: String,
        name: String,
        topic: String,
    },
    GetProfile {
        username: String,
    },
    UpdateProfile {
        picture: Option<String>,
        banner: Option<String>,
    },
    SetUserRole {
        username: String,
        role: UserRole,
    },
    SetUserBanned {
        username: String,
        banned: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub picture: Option<String>,
    pub banner: Option<String>,
    #[serde(default)]
    pub role: UserRole,
    #[serde(default)]
    pub banned: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Authenticated {
        username: String,
        picture: Option<String>,
        banner: Option<String>,
        role: UserRole,
        #[serde(default)]
        session_token: String,
    },
    SessionExpired {
        message: String,
    },
    AuthenticationFailed {
        message: String,
    },
    AccountBanned {
        message: String,
    },
    LoggedOut,
    ChatMessage {
        #[serde(default = "default_chat_server_id")]
        server_id: String,
        #[serde(default = "default_channel_id")]
        channel_id: String,
        author: String,
        content: String,
    },
    Channels {
        #[serde(default = "default_chat_server_id")]
        server_id: String,
        channels: Vec<Channel>,
    },
    ChatServers {
        servers: Vec<ChatServerView>,
        active_server_id: String,
    },
    UserJoined {
        #[serde(default = "default_chat_server_id")]
        server_id: String,
        username: String,
    },
    UserLeft {
        #[serde(default = "default_chat_server_id")]
        server_id: String,
        username: String,
    },
    ProfileUpdated(UserProfile),
    Profile(UserProfile),
    Error {
        message: String,
    },
}
