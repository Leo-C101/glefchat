use base64::Engine;
use std::collections::HashSet;

use crate::protocol::MAX_PROFILE_IMAGE_SIZE;

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 1024;

const MAX_CHANNEL_NAME_LENGTH: usize = 32;
const MAX_CHANNEL_TOPIC_LENGTH: usize = 160;
const MAX_CHAT_SERVER_NAME_LENGTH: usize = 32;

pub fn valid_profile_image(image: &Option<String>) -> bool {
    image.as_ref().is_none_or(|image| {
        base64::engine::general_purpose::STANDARD
            .decode(image)
            .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_PROFILE_IMAGE_SIZE)
    })
}

pub fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub fn valid_channel_name(name: &str) -> bool {
    (1..=MAX_CHANNEL_NAME_LENGTH).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub fn valid_channel_topic(topic: &str) -> bool {
    topic.len() <= MAX_CHANNEL_TOPIC_LENGTH && !topic.chars().any(char::is_control)
}

pub fn valid_chat_server_name(name: &str) -> bool {
    (2..=MAX_CHAT_SERVER_NAME_LENGTH).contains(&name.len()) && !name.chars().any(char::is_control)
}

pub fn parse_admin_usernames(value: &str) -> HashSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|username| valid_username(username))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        parse_admin_usernames, valid_channel_name, valid_channel_topic, valid_chat_server_name,
        valid_username,
    };
    use std::collections::HashSet;

    #[test]
    fn username_validation_rejects_control_characters() {
        assert!(valid_username("alice_42"));
        assert!(!valid_username("al"));
        assert!(!valid_username("alice\t42"));
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
        assert!(valid_chat_server_name("GlefChat"));
        assert!(!valid_chat_server_name("x"));
    }

    #[test]
    fn admin_bootstrap_list_is_trimmed_and_validated() {
        let admins = parse_admin_usernames(" alice, invalid name, bob_2, al ");
        assert_eq!(
            admins,
            HashSet::from(["alice".to_string(), "bob_2".to_string()])
        );
    }
}
