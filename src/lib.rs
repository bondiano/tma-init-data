#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use url::Url;

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

/// Contains launch parameters data
/// https://docs.telegram-mini-apps.com/platform/init-data#parameters-list
#[derive(Debug, PartialEq, Deserialize)]
pub struct InitData {
    /// The date the initialization data was created. Is a number representing a
    /// Unix timestamp.
    pub auth_date: u64,

    /// The number of seconds after which a message can be sent via the method answerWebAppQuery.
    pub can_send_after: Option<u64>,

    /// An object containing data about the chat where the bot was launched via the attachment menu.
    /// Returned for supergroups, channels and group chats - only for Mini Apps launched via the attachment menu.
    pub chat: Option<Chat>,

    /// The type of chat from which the Mini Apps was opened.
    /// Returned only for applications opened by direct link.
    pub chat_type: Option<String>,

    /// A global identifier indicating the chat from which the Mini Apps was opened.
    /// Returned only for applications opened by direct link.
    pub chat_instance: Option<String>,

    /// Initialization data signature.
    pub hash: String,

    /// The unique session ID of the Mini App.
    /// Used in the process of sending a message via the method answerWebAppQuery.
    pub query_id: String,

    /// An object containing data about the chat partner of the current user in the chat where the bot was launched via the attachment menu.
    /// Returned only for private chats and only for Mini Apps launched via the attachment menu.
    pub receiver: Option<User>,

    /// The value of the startattach or startapp query parameter specified in the link.
    /// It is returned only for Mini Apps opened through the attachment menu.
    pub start_param: Option<String>,

    /// An object containing information about the current user.
    pub user: Option<User>,
}

/// Describes user information:
/// https://docs.telegram-mini-apps.com/launch-parameters/init-data#user
#[derive(Debug, PartialEq, Deserialize)]
pub struct User {
    /// True, if this user added the bot to the attachment menu.
    pub added_to_attachment_menu: Option<bool>,

    /// True, if this user allowed the bot to message them.
    pub allows_write_to_pm: Option<bool>,

    /// Has the user purchased Telegram Premium.
    pub is_premium: Option<bool>,

    /// Bot or user name.
    pub first_name: String,

    /// Bot or user ID.
    pub id: i64,

    /// Is the user a bot.
    pub is_bot: Option<bool>,

    /// User's last name.
    pub last_name: Option<String>,

    /// IETF user's language.
    pub language_code: Option<String>,

    /// Link to the user's or bot's photo. Photos can have formats `.jpeg` and `.svg`.
    /// It is returned only for Mini Apps opened through the attachment menu.
    pub photo_url: Option<String>,

    /// Login of the bot or user.
    pub username: Option<String>,
}

/// Describes the chat information.
/// https://docs.telegram-mini-apps.com/platform/init-data#chat
#[derive(Debug, PartialEq, Deserialize)]
pub struct Chat {
    /// Chat ID
    pub id: i64,

    /// Chat type
    pub r#type: String,

    /// Chat title
    pub title: String,

    /// Chat photo link. The photo can have .jpeg and .svg formats.
    /// It is returned only for Mini Apps opened through the attachments menu.
    pub photo_url: Option<String>,

    /// Chat user login.
    pub username: Option<String>,
}

#[derive(Debug)]
pub enum ParseDataError {
    InvalidSignature(serde_json::Error),
    InvalidQueryString(url::ParseError),
}

/// Converts passed init data presented as query string to InitData object.
pub fn parse(init_data: String) -> Result<InitData, ParseDataError> {
    // Parse passed init data as query string
    let url = Url::parse(&format!("http://dummy.com?{}", init_data))
        .map_err(ParseDataError::InvalidQueryString)?;

    // Create a static HashSet of properties that should always be interpreted as strings
    static STRING_PROPS: phf::Set<&'static str> = phf::phf_set! {
        "start_param",
    };

    // Build JSON pairs
    let mut pairs = Vec::new();
    for (key, value) in url.query_pairs() {
        let val = value.to_string();

        // Determine the format based on whether it's a string prop or valid JSON
        let formatted_pair = if STRING_PROPS.contains(key.as_ref()) {
            // Use string format for specified string properties
            format!("\"{}\":\"{}\"", key, val)
        } else {
            // Check if the value is valid JSON
            if serde_json::from_str::<serde_json::Value>(&val).is_ok() {
                // Use raw format for valid JSON
                format!("\"{}\":{}", key, val)
            } else {
                // Use string format for non-JSON values
                format!("\"{}\":\"{}\"", key, val)
            }
        };

        pairs.push(formatted_pair);
    }

    // Create final JSON string
    let json_str = format!("{{{}}}", pairs.join(","));

    // Deserialize JSON into InitData struct
    serde_json::from_str(&json_str).map_err(ParseDataError::InvalidSignature)
}

#[derive(Debug)]
pub enum SignError {
    CouldNotProcessSignature,
    CouldNotProcessAuthTime(SystemTimeError),
    InvalidQueryString(url::ParseError),
}

/// Sign signs passed payload using specified key. Function removes such
/// technical parameters as "hash" and "auth_date".
pub fn sign(
    payload: HashMap<String, String>,
    bot_token: String,
    auth_time: SystemTime,
) -> Result<String, SignError> {
    let mut pairs = payload
        .iter()
        .filter_map(|(k, v)| {
            // Skip technical fields.
            if k == "hash" || k == "auth_date" {
                None
            } else {
                Some(format!("{}={}", k, v))
            }
        })
        .collect::<Vec<String>>();

    let auth_date = auth_time
        .duration_since(UNIX_EPOCH)
        .map_err(SignError::CouldNotProcessAuthTime)?
        .as_secs();
    // Append sign date.
    pairs.push(format!("auth_date={}", auth_date));

    // According to docs, we sort all the pairs in alphabetical order.
    pairs.sort();

    let payload = pairs.join("\n");

    // First HMAC: Create secret key using "WebAppData"
    let mut sk_hmac = HmacSha256::new_from_slice("WebAppData".as_bytes())
        .map_err(|_| SignError::CouldNotProcessSignature)?;
    sk_hmac.update(bot_token.as_bytes());
    let secret_key = sk_hmac.finalize().into_bytes();

    // Second HMAC: Sign the payload using the secret key
    let mut imp_hmac =
        HmacSha256::new_from_slice(&secret_key).map_err(|_| SignError::CouldNotProcessSignature)?;
    imp_hmac.update(payload.as_bytes());

    // Get result and convert to hex string
    let result = imp_hmac.finalize().into_bytes();
    let result = result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(result)
}

pub fn sign_query_string(
    qs: String,
    bot_token: String,
    auth_time: SystemTime,
) -> Result<String, SignError> {
    let url =
        Url::parse(&format!("http://dummy.com?{}", qs)).map_err(SignError::InvalidQueryString)?;

    let mut params: HashMap<String, String> = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.to_string(), value.to_string());
    }

    sign(params, bot_token, auth_time)
}

#[derive(Debug)]
pub enum ValidationError {
    InvalidQueryString(url::ParseError),
    UnexpectedFormat,
    SignMissing,
    AuthDateMissing,
    Expired,
    SignInvalid,
}

/// Validates passed init data. This method expects initData to be
/// passed in the exact raw format as it could be found
/// in window.Telegram.WebApp.initData. Returns `Ok` in case init data is
/// signed correctly, and it is allowed to trust it.
///
/// Current code is implementation of algorithmic code described in official
/// docs:
/// https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
///
/// # Arguments
/// * `init_data` - init data passed from application
/// * `token` - TWA bot secret token which was used to create init data
/// * `exp_in` - maximum init data lifetime. It is strongly recommended to use this
///   parameter. In case exp duration is None, function does not check if parameters are expired.
pub fn validate(
    init_data: String,
    bot_token: String,
    exp_in: Duration,
) -> Result<bool, ValidationError> {
    // Parse passed init data as query string
    let url = Url::parse(&format!("http://dummy.com?{}", init_data))
        .map_err(ValidationError::InvalidQueryString)?;

    let mut auth_date: Option<SystemTime> = None;
    let mut hash: Option<String> = None;
    let mut pairs = Vec::new();

    // Iterate over all key-value pairs of parsed parameters
    for (key, value) in url.query_pairs() {
        // Store found sign
        if key == "hash" {
            hash = Some(value.to_string());
            continue;
        }
        if key == "auth_date" {
            if let Ok(timestamp) = value.parse::<u64>() {
                auth_date = Some(UNIX_EPOCH + Duration::from_secs(timestamp));
            }
        }
        // Append new pair
        pairs.push(format!("{}={}", key, value));
    }

    // Sign is always required
    let hash = hash.ok_or(ValidationError::SignMissing)?;

    // In case expiration time is passed, we do additional parameters check
    if exp_in != Duration::from_secs(0) {
        // In case auth date is none, it means we cannot check if parameters are expired
        let auth_date = auth_date.ok_or(ValidationError::AuthDateMissing)?;

        // Check if init data is expired
        if auth_date + exp_in < SystemTime::now() {
            return Err(ValidationError::Expired);
        }
    }

    // According to docs, we sort all the pairs in alphabetical order
    pairs.sort();

    // Calculate signature
    let calculated_hash = sign_query_string(
        init_data,
        bot_token,
        auth_date.unwrap_or_else(|| UNIX_EPOCH),
    )
    .map_err(|_| ValidationError::UnexpectedFormat)?;

    // In case our sign is not equal to found one, we should throw an error
    if calculated_hash != hash {
        return Err(ValidationError::SignInvalid);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_parse_valid_data() {
        let init_data = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2&start_param=abc";
        let result = parse(init_data.to_string());
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(
            data,
            InitData {
                auth_date: 1662771648,
                can_send_after: None,
                chat: None,
                chat_type: None,
                chat_instance: None,
                hash: "c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2"
                    .to_string(),
                query_id: "AAHdF6IQAAAAAN0XohDhrOrc".to_string(),
                receiver: None,
                start_param: Some("abc".to_string()),
                user: Some(User {
                    added_to_attachment_menu: None,
                    allows_write_to_pm: None,
                    is_premium: Some(true),
                    first_name: "Vladislav".to_string(),
                    id: 279058397,
                    is_bot: None,
                    last_name: Some("Kibenko".to_string()),
                    language_code: Some("ru".to_string()),
                    photo_url: None,
                    username: Some("vdkfrost".to_string())
                })
            }
        );
    }

    #[test]
    fn test_parse_invalid_data() {
        let init_data = "invalid data";
        let result = parse(init_data.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_query_string() {
        let qs = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2".to_string();
        let test_bot_token = "5768337691:AAH5YkoiEuPk8-FZa32hStHTqXiLPtAEhx8".to_string();
        let test_sign_hash =
            "c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2".to_string();
        let auth_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1662771648);

        let result = sign_query_string(qs, test_bot_token, auth_time).unwrap();

        assert_eq!(result, test_sign_hash);
    }

    #[test]
    fn test_sign_query_string_no_date() {
        let qs = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D".to_string();
        let test_bot_token = "5768337691:AAH5YkoiEuPk8-FZa32hStHTqXiLPtAEhx8".to_string();
        let test_sign_hash =
            "c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2".to_string();
        let auth_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1662771648);

        let result = sign_query_string(qs, test_bot_token, auth_time).unwrap();

        assert_eq!(result, test_sign_hash);
    }

    #[test]
    fn test_validate_success() {
        let init_data = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2".to_string();
        let token = "5768337691:AAH5YkoiEuPk8-FZa32hStHTqXiLPtAEhx8".to_string();
        let exp_in = Duration::from_secs(1662771648);

        assert!(validate(init_data, token, exp_in).is_ok());
    }

    #[test]
    fn test_validate_expired() {
        let init_data =
            "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2.".to_string();
        let token = "your_bot_token".to_string();
        let exp_in = Duration::from_secs(86400);

        assert!(matches!(
            validate(init_data, token, exp_in),
            Err(ValidationError::Expired)
        ));
    }

    #[test]
    fn test_validate_missing_hash() {
        let init_data = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648".to_string();
        let token = "your_bot_token".to_string();
        let exp_in = Duration::from_secs(86400);

        assert!(matches!(
            validate(init_data, token, exp_in),
            Err(ValidationError::SignMissing)
        ));
    }
}
