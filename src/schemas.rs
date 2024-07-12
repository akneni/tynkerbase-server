pub use tynkerbase_universal::netwk_utils::Node;
use mongodb::bson::Bson;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Debug, Serialize, Deserialize)]
pub struct UserAuthData {
    pub email: String,
    pub pass_sha256: String,
    pub creation_time: f64,
    pub salt: String,
    pub ngrok_aes: Option<Bson>,
}

impl UserAuthData {
    pub fn new(email: &str, pass_sha256: &str) -> Self {
        let start = SystemTime::now();
        let t = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let t = t.as_secs() as f64 + t.subsec_nanos() as f64 * 1e-9;

        let salt = tynkerbase_universal::crypt_utils::gen_salt();

        UserAuthData {
            email: email.to_string(),
            pass_sha256: pass_sha256.to_string(),
            creation_time: t,
            salt: salt,
            ngrok_aes: None,
        }
    }
}
