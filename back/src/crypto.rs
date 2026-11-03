//! Envelope encryption for the vault.
//!
//! The deployment master key (`KEYSTONE_MASTER_KEY`) never encrypts secrets directly. Each vault
//! application gets its own random 256-bit data key, stored wrapped by the master key. Every value
//! is sealed with AES-256-GCM under its application's data key, and the ciphertext is bound to
//! where it lives (application, environment, kind, name, version) through associated data, so a
//! row copied to another location in the database fails to decrypt instead of leaking.
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NONCE: usize = 12;

#[derive(Clone)]
pub struct MasterKey(Key<Aes256Gcm>);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes.into())
    }
    /// A fresh application data key, returned already wrapped for storage.
    pub fn new_data_key(&self, app_id: &str) -> anyhow::Result<Vec<u8>> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        seal(&self.0, &key, format!("keystone:dek:{app_id}").as_bytes())
    }
    pub fn unwrap_data_key(&self, app_id: &str, wrapped: &[u8]) -> anyhow::Result<DataKey> {
        let raw = open(
            &self.0,
            wrapped,
            format!("keystone:dek:{app_id}").as_bytes(),
        )?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("Data key has the wrong length"))?;
        Ok(DataKey(bytes.into()))
    }
}

const CHECK: &[u8] = b"keystone-master-key-check-v1";

impl MasterKey {
    /// A value only this key can open, stored once so a wrong key is caught at startup.
    pub fn check_value(&self) -> anyhow::Result<Vec<u8>> {
        seal(&self.0, CHECK, b"keystone:kek-check")
    }
    pub fn verify(&self, check: &[u8]) -> bool {
        open(&self.0, check, b"keystone:kek-check").is_ok_and(|v| v == CHECK)
    }
    /// Re-wraps an application data key under `next` without touching any secret.
    pub fn rewrap(
        &self,
        next: &MasterKey,
        app_id: &str,
        wrapped: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let aad = format!("keystone:dek:{app_id}");
        let raw = open(&self.0, wrapped, aad.as_bytes())?;
        seal(&next.0, &raw, aad.as_bytes())
    }
    /// Console settings that may be credentials, sealed directly by the master key.
    pub fn seal_setting(&self, key: &str, value: &[u8]) -> anyhow::Result<Vec<u8>> {
        seal(&self.0, value, format!("keystone:setting:{key}").as_bytes())
    }
    pub fn open_setting(&self, key: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        open(
            &self.0,
            sealed,
            format!("keystone:setting:{key}").as_bytes(),
        )
    }
}

pub struct DataKey(Key<Aes256Gcm>);

impl DataKey {
    pub fn seal(&self, plaintext: &[u8], location: &str) -> anyhow::Result<Vec<u8>> {
        seal(&self.0, plaintext, location.as_bytes())
    }
    pub fn open(&self, sealed: &[u8], location: &str) -> anyhow::Result<Vec<u8>> {
        open(&self.0, sealed, location.as_bytes())
    }
}

/// Associated data that pins a ciphertext to one version of one item.
pub fn location(app: &str, environment: &str, kind: &str, name: &str, version: i64) -> String {
    format!("keystone:v1:{app}/{environment}/{kind}/{name}@{version}")
}

fn seal(key: &Key<Aes256Gcm>, plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    out.extend(
        Aes256Gcm::new(key)
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?,
    );
    Ok(out)
}

fn open(key: &Key<Aes256Gcm>, sealed: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(sealed.len() > NONCE, "Ciphertext is truncated");
    let (nonce, ciphertext) = sealed.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into()?;
    Aes256Gcm::new(key)
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

/// Application access token: `ksv_<id>.<secret>`. The id is a public lookup handle, the secret
/// is 256 random bits stored only as a SHA-256 digest (a slow hash adds nothing at this entropy).
pub struct NewToken {
    pub id: String,
    pub token: String,
    pub digest: Vec<u8>,
}

pub fn new_token() -> NewToken {
    let mut id = [0u8; 8];
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    OsRng.fill_bytes(&mut secret);
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let secret = URL_SAFE_NO_PAD.encode(secret);
    NewToken {
        token: format!("ksv_{id}.{secret}"),
        digest: Sha256::digest(secret.as_bytes()).to_vec(),
        id,
    }
}

/// Splits a presented token into its id and secret without touching the database.
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let (id, secret) = token.strip_prefix("ksv_")?.split_once('.')?;
    let valid_id = id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit());
    let valid_secret = secret.len() == 43
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (valid_id && valid_secret).then_some((id, secret))
}

pub fn token_matches(secret: &str, digest: &[u8]) -> bool {
    bool::from(Sha256::digest(secret.as_bytes())[..].ct_eq(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_bound_to_their_location() {
        let master = MasterKey::from_bytes([7; 32]);
        let wrapped = master.new_data_key("billing").unwrap();
        assert!(master.unwrap_data_key("other-app", &wrapped).is_err());
        let key = master.unwrap_data_key("billing", &wrapped).unwrap();
        let here = location("billing", "prod", "key", "db.password", 1);
        let sealed = key.seal(b"hunter2", &here).unwrap();
        assert_eq!(key.open(&sealed, &here).unwrap(), b"hunter2");
        let there = location("billing", "dev", "key", "db.password", 1);
        assert!(key.open(&sealed, &there).is_err());
    }

    #[test]
    fn rotation_rewraps_and_check_value_detects_wrong_key() {
        let old = MasterKey::from_bytes([1; 32]);
        let next = MasterKey::from_bytes([2; 32]);
        let wrapped = old.new_data_key("app").unwrap();
        let sealed = old
            .unwrap_data_key("app", &wrapped)
            .unwrap()
            .seal(b"v", "loc")
            .unwrap();
        let rewrapped = old.rewrap(&next, "app", &wrapped).unwrap();
        assert!(old.unwrap_data_key("app", &rewrapped).is_err());
        assert_eq!(
            next.unwrap_data_key("app", &rewrapped)
                .unwrap()
                .open(&sealed, "loc")
                .unwrap(),
            b"v"
        );
        let check = old.check_value().unwrap();
        assert!(old.verify(&check) && !next.verify(&check));
    }

    #[test]
    fn tokens_round_trip() {
        let token = new_token();
        let (id, secret) = parse_token(&token.token).unwrap();
        assert_eq!(id, token.id);
        assert!(token_matches(secret, &token.digest));
        assert!(!token_matches("wrong", &token.digest));
        assert!(parse_token("ksv_short.secret").is_none());
    }
}
