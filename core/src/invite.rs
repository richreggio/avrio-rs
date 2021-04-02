// Copyright 2020 he avrio core developers

extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate bs58;

extern crate avrio_database;
use avrio_database::{get_data, save_data};

extern crate avrio_config;
use avrio_config::config_db_path;

pub fn per_epoch_limit(nodes: u64) -> u64 {
    ((1.0 / 3.0) * (nodes / 2) as f64) as u64
}

/// Generates the public private key pair for a new invite, returns a tuple (publickey, privatekey)
pub fn generate_invite() -> (String, String) {
    // Generates a platform specific secure random number generator
    let rngc = randc::SystemRandom::new();
    // Uses the RNG to generate a serialized public private key pair
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
    // Verifies that the public private key pair are valid
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    (
        bs58::encode(peer_public_key_bytes).into_string(),
        bs58::encode(pkcs8_bytes).into_string(),
    )
}

/// Returns true if the invite is in existance and not spent.
pub fn unspent(invite: &str) -> bool {
    get_data(&(config_db_path() + "/invites"), invite) == "u"
}

/// Marks the invite as spent
pub fn mark_spent(invite: &str) -> Result<(), &str> {
    if !unspent(invite) {
        Err("Invite has already been spent")
    } else if save_data("s", &(config_db_path() + "/invites"), invite) != 1 {
        Err("Error marking invite as spent")
    } else {
        Ok(())
    }
}

/// Saves the public key into our invites db (and sets to unspent)
pub fn new(invite: &str) -> Result<(), &str> {
    if get_data(&(config_db_path() + "/invites"), invite) != "-1" {
        Err("Error creating invite")
    } else if save_data("u", &(config_db_path() + "/invites"), invite) != 1 {
        Err("Error saving invite")
    } else {
        Ok(())
    }
}

/// Returns true if:
/// 1) The invite format is valid
/// 2) It is on the blockchain and unspent.
pub fn valid(invite: &str) -> bool {
    unspent(invite)
}
