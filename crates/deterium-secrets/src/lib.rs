//! Keeps the secrets inside saved server profiles (WireGuard private keys,
//! preshared keys, and whole OpenVPN configs — which embed private keys)
//! from sitting in the profile file as readable text.
//!
//! On Windows they are encrypted with DPAPI, tied to the current Windows
//! user: another user or another PC can't decrypt the file, and no password
//! has to be remembered. A protected value looks like `dpapi:v1:<base64>`.
//! Plain values still load (old profile files) and are upgraded the next
//! time the profile is saved.
//!
//! Scope, honestly: this protects keys *at rest* — a copied profile file, a
//! backup, a synced folder. It does not hide them from programs already
//! running as the same Windows user, and the app itself necessarily holds
//! them in memory while connected.
//!
//! Other platforms: no protection is applied yet (values stay plain); the
//! profile store restricts the file's permissions there instead.

use deterium_core::ServerProfile;

const PREFIX: &str = "dpapi:v1:";
/// Binds ciphertext to this application's format, so a blob protected for
/// some other purpose by the same user isn't accepted as a profile secret.
#[cfg_attr(not(windows), allow(dead_code))] // DPAPI is the only user
const ENTROPY: &[u8] = b"Deterium profile secret v1";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error(
        "this value can't be decrypted: it was saved by another Windows user or on another PC"
    )]
    CannotDecrypt,
    #[error("the protected value is damaged")]
    Malformed,
    #[error("secret protection failed: {0}")]
    Os(String),
}

/// Whether this build can protect secrets at all.
pub fn is_available() -> bool {
    cfg!(windows)
}

pub fn is_protected(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// Encrypts `plain`. Already-protected values are returned unchanged.
pub fn protect(plain: &str) -> Result<String, SecretError> {
    if is_protected(plain) {
        return Ok(plain.to_string());
    }
    platform::protect(plain.as_bytes())
}

/// Decrypts a protected value; anything else is already plain and is
/// returned as is.
pub fn reveal(value: &str) -> Result<String, SecretError> {
    if !is_protected(value) {
        return Ok(value.to_string());
    }
    let bytes = platform::reveal(&value[PREFIX.len()..])?;
    String::from_utf8(bytes).map_err(|_| SecretError::Malformed)
}

/// Protects every secret field of the profile in place. Returns whether
/// anything changed. Without platform support nothing changes.
pub fn protect_profile(profile: &mut ServerProfile) -> Result<bool, SecretError> {
    if !is_available() {
        return Ok(false);
    }
    let mut changed = false;
    let mut apply = |field: &mut String| -> Result<(), SecretError> {
        if !field.trim().is_empty() && !is_protected(field) {
            *field = protect(field)?;
            changed = true;
        }
        Ok(())
    };

    if let Some(wg) = profile.wireguard.as_mut() {
        apply(&mut wg.interface.private_key)?;
        if let Some(psk) = wg.peer.preshared_key.as_mut() {
            apply(psk)?;
        }
    }
    if let Some(ovpn) = profile.openvpn.as_mut() {
        apply(&mut ovpn.raw_config)?;
        if let Some(password) = ovpn.password.as_mut() {
            apply(password)?;
        }
    }
    Ok(changed)
}

/// Decrypts every protected field in place. Returns `true` if the profile
/// still held plain-text secrets, i.e. it should be saved again so they get
/// protected (a one-time upgrade for profiles written before this existed).
pub fn reveal_profile(profile: &mut ServerProfile) -> Result<bool, SecretError> {
    let mut had_plain = false;
    let mut apply = |field: &mut String| -> Result<(), SecretError> {
        if is_protected(field) {
            *field = reveal(field)?;
        } else if !field.trim().is_empty() {
            had_plain = true;
        }
        Ok(())
    };

    if let Some(wg) = profile.wireguard.as_mut() {
        apply(&mut wg.interface.private_key)?;
        if let Some(psk) = wg.peer.preshared_key.as_mut() {
            apply(psk)?;
        }
    }
    if let Some(ovpn) = profile.openvpn.as_mut() {
        apply(&mut ovpn.raw_config)?;
        if let Some(password) = ovpn.password.as_mut() {
            apply(password)?;
        }
    }
    Ok(had_plain && is_available())
}

#[cfg(windows)]
mod platform {
    use super::{SecretError, ENTROPY, PREFIX};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    /// Copies a DPAPI-allocated output blob into a Vec and frees it.
    ///
    /// # Safety
    /// `out` must be an output blob filled in by a successful DPAPI call.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as *mut core::ffi::c_void);
        bytes
    }

    pub fn protect(plain: &[u8]) -> Result<String, SecretError> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: both input blobs point at live slices for the call; the
        // output blob is filled by Windows and released in `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretError::Os(format!(
                "CryptProtectData failed ({})",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the call succeeded, so `output` is a valid DPAPI allocation.
        let encrypted = unsafe { take(output) };
        Ok(format!("{PREFIX}{}", STANDARD.encode(encrypted)))
    }

    pub fn reveal(encoded: &str) -> Result<Vec<u8>, SecretError> {
        let encrypted = STANDARD
            .decode(encoded.trim())
            .map_err(|_| SecretError::Malformed)?;
        let input = blob(&encrypted);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretError::CannotDecrypt);
        }
        // SAFETY: the call succeeded, so `output` is a valid DPAPI allocation.
        Ok(unsafe { take(output) })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SecretError;

    pub fn protect(_: &[u8]) -> Result<String, SecretError> {
        Err(SecretError::Os("not supported on this platform yet".into()))
    }

    pub fn reveal(_: &str) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::CannotDecrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use deterium_core::import::parse_openvpn;
    use deterium_core::import::parse_wireguard_conf;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nPresharedKey = rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.6.0.0/24\n";
    const KEY: &str = "AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=";

    #[test]
    fn plain_values_pass_through_reveal() {
        assert_eq!(reveal("just plain text").unwrap(), "just plain text");
        assert!(!is_protected(KEY));
    }

    #[cfg(windows)]
    mod windows_only {
        use super::*;

        #[test]
        fn round_trips_and_hides_the_value() {
            let protected = protect(KEY).unwrap();
            assert!(is_protected(&protected));
            assert!(!protected.contains(KEY));
            assert_eq!(reveal(&protected).unwrap(), KEY);
        }

        #[test]
        fn protecting_twice_is_harmless_and_each_blob_differs() {
            let once = protect(KEY).unwrap();
            assert_eq!(protect(&once).unwrap(), once);
            assert_ne!(
                protect(KEY).unwrap(),
                protect(KEY).unwrap(),
                "random salt per call"
            );
        }

        #[test]
        fn a_damaged_value_is_an_error_not_garbage() {
            let protected = protect(KEY).unwrap();
            let damaged = format!("{}AAAA", &protected[..protected.len() - 4]);
            assert!(reveal(&damaged).is_err());
            assert!(matches!(
                reveal("dpapi:v1:%%%"),
                Err(SecretError::Malformed)
            ));
        }

        #[test]
        fn a_whole_wireguard_profile_round_trips() {
            let original = parse_wireguard_conf(CONF, "t").unwrap().profile;
            let mut profile = original.clone();

            assert!(protect_profile(&mut profile).unwrap());
            let wg = profile.wireguard.as_ref().unwrap();
            assert!(is_protected(&wg.interface.private_key));
            assert!(is_protected(wg.peer.preshared_key.as_ref().unwrap()));
            let toml = profile.to_toml_string().unwrap();
            assert!(
                !toml.contains(KEY),
                "the private key must not appear in the file"
            );
            assert!(!toml.contains("rJ7Pb5Ej25Q"), "nor the preshared key");
            assert!(
                toml.contains("hNB8xHQb"),
                "public keys are not secret and stay readable"
            );

            assert!(
                !reveal_profile(&mut profile).unwrap(),
                "nothing was left in plain text"
            );
            assert_eq!(
                profile.wireguard.unwrap().interface.private_key,
                original.wireguard.unwrap().interface.private_key
            );
        }

        #[test]
        fn legacy_plain_profiles_are_flagged_for_upgrade() {
            let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
            assert!(
                reveal_profile(&mut profile).unwrap(),
                "plain secrets => needs saving again"
            );
        }

        #[test]
        fn an_openvpn_config_with_embedded_keys_is_protected_whole() {
            let raw = "client\nremote a 1194\n<key>\n-----BEGIN PRIVATE KEY-----\nSECRETSECRET\n-----END PRIVATE KEY-----\n</key>\n";
            let mut profile = parse_openvpn(raw, "o").unwrap().profile;
            assert!(protect_profile(&mut profile).unwrap());
            let toml = profile.to_toml_string().unwrap();
            assert!(!toml.contains("SECRETSECRET"));
            assert!(
                !toml.contains("remote a 1194"),
                "the whole config is opaque"
            );

            reveal_profile(&mut profile).unwrap();
            assert_eq!(profile.openvpn.unwrap().raw_config, raw);
        }

        #[test]
        fn the_openvpn_password_is_protected_but_the_username_stays_readable() {
            let mut profile = parse_openvpn("client\nremote a 1194\nauth-user-pass\n", "o")
                .unwrap()
                .profile;
            let ovpn = profile.openvpn.as_mut().unwrap();
            ovpn.username = Some("alice".into());
            ovpn.password = Some("hunter2-correct-horse".into());

            assert!(protect_profile(&mut profile).unwrap());
            let toml = profile.to_toml_string().unwrap();
            assert!(!toml.contains("hunter2"), "password must not be readable");
            assert!(toml.contains("alice"));

            reveal_profile(&mut profile).unwrap();
            let ovpn = profile.openvpn.unwrap();
            assert_eq!(ovpn.password.as_deref(), Some("hunter2-correct-horse"));
        }

        #[test]
        fn empty_secrets_are_left_alone() {
            let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
            profile.wireguard.as_mut().unwrap().peer.preshared_key = Some(String::new());
            protect_profile(&mut profile).unwrap();
            assert_eq!(
                profile.wireguard.unwrap().peer.preshared_key.as_deref(),
                Some("")
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn without_platform_support_profiles_are_left_untouched() {
        let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        assert!(!protect_profile(&mut profile).unwrap());
        assert_eq!(profile.wireguard.unwrap().interface.private_key, KEY);
    }
}
