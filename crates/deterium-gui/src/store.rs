//! Where servers live on disk. User servers are one `.toml` per server in
//! `profiles/`; the optional built-in catalog is read-only and lives in
//! `catalog/` (empty by default — see docs/adr/0002).
//!
//! Secrets (private keys, preshared keys, embedded OpenVPN keys) are
//! encrypted on disk (`deterium-secrets`) and decrypted when loaded, so
//! everything above this module only ever sees ordinary profiles. A profile
//! written before encryption existed is upgraded in place the first time it
//! is loaded.

use deterium_core::{ServerProfile, Uuid};
use std::io;
use std::path::{Path, PathBuf};

/// Folder name under the app's data directory, and the pre-0.1 location
/// (relative to wherever the app was started) that is migrated from.
const PROFILES_DIR: &str = "profiles";
const CATALOG_DIR: &str = "catalog";

/// Where this user's servers live: `%APPDATA%\Deterium\profiles` on Windows,
/// `$XDG_CONFIG_HOME/deterium/profiles` (or `~/.config/...`) elsewhere.
/// `DETERIUM_DATA_DIR` overrides the base folder (portable installs, tests).
pub fn data_dir() -> PathBuf {
    if let Some(custom) = std::env::var_os("DETERIUM_DATA_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(custom);
    }
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("APPDATA") {
            return PathBuf::from(base).join("Deterium");
        }
    } else if let Some(base) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    {
        return base.join("deterium");
    }
    PathBuf::from(".")
}

pub fn user_dir() -> PathBuf {
    data_dir().join(PROFILES_DIR)
}

/// The read-only catalog ships next to the executable.
fn catalog_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(CATALOG_DIR)))
        .filter(|dir| dir.is_dir())
        .unwrap_or_else(|| PathBuf::from(CATALOG_DIR))
}

/// Moves servers saved by earlier versions (`./profiles`, relative to the
/// working directory) into the data directory. Only runs when the new place
/// is still empty, never overwrites anything, and returns how many moved.
pub fn migrate_legacy(legacy: &Path, target: &Path) -> usize {
    let has_toml = |dir: &Path| {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("toml"))
    };
    if !has_toml(legacy) || has_toml(target) {
        return 0;
    }
    if let (Ok(a), Ok(b)) = (legacy.canonicalize(), target.canonicalize()) {
        if a == b {
            return 0;
        }
    }
    if std::fs::create_dir_all(target).is_err() {
        return 0;
    }
    let mut moved = 0;
    for entry in std::fs::read_dir(legacy).into_iter().flatten().flatten() {
        let from = entry.path();
        if from.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        let to = target.join(entry.file_name());
        if to.exists() {
            continue;
        }
        // Copy first, delete the original only after the copy is verified.
        if std::fs::copy(&from, &to).is_ok()
            && std::fs::read(&from).ok() == std::fs::read(&to).ok()
            && std::fs::remove_file(&from).is_ok()
        {
            moved += 1;
        }
    }
    moved
}

#[derive(Clone)]
pub struct StoredProfile {
    pub path: PathBuf,
    pub profile: ServerProfile,
    /// Shipped with the app: connectable, but not editable or deletable.
    pub builtin: bool,
}

pub struct Loaded {
    pub profiles: Vec<StoredProfile>,
    /// Files that exist but couldn't be read, as "name: reason".
    pub skipped: Vec<String>,
    /// Profiles whose plain-text secrets were just encrypted on disk.
    pub upgraded: usize,
}

pub struct Store {
    user_dir: PathBuf,
    catalog_dir: PathBuf,
}

impl Store {
    pub fn new() -> Self {
        Self::at(user_dir(), catalog_dir())
    }

    pub fn user_dir(&self) -> &Path {
        &self.user_dir
    }

    pub fn at(user_dir: impl Into<PathBuf>, catalog_dir: impl Into<PathBuf>) -> Self {
        Self {
            user_dir: user_dir.into(),
            catalog_dir: catalog_dir.into(),
        }
    }

    pub fn load(&self) -> Loaded {
        let mut profiles = Vec::new();
        let mut skipped = Vec::new();
        let mut needs_upgrade = Vec::new();
        read_dir_into(
            &self.user_dir,
            false,
            &mut profiles,
            &mut skipped,
            &mut needs_upgrade,
        );
        read_dir_into(
            &self.catalog_dir,
            true,
            &mut profiles,
            &mut skipped,
            &mut Vec::new(),
        );

        let upgraded = needs_upgrade
            .iter()
            .filter(|path| {
                profiles
                    .iter()
                    .find(|p| &p.path == *path)
                    .is_some_and(|p| upgrade_in_place(path, &p.profile))
            })
            .count();

        profiles.sort_by_key(|p| (p.builtin, p.profile.name.to_lowercase()));
        Loaded {
            profiles,
            skipped,
            upgraded,
        }
    }

    /// Saves a profile that has no file yet.
    pub fn save_new(&self, profile: ServerProfile) -> io::Result<StoredProfile> {
        let path = self.user_dir.join(file_name_for(&profile));
        write_profile(&path, &profile)?;
        Ok(StoredProfile {
            path,
            profile,
            builtin: false,
        })
    }

    /// Overwrites the file an existing server was loaded from.
    pub fn save_existing(
        &self,
        existing: &StoredProfile,
        profile: ServerProfile,
    ) -> io::Result<StoredProfile> {
        write_profile(&existing.path, &profile)?;
        Ok(StoredProfile {
            path: existing.path.clone(),
            profile,
            builtin: false,
        })
    }

    pub fn delete(&self, stored: &StoredProfile) -> io::Result<()> {
        if stored.builtin {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "built-in servers can't be deleted",
            ));
        }
        std::fs::remove_file(&stored.path)
    }
}

fn read_dir_into(
    dir: &Path,
    builtin: bool,
    profiles: &mut Vec<StoredProfile>,
    skipped: &mut Vec<String>,
    needs_upgrade: &mut Vec<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(err) => {
                skipped.push(format!("{name}: {err}"));
                continue;
            }
        };
        let mut profile = match ServerProfile::parse(&raw) {
            Ok(profile) => profile,
            Err(err) => {
                skipped.push(format!("{name}: {err}"));
                continue;
            }
        };
        match deterium_secrets::reveal_profile(&mut profile) {
            Ok(had_plain) => {
                if had_plain && !builtin {
                    needs_upgrade.push(path.clone());
                }
                profiles.push(StoredProfile {
                    path,
                    profile,
                    builtin,
                });
            }
            Err(err) => skipped.push(format!("{name}: {err}")),
        }
    }
}

/// Rewrites a profile file so its secrets are encrypted. Verified: the file
/// is read back and decrypted, and if it doesn't match, the original bytes
/// are restored — an upgrade must never be able to lose a key.
fn upgrade_in_place(path: &Path, profile: &ServerProfile) -> bool {
    let Ok(original) = std::fs::read(path) else {
        return false;
    };
    if write_profile(path, profile).is_err() {
        return false;
    }

    let verified = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| ServerProfile::parse(&raw).ok())
        .and_then(|mut written| {
            deterium_secrets::reveal_profile(&mut written).ok()?;
            Some(written.to_toml_string().ok()? == profile.to_toml_string().ok()?)
        })
        .unwrap_or(false);

    if !verified {
        let _ = std::fs::write(path, original);
    }
    verified
}

/// Atomic write (temp file + rename) so a crash can't leave half a profile.
/// Secrets are encrypted on the way out; where that isn't available the
/// file at least gets owner-only permissions.
fn write_profile(path: &Path, profile: &ServerProfile) -> io::Result<()> {
    let mut to_save = profile.clone();
    deterium_secrets::protect_profile(&mut to_save).map_err(|e| io::Error::other(e.to_string()))?;
    let toml = to_save
        .to_toml_string()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, toml)?;
    owner_only(&tmp);
    std::fs::rename(&tmp, path)
}

fn owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn file_name_for(profile: &ServerProfile) -> String {
    let id: Uuid = profile.id;
    let short = id.to_string()[..8].to_string();
    format!("{}-{short}.toml", slug(&profile.name))
}

fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    let out: String = out.chars().take(40).collect();
    if out.is_empty() {
        "server".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_wireguard_conf;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";

    fn temp_store(tag: &str) -> (Store, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("deterium-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        (Store::at(root.join("profiles"), root.join("catalog")), root)
    }

    fn profile(name: &str) -> ServerProfile {
        parse_wireguard_conf(CONF, name).unwrap().profile
    }

    #[test]
    fn legacy_servers_move_once_and_never_overwrite() {
        let (_, root) = temp_store("migrate");
        let legacy = root.join("old");
        let target = root.join("new");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("a.toml"), "a").unwrap();
        std::fs::write(legacy.join("b.toml"), "b").unwrap();
        std::fs::write(legacy.join("notes.txt"), "keep").unwrap();

        assert_eq!(migrate_legacy(&legacy, &target), 2);
        assert_eq!(std::fs::read_to_string(target.join("a.toml")).unwrap(), "a");
        assert!(!legacy.join("a.toml").exists(), "moved, not copied");
        assert!(legacy.join("notes.txt").exists(), "other files untouched");

        // Nothing left to move; a second run is a no-op.
        assert_eq!(migrate_legacy(&legacy, &target), 0);

        // A destination that already has servers is never mixed into.
        std::fs::write(legacy.join("c.toml"), "c").unwrap();
        assert_eq!(migrate_legacy(&legacy, &target), 0);
        assert!(legacy.join("c.toml").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn slugs_are_filesystem_safe() {
        assert_eq!(slug("My VPS (Frankfurt)!"), "my-vps-frankfurt");
        assert_eq!(slug("   "), "server");
        assert_eq!(slug("../../etc/passwd"), "etc-passwd");
    }

    #[test]
    fn save_load_edit_delete_round_trip() {
        let (store, root) = temp_store("roundtrip");

        let saved = store.save_new(profile("Home")).unwrap();
        assert!(saved.path.exists());
        assert_eq!(store.load().profiles.len(), 1);

        let mut edited = saved.profile.clone();
        edited.name = "Home (renamed)".into();
        let resaved = store.save_existing(&saved, edited).unwrap();
        assert_eq!(
            resaved.path, saved.path,
            "renaming must not orphan the old file"
        );

        let loaded = store.load();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].profile.name, "Home (renamed)");

        store.delete(&resaved).unwrap();
        assert!(store.load().profiles.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn catalog_entries_are_builtin_and_undeletable() {
        let (store, root) = temp_store("catalog");
        std::fs::create_dir_all(root.join("catalog")).unwrap();
        let p = profile("Free relay");
        std::fs::write(
            root.join("catalog").join("free.toml"),
            p.to_toml_string().unwrap(),
        )
        .unwrap();

        let loaded = store.load();
        assert_eq!(loaded.profiles.len(), 1);
        assert!(loaded.profiles[0].builtin);
        assert!(store.delete(&loaded.profiles[0]).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn private_keys_are_not_readable_in_the_saved_file_but_load_back_intact() {
        let (store, root) = temp_store("encrypted");
        let saved = store.save_new(profile("Secret server")).unwrap();

        let on_disk = std::fs::read_to_string(&saved.path).unwrap();
        assert!(
            !on_disk.contains("AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw="),
            "the private key must not be readable in the file"
        );
        assert!(on_disk.contains("dpapi:v1:"));

        let loaded = store.load();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(
            loaded.profiles[0]
                .profile
                .wireguard
                .as_ref()
                .unwrap()
                .interface
                .private_key,
            "AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw="
        );
        assert!(
            loaded.profiles[0].profile.check().is_empty(),
            "decrypted profiles validate"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn an_old_plain_text_profile_is_upgraded_once_and_keeps_working() {
        let (store, root) = temp_store("upgrade");
        std::fs::create_dir_all(root.join("profiles")).unwrap();
        let path = root.join("profiles").join("old.toml");
        let plain = profile("Old server");
        std::fs::write(&path, plain.to_toml_string().unwrap()).unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("AHuqsk/lVEUc"));

        let first = store.load();
        assert_eq!(first.upgraded, 1);
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("AHuqsk/lVEUc"));
        assert_eq!(
            first.profiles[0]
                .profile
                .wireguard
                .as_ref()
                .unwrap()
                .interface
                .private_key,
            plain.wireguard.as_ref().unwrap().interface.private_key
        );

        let second = store.load();
        assert_eq!(second.upgraded, 0, "already protected, nothing to do");
        assert_eq!(second.profiles.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn a_file_that_cannot_be_decrypted_is_reported_and_left_untouched() {
        let (store, root) = temp_store("foreign");
        std::fs::create_dir_all(root.join("profiles")).unwrap();
        let mut foreign = profile("Someone else's");
        // Looks like DPAPI output, but isn't ours: decrypting must fail.
        foreign.wireguard.as_mut().unwrap().interface.private_key =
            "dpapi:v1:AAAAAAAAAAAAAAAA".into();
        let path = root.join("profiles").join("foreign.toml");
        let text = foreign.to_toml_string().unwrap();
        std::fs::write(&path, &text).unwrap();

        let loaded = store.load();
        assert!(loaded.profiles.is_empty());
        assert_eq!(loaded.skipped.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            text,
            "never modified"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_files_are_reported_not_dropped_silently() {
        let (store, root) = temp_store("skipped");
        std::fs::create_dir_all(root.join("profiles")).unwrap();
        std::fs::write(root.join("profiles").join("broken.toml"), "not = [valid").unwrap();

        let loaded = store.load();
        assert!(loaded.profiles.is_empty());
        assert_eq!(loaded.skipped.len(), 1);
        assert!(loaded.skipped[0].starts_with("broken.toml"));
        let _ = std::fs::remove_dir_all(root);
    }
}
