//! Where the host credential lives on disk.
//!
//! A host token is a bearer credential: anyone who reads this file can submit
//! telemetry as this host. So the file gets the strongest permissions the
//! platform offers without a service account, and the failure to set them is
//! loud rather than silent.
//!
//! Windows and Unix need different calls for the same intent, and neither is
//! expressible portably, which is why this is its own module rather than three
//! lines inside `main`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use transport::HostCredential;

/// Default location, matching where `config` already puts the offline buffer.
pub fn default_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\Chaos\host.token")
    } else {
        PathBuf::from("/var/lib/chaos/host.token")
    }
}

/// Read a stored credential. Returns `None` when there is no file, or when the
/// file does not contain a credential we would be willing to use.
pub fn load(path: &Path) -> io::Result<Option<HostCredential>> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let token = contents.trim().to_string();
            Ok(HostCredential::new(token))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write a credential, restricting access to the current user.
///
/// The write is not atomic — it is a single short string that a crash can
/// truncate, and a truncated token simply fails to parse on the next read,
/// which sends the agent back through enrollment. An atomic rename would be
/// better if the file were ever large enough to be worth interrupting.
pub fn save(path: &Path, credential: &HostCredential) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", credential.token))?;
    restrict(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // 0600: owner read/write only. The process normally runs as the same user
    // that will read it back, so there is no reason for group or other access.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::process::{Command, Stdio};

    // Break inheritance and grant only the current user. Without this, a file
    // under ProgramData is readable by any local user and the credential is
    // shared with every account on the machine.
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() {
        eprintln!(
            "warning: could not determine the current user; \
             {} may be readable by other local accounts",
            path.display()
        );
        return Ok(());
    }

    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:F"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            eprintln!(
                "warning: icacls exited with {status}; {} may be readable by \
                 other local accounts",
                path.display()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "warning: could not run icacls ({e}); {} may be readable by \
                 other local accounts",
                path.display()
            );
            Ok(())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> HostCredential {
        HostCredential::new(format!("0123456789abcdef.{}", "a".repeat(64))).expect("valid shape")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chaos-cred-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trips_a_credential() {
        let dir = temp_dir("round-trip");
        let path = dir.join("host.token");

        save(&path, &credential()).expect("save");
        let loaded = load(&path).expect("read").expect("present");
        assert_eq!(loaded, credential());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let path = temp_dir("missing").join("host.token");
        assert!(load(&path).expect("read").is_none());
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let dir = temp_dir("nested");
        let path = dir.join("a").join("b").join("host.token");
        save(&path, &credential()).expect("save");
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_file_loads_as_absent_rather_than_as_a_bad_credential() {
        let dir = temp_dir("corrupt");
        let path = dir.join("host.token");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, "this is not a token\n").unwrap();

        // `None` sends the agent back through enrollment; returning an invalid
        // credential would send it into a retry loop that can never succeed.
        assert!(load(&path).expect("read").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trailing_whitespace_is_tolerated() {
        let dir = temp_dir("whitespace");
        let path = dir.join("host.token");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, format!("  {}\n\n", credential().token)).unwrap();

        assert_eq!(load(&path).expect("read"), Some(credential()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_default_path_is_absolute_and_platform_appropriate() {
        let path = default_path();
        assert!(path.is_absolute(), "{path:?}");
        assert!(path.ends_with("host.token"));
    }

    #[cfg(unix)]
    #[test]
    fn saved_credentials_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let path = dir.join("host.token");
        save(&path, &credential()).expect("save");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
