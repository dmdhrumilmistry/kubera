//! Trust roots for platforms where the OS verifier is unavailable.
//!
//! On most platforms reqwest verifies TLS with `rustls-platform-verifier`,
//! which asks the operating system. On Android that verifier calls into the
//! Java runtime through JNI and must be initialised with a JVM handle - which
//! a plain native CLI (for example under Termux) never has, so the first
//! HTTPS request panics. There we verify against an explicit root store
//! instead, built from the first source that yields certificates:
//!
//! 1. `SSL_CERT_FILE` (a PEM bundle), the conventional override;
//! 2. Termux's CA bundle (`$PREFIX/etc/tls/cert.pem`);
//! 3. Android's system stores (`/apex/com.android.conscrypt/cacerts` on
//!    Android 14+, `/system/etc/security/cacerts` before that);
//! 4. Mozilla's root program, embedded at build time (`webpki-root-certs`).
//!
//! Preferring files on the device keeps roots current with system updates
//! and honours user-installed CAs (corporate proxies); the embedded set is a
//! last resort so verification never silently has zero roots.

use std::path::{Path, PathBuf};

use reqwest::Certificate;

/// Where a root store came from (shown in diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootSource {
    Bundle(PathBuf),
    Directory(PathBuf),
    Embedded,
}

/// Termux's default prefix, used when `$PREFIX` is not exported.
const TERMUX_PREFIX: &str = "/data/data/com.termux/files/usr";

/// Android system CA directories, newest first.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const ANDROID_CA_DIRS: &[&str] = &[
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
];

/// PEM bundles to try, in priority order.
pub fn candidate_bundles(ssl_cert_file: Option<&str>, prefix: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(f) = ssl_cert_file.filter(|f| !f.is_empty()) {
        out.push(PathBuf::from(f));
    }
    if let Some(p) = prefix.filter(|p| !p.is_empty()) {
        out.push(Path::new(p).join("etc/tls/cert.pem"));
    }
    let termux = Path::new(TERMUX_PREFIX).join("etc/tls/cert.pem");
    if !out.contains(&termux) {
        out.push(termux);
    }
    out
}

/// Parse a PEM bundle; `None` if unreadable or it contains no certificate.
pub fn load_bundle(path: &Path) -> Option<Vec<Certificate>> {
    let data = std::fs::read(path).ok()?;
    let certs = Certificate::from_pem_bundle(&data).ok()?;
    (!certs.is_empty()).then_some(certs)
}

/// Load every PEM certificate file in a directory (Android's `cacerts`
/// layout: one `<hash>.0` file per root). Unparseable entries are skipped.
pub fn load_dir(dir: &Path) -> Option<Vec<Certificate>> {
    let mut certs = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if let Ok(data) = std::fs::read(entry.path())
            && let Ok(mut c) = Certificate::from_pem_bundle(&data)
        {
            certs.append(&mut c);
        }
    }
    (!certs.is_empty()).then_some(certs)
}

/// First non-empty root store among the on-device sources.
pub fn find_on_device(
    bundles: &[PathBuf],
    dirs: &[PathBuf],
) -> Option<(Vec<Certificate>, RootSource)> {
    for b in bundles {
        if let Some(c) = load_bundle(b) {
            return Some((c, RootSource::Bundle(b.clone())));
        }
    }
    for d in dirs {
        if let Some(c) = load_dir(d) {
            return Some((c, RootSource::Directory(d.clone())));
        }
    }
    None
}

/// Root store for Android: on-device sources, else the embedded Mozilla set.
#[cfg(target_os = "android")]
pub fn android_roots() -> (Vec<Certificate>, RootSource) {
    let bundles = candidate_bundles(
        std::env::var("SSL_CERT_FILE").ok().as_deref(),
        std::env::var("PREFIX").ok().as_deref(),
    );
    let dirs: Vec<PathBuf> = ANDROID_CA_DIRS.iter().map(PathBuf::from).collect();
    if let Some(found) = find_on_device(&bundles, &dirs) {
        return found;
    }
    let embedded = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| Certificate::from_der(der.as_ref()).ok())
        .collect();
    (embedded, RootSource::Embedded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_priority_and_dedup() {
        let c = candidate_bundles(Some("/x/ca.pem"), Some("/p"));
        assert_eq!(
            c,
            vec![
                PathBuf::from("/x/ca.pem"),
                PathBuf::from("/p/etc/tls/cert.pem"),
                PathBuf::from(TERMUX_PREFIX).join("etc/tls/cert.pem"),
            ]
        );
        // Termux's own prefix is not listed twice.
        let c = candidate_bundles(None, Some(TERMUX_PREFIX));
        assert_eq!(c.len(), 1);
        // Empty values are ignored.
        assert_eq!(candidate_bundles(Some(""), Some("")).len(), 1);
    }

    #[test]
    fn missing_and_empty_sources_fall_through() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        assert!(load_bundle(&empty).is_none());
        assert!(load_bundle(&dir.path().join("missing.pem")).is_none());
        assert!(load_dir(dir.path()).is_none());
        assert!(find_on_device(&[empty], &[dir.path().to_path_buf()]).is_none());
    }

    #[test]
    fn loads_system_bundle_when_present() {
        // Any Linux CI host has one of these; skip silently otherwise.
        let candidates = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
        ];
        let Some(path) = candidates.iter().map(Path::new).find(|p| p.exists()) else {
            return;
        };
        let (certs, src) = find_on_device(&[path.to_path_buf()], &[]).unwrap();
        assert!(certs.len() > 10);
        assert_eq!(src, RootSource::Bundle(path.to_path_buf()));
    }

    #[test]
    fn loads_android_style_directory() {
        // Android stores one PEM per file, often with a text dump before it.
        let Some(bundle) = ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
        else {
            return;
        };
        let text = std::fs::read_to_string(bundle).unwrap();
        let first = text
            .split_inclusive("-----END CERTIFICATE-----")
            .next()
            .unwrap()
            .trim_start();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("5ad8a5d6.0"),
            format!("Certificate:\n    Data: ...\n{first}\n"),
        )
        .unwrap();
        let (certs, src) = find_on_device(&[], &[dir.path().to_path_buf()]).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(src, RootSource::Directory(dir.path().to_path_buf()));
    }
}
