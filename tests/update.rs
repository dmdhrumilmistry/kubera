//! `kubera update` against a fake GitHub release served by a mock server.
//!
//! The "installed binary" is always a throwaway file in a temporary
//! directory, never the test binary itself.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use kubera::update::{self, Source, Updater};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TARGET: &str = "x86_64-unknown-linux-musl";
const ASSET: &str = "kubera-x86_64-unknown-linux-musl.tar.gz";

/// A release archive laid out like release.yml's, holding `binary`.
fn archive(binary: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data, mode) in [
        (format!("kubera-{TARGET}/README.md"), &b"readme"[..], 0o644),
        (format!("kubera-{TARGET}/kubera"), binary, 0o755),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_cksum();
        tar.append_data(&mut h, name, data).unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

/// A stand-in for a new kubera: a script that prints its version.
fn fake_kubera(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho \"kubera {version}\"\n").into_bytes()
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

fn source(server: &MockServer) -> Source {
    Source {
        api: format!("{}/api/", server.uri()).parse().unwrap(),
        repo: "owner/kubera".into(),
        hosts: vec!["127.0.0.1".into()],
        allow_http: true,
    }
}

struct Fake {
    tag: &'static str,
    archive: Vec<u8>,
    checksum: String,
    api_digest: Option<String>,
}

impl Fake {
    fn new(tag: &'static str, binary: &[u8]) -> Self {
        let archive = archive(binary);
        let checksum = format!("{}  {ASSET}\n", sha256(&archive));
        Self {
            tag,
            archive,
            checksum,
            api_digest: None,
        }
    }

    /// Serve the release. The archive URL redirects (like github.com does)
    /// to a second path that holds the bytes.
    async fn serve(&self, server: &MockServer, api_path: &str) {
        let base = server.uri();
        let mut asset = serde_json::json!({
            "name": ASSET,
            "browser_download_url": format!("{base}/download/{}/{ASSET}", self.tag),
            "size": self.archive.len(),
        });
        if let Some(d) = &self.api_digest {
            asset["digest"] = serde_json::json!(format!("sha256:{d}"));
        }
        let body = serde_json::json!({
            "tag_name": self.tag,
            "draft": false,
            "prerelease": false,
            "assets": [
                asset,
                {
                    "name": format!("{ASSET}.sha256"),
                    "browser_download_url": format!("{base}/download/{}/{ASSET}.sha256", self.tag),
                    "size": self.checksum.len(),
                },
                {
                    "name": "kubera-aarch64-apple-darwin.tar.gz",
                    "browser_download_url": format!("{base}/download/{}/other.tar.gz", self.tag),
                    "size": 1,
                }
            ]
        });
        Mock::given(method("GET"))
            .and(path(api_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/download/{}/{ASSET}", self.tag)))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{base}/objects/{ASSET}?sig=s3cr3t")),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/objects/{ASSET}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(self.archive.clone()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/download/{}/{ASSET}.sha256", self.tag)))
            .respond_with(ResponseTemplate::new(200).set_body_string(self.checksum.clone()))
            .mount(server)
            .await;
    }
}

/// A fake installed kubera in its own directory.
fn installed(version: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("kubera");
    std::fs::write(&exe, fake_kubera(version)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, exe)
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn finds_the_latest_release() {
    let server = MockServer::start().await;
    Fake::new("v9.9.9", &fake_kubera("9.9.9"))
        .serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let rel = Updater::new(source(&server))
        .unwrap()
        .release(None)
        .await
        .unwrap();
    assert_eq!(rel.tag, "v9.9.9");
    assert_eq!(rel.version.to_string(), "9.9.9");
    assert!(rel.version > update::current_version());
    assert!(rel.asset(ASSET).is_some());
}

#[tokio::test]
async fn looks_up_a_tag_and_rejects_odd_ones_offline() {
    let server = MockServer::start().await;
    Fake::new("v0.1.0", &fake_kubera("0.1.0"))
        .serve(&server, "/api/repos/owner/kubera/releases/tags/v0.1.0")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    assert_eq!(up.release(Some("0.1.0")).await.unwrap().tag, "v0.1.0");
    let err = up.release(Some("../../evil")).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("not a release version"),
        "{err:#}"
    );
    let err = up.release(Some("v7.7.7")).await.unwrap_err();
    assert!(format!("{err:#}").contains("not found"), "{err:#}");
    // Only the two lookups for real tags reached the server.
    let api_calls = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().starts_with("/api/"))
        .count();
    assert_eq!(api_calls, 2);
}

#[cfg(unix)]
#[tokio::test]
async fn installs_a_verified_release_over_the_binary() {
    let server = MockServer::start().await;
    let new = fake_kubera("9.9.9");
    let mut fake = Fake::new("v9.9.9", &new);
    fake.api_digest = Some(sha256(&fake.archive));
    fake.serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    let rel = up.release(None).await.unwrap();
    let (dir, exe) = installed("0.0.1");

    up.install(&rel, TARGET, &exe).await.unwrap();

    assert_eq!(std::fs::read(&exe).unwrap(), new);
    let out = Command::new(&exe).arg("--version").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "kubera 9.9.9");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
        0o755
    );
    // No temporary files left behind.
    assert_eq!(dir_entries(dir.path()), ["kubera"]);
}

#[tokio::test]
async fn checksum_mismatch_aborts_without_touching_the_binary() {
    let server = MockServer::start().await;
    let mut fake = Fake::new("v9.9.9", &fake_kubera("9.9.9"));
    fake.checksum = format!("{}  {ASSET}\n", "0".repeat(64));
    fake.serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    let rel = up.release(None).await.unwrap();
    let (dir, exe) = installed("0.0.1");
    let before = std::fs::read(&exe).unwrap();

    let err = up.install(&rel, TARGET, &exe).await.unwrap_err();

    let msg = format!("{err:#}");
    assert!(msg.contains("checksum mismatch"), "{msg}");
    assert!(!msg.contains("s3cr3t"), "pre-signed query leaked: {msg}");
    assert_eq!(std::fs::read(&exe).unwrap(), before);
    assert_eq!(dir_entries(dir.path()), ["kubera"]);
}

#[tokio::test]
async fn api_digest_must_agree_with_the_checksum_file() {
    let server = MockServer::start().await;
    let mut fake = Fake::new("v9.9.9", &fake_kubera("9.9.9"));
    fake.api_digest = Some("1".repeat(64));
    fake.serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    let rel = up.release(None).await.unwrap();
    let (_dir, exe) = installed("0.0.1");
    let before = std::fs::read(&exe).unwrap();

    let err = up.install(&rel, TARGET, &exe).await.unwrap_err();

    assert!(format!("{err:#}").contains("refusing to update"), "{err:#}");
    assert_eq!(std::fs::read(&exe).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn a_binary_that_does_not_run_is_not_installed() {
    let server = MockServer::start().await;
    // Verified bytes, but not something that runs and reports the version.
    Fake::new("v9.9.9", b"#!/bin/sh\nexit 3\n")
        .serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    let rel = up.release(None).await.unwrap();
    let (dir, exe) = installed("0.0.1");
    let before = std::fs::read(&exe).unwrap();

    let err = up.install(&rel, TARGET, &exe).await.unwrap_err();

    assert!(
        format!("{err:#}").contains("nothing was changed"),
        "{err:#}"
    );
    assert_eq!(std::fs::read(&exe).unwrap(), before);
    assert_eq!(dir_entries(dir.path()), ["kubera"]);
}

#[tokio::test]
async fn missing_checksum_file_is_refused() {
    let server = MockServer::start().await;
    let fake = Fake::new("v9.9.9", &fake_kubera("9.9.9"));
    fake.serve(&server, "/api/repos/owner/kubera/releases/latest")
        .await;
    let up = Updater::new(source(&server)).unwrap();
    let mut rel = up.release(None).await.unwrap();
    rel.assets.retain(|a| !a.name.ends_with(".sha256"));
    let (_dir, exe) = installed("0.0.1");

    let err = up.install(&rel, TARGET, &exe).await.unwrap_err();

    assert!(format!("{err:#}").contains("unverifiable"), "{err:#}");
}

#[tokio::test]
async fn redirects_only_go_to_allowed_hosts() {
    let server = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    let port = elsewhere.address().port();
    Mock::given(method("GET"))
        .and(path("/api/repos/owner/kubera/releases/latest"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("http://localhost:{port}/stolen")),
        )
        .mount(&server)
        .await;
    let err = Updater::new(source(&server))
        .unwrap()
        .release(None)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not a GitHub release host"),
        "{err:#}"
    );
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn plain_http_is_refused_by_default() {
    let server = MockServer::start().await;
    let mut src = source(&server);
    src.allow_http = false;
    let err = Updater::new(src).unwrap().release(None).await.unwrap_err();
    assert!(format!("{err:#}").contains("only https"), "{err:#}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn cli_update_help_and_non_interactive_refusal() {
    let bin = env!("CARGO_BIN_EXE_kubera");
    let out = Command::new(bin)
        .args(["update", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in ["--check", "--version", "--yes"] {
        assert!(help.contains(flag), "{help}");
    }
    // A malformed version is rejected before anything else happens.
    let out = Command::new(bin)
        .args(["update", "--check", "--version", "latest;rm"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a release version"));
}
