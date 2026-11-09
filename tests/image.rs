//! Container image scanning: archives built in-test and a mock registry.

use std::io::Write;
use std::process::Command;

use sha2::{Digest, Sha256};

fn token() -> String {
    format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo")
}

fn tar_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    b.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn digest(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

/// Layer 1 adds a secret file, layer 2 deletes it (whiteout); the config
/// carries a secret in ENV.
fn image_parts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let l1 = gzip(&tar_bytes(&[
        (
            "app/creds.env",
            format!("GITHUB_TOKEN={}\n", token()).as_bytes(),
        ),
        ("app/main.py", b"print('hi')\n"),
    ]));
    let l2 = gzip(&tar_bytes(&[("app/.wh.creds.env", b"")]));
    let cfg = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64", "os": "linux",
        "config": {"Env": [format!("DEPLOY_TOKEN={}", token())]},
        "history": [{"created_by": "COPY creds.env /app/"}]
    }))
    .unwrap();
    (l1, l2, cfg)
}

fn manifest(cfg: &[u8], layers: &[&[u8]]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(cfg), "size": cfg.len()},
        "layers": layers.iter().map(|l| serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(l), "size": l.len()
        })).collect::<Vec<_>>()
    }))
    .unwrap()
}

fn kubera(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn findings(out: &std::process::Output) -> Vec<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    v.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["detector"].as_str().unwrap().to_string(),
                f["location"]["path"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn oci_layout_archive_finds_deleted_file_and_env() {
    let (l1, l2, cfg) = image_parts();
    let m = manifest(&cfg, &[&l1, &l2]);
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": digest(&m), "size": m.len(),
                       "platform": {"os": "linux", "architecture": "amd64"}}]
    }))
    .unwrap();
    let blob = |b: &[u8]| format!("blobs/sha256/{}", &digest(b)[7..]);
    let files: Vec<(String, Vec<u8>)> = vec![
        (
            "oci-layout".into(),
            br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
        ),
        ("index.json".into(), index),
        (blob(&m), m.clone()),
        (blob(&cfg), cfg.clone()),
        (blob(&l1), l1.clone()),
        (blob(&l2), l2.clone()),
    ];
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.tar");
    std::fs::write(&path, tar_bytes(&refs)).unwrap();
    let out = kubera(&["scan", "image", path.to_str().unwrap(), "-f", "json"]);
    let f = findings(&out);
    assert!(
        f.contains(&("github-token".into(), "/app/creds.env".into())),
        "{f:?}"
    );
    assert!(
        f.iter().any(|(_, p)| p.starts_with("<image config")),
        "{f:?}"
    );
}

#[test]
fn docker_save_archive() {
    let (l1, _l2, cfg) = image_parts();
    let raw_layer = {
        // docker save (legacy) stores uncompressed layer.tar files.
        let mut d = flate2::read::GzDecoder::new(l1.as_slice());
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut d, &mut v).unwrap();
        v
    };
    let manifest_json = serde_json::to_vec(&serde_json::json!([
        {"Config": "cfg.json", "RepoTags": ["acme/app:1.0"], "Layers": ["abc/layer.tar"]}
    ]))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("saved.tar");
    std::fs::write(
        &path,
        tar_bytes(&[
            ("manifest.json", &manifest_json),
            ("cfg.json", &cfg),
            ("abc/layer.tar", &raw_layer),
        ]),
    )
    .unwrap();
    let out = kubera(&["scan", "image", path.to_str().unwrap(), "-f", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2, "{v:#}");
    assert_eq!(v[0]["location"]["repository"], "acme/app:1.0");
}

async fn mock_registry(tamper: bool) -> (wiremock::MockServer, String) {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (l1, l2, cfg) = image_parts();
    let m = manifest(&cfg, &[&l1, &l2]);
    let server = MockServer::start().await;
    let challenge = format!(
        r#"Bearer realm="{}/token",service="test-registry",scope="repository:acme/app:pull""#,
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/token"))
        .and(query_param("service", "test-registry"))
        .and(query_param("scope", "repository:acme/app:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "T0K"})))
        .mount(&server)
        .await;
    let authed = |p: String, body: Vec<u8>| {
        Mock::given(method("GET"))
            .and(path(p))
            .and(header("authorization", "Bearer T0K"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
    };
    authed("/v2/acme/app/manifests/1.0".into(), m)
        .mount(&server)
        .await;
    authed(format!("/v2/acme/app/blobs/{}", digest(&cfg)), cfg.clone())
        .mount(&server)
        .await;
    authed(format!("/v2/acme/app/blobs/{}", digest(&l1)), l1.clone())
        .mount(&server)
        .await;
    let l2_body = if tamper {
        b"tampered".to_vec()
    } else {
        l2.clone()
    };
    authed(format!("/v2/acme/app/blobs/{}", digest(&l2)), l2_body)
        .mount(&server)
        .await;
    // Anything unauthenticated gets the bearer challenge.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(401).insert_header("www-authenticate", challenge.as_str()),
        )
        .mount(&server)
        .await;
    let image = format!(
        "{}/acme/app:1.0",
        server.uri().trim_start_matches("http://")
    );
    (server, image)
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_pull_with_bearer_token_flow() {
    let (_server, image) = mock_registry(false).await;
    let out = tokio::task::spawn_blocking(move || {
        kubera(&["scan", "image", &image, "--plain-http", "-f", "json"])
    })
    .await
    .unwrap();
    let f = findings(&out);
    assert!(
        f.contains(&("github-token".into(), "/app/creds.env".into())),
        "{f:?}"
    );
    assert_eq!(f.len(), 2, "{f:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_blob_digest_is_verified() {
    let (_server, image) = mock_registry(true).await;
    let out = tokio::task::spawn_blocking(move || {
        kubera(&["scan", "image", &image, "--plain-http", "-f", "json"])
    })
    .await
    .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("digest mismatch"), "{err}");
}

#[test]
fn plain_http_registry_requires_opt_in() {
    let out = kubera(&["scan", "image", "127.0.0.1:9/acme/app:1"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("https://127.0.0.1:9"));
}
