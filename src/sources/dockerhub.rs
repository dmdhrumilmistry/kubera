//! Docker Hub organizations: list an org's repositories and their most
//! recent tags through the Hub API, then scan each image with the
//! registry puller of [`super::image`] (every layer, config and history).
//!
//! Listing is anonymous for public repositories. With a user and a
//! personal access token, Kubera logs in to the Hub API (`/v2/users/login`)
//! to see private repositories as well; the same credentials are used for
//! the registry pulls. Hub pagination (`next`) is followed on the same
//! origin only, through [`crate::forge::Client`].

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::forge::{Client, Kind, enc};

pub struct Options {
    /// Hub API base, e.g. https://hub.docker.com.
    pub hub: String,
    /// Registry host the images are pulled from (`docker.io`).
    pub registry: String,
    /// Repositories listed per organization.
    pub limit: usize,
    /// Most recently pushed tags scanned per repository.
    pub tags: usize,
    /// Tags whose compressed size is larger are skipped.
    pub max_image_size: u64,
}

/// Exchange a username and access token for a Hub API JWT.
pub async fn login(hub: &str, user: &str, token: &str, allow_http: bool) -> Result<String> {
    let url = format!("{}/v2/users/login", hub.trim_end_matches('/'));
    let u = reqwest::Url::parse(&url).context("invalid Hub URL")?;
    if u.scheme() != "https" && !(allow_http && u.scheme() == "http") {
        bail!("refusing non-https Hub URL {}", crate::http::redact_url(&u));
    }
    let http = reqwest::Client::builder()
        .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let resp = http
        .post(u)
        .json(&serde_json::json!({"username": user, "password": token}))
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("Docker Hub login")?;
    let status = resp.status().as_u16();
    let v: Value = resp.json().await.unwrap_or_default();
    if status != 200 {
        bail!(
            "Docker Hub login failed: HTTP {status} {}",
            v["detail"].as_str().or(v["message"].as_str()).unwrap_or("")
        );
    }
    v["token"]
        .as_str()
        .map(str::to_string)
        .context("Docker Hub login answered without a token")
}

/// Image references (`docker.io/org/repo:tag`) to scan for `org`, plus
/// warnings for skipped tags.
pub async fn images(client: &Client, org: &str, o: &Options) -> Result<(Vec<String>, Vec<String>)> {
    let hub = o.hub.trim_end_matches('/');
    let ns = enc(org);
    let repos = client
        .paginate(
            Kind::Other,
            &format!("{hub}/v2/namespaces/{ns}/repositories?page_size=100"),
            o.limit,
        )
        .await
        .with_context(|| format!("listing Docker Hub repositories of {org}"))?;
    let (mut refs, mut warnings) = (Vec::new(), Vec::new());
    for r in repos {
        let name = r["name"].as_str().unwrap_or_default();
        let image = r["repository_type"].as_str().is_none_or(|t| t == "image");
        if name.is_empty() || !image {
            continue;
        }
        let url = format!(
            "{hub}/v2/namespaces/{ns}/repositories/{}/tags?page_size={}&ordering=last_updated",
            enc(name),
            o.tags.clamp(1, 100)
        );
        let tags = match client.paginate(Kind::Other, &url, o.tags.max(1)).await {
            Ok(t) => t,
            Err(e) => {
                warnings.push(format!("{org}/{name}: tags: {e:#}"));
                continue;
            }
        };
        for t in tags {
            let tag = t["name"].as_str().unwrap_or_default();
            if tag.is_empty()
                || !tag
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            {
                continue;
            }
            if t["full_size"]
                .as_u64()
                .is_some_and(|s| s > o.max_image_size)
            {
                warnings.push(format!(
                    "{org}/{name}:{tag} is larger than --max-image-size; skipped"
                ));
                continue;
            }
            refs.push(format!("{}/{org}/{name}:{tag}", o.registry));
        }
    }
    Ok((refs, warnings))
}
