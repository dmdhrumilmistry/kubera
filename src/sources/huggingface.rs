//! Hugging Face Hub: models, datasets and Spaces.
//!
//! Every Hub repository is a git repository, so it is scanned with the
//! history scanner (edits and deleted files included) through its
//! `https://huggingface.co/...` clone URL. Large files live in Git LFS:
//! the clone holds only their pointers, so model weights are never
//! downloaded. With `--include-lfs`, LFS files up to `--max-lfs-size` on
//! the main branch are fetched too (through the API's redirect to
//! pre-signed storage, without the token), checked against their LFS
//! sha256, and scanned as text or archives.
//!
//! The optional token (`hf_...`) is only sent to the Hub's own host:
//! API calls go through [`crate::forge::Client`] (same-origin `Link`
//! pagination), and clones get it as an origin-scoped header.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::Chunk;
use crate::config::Filter;
use crate::finding::{Location, SourceKind};
use crate::forge::{Client, Kind, enc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RepoType {
    Model,
    Dataset,
    Space,
}

impl RepoType {
    fn api(self) -> &'static str {
        match self {
            RepoType::Model => "models",
            RepoType::Dataset => "datasets",
            RepoType::Space => "spaces",
        }
    }

    /// URL path prefix of the repository on the Hub.
    fn prefix(self) -> &'static str {
        match self {
            RepoType::Model => "",
            RepoType::Dataset => "datasets/",
            RepoType::Space => "spaces/",
        }
    }
}

pub const ALL: [RepoType; 3] = [RepoType::Model, RepoType::Dataset, RepoType::Space];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub kind: RepoType,
    /// `owner/name`.
    pub id: String,
}

pub struct Options {
    /// Hub base, e.g. https://huggingface.co.
    pub hub: String,
    /// `owner` or `owner/name`.
    pub targets: Vec<String>,
    /// Repository types; for an owner, every type when empty.
    pub types: Vec<RepoType>,
    /// Repositories listed per owner and type.
    pub limit: usize,
    pub max_lfs_size: u64,
    pub max_file_size: u64,
}

fn valid_part(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && s.len() <= 96
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// The repositories `o` names: `owner/name` directly, `owner` listed
/// through the API.
pub async fn repos(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Vec<Repo>> {
    let hub = o.hub.trim_end_matches('/');
    let mut out = Vec::new();
    for t in &o.targets {
        let t = t.trim_matches('/');
        match t.split_once('/') {
            Some((owner, name)) => {
                if !valid_part(owner) || !valid_part(name) {
                    bail!("`{t}` is not owner/name");
                }
                let types = if o.types.is_empty() {
                    &[RepoType::Model][..]
                } else {
                    &o.types[..]
                };
                out.extend(types.iter().map(|k| Repo {
                    kind: *k,
                    id: t.to_string(),
                }));
            }
            None => {
                if !valid_part(t) {
                    bail!("`{t}` is not a Hugging Face user or organization");
                }
                let types = if o.types.is_empty() {
                    &ALL[..]
                } else {
                    &o.types[..]
                };
                for k in types {
                    progress(format!("{t}: listing {}", k.api()));
                    let url = format!("{hub}/api/{}?author={}&limit=100", k.api(), enc(t));
                    let items = client
                        .paginate(Kind::Other, &url, o.limit)
                        .await
                        .with_context(|| format!("listing {} of {t}", k.api()))?;
                    for it in items {
                        let id = it["id"].as_str().unwrap_or_default();
                        // Only repositories of this owner, with sane names.
                        let ok = id
                            .split_once('/')
                            .is_some_and(|(a, n)| a.eq_ignore_ascii_case(t) && valid_part(n));
                        if ok {
                            out.push(Repo {
                                kind: *k,
                                id: id.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    out.dedup();
    Ok(out)
}

/// The git clone URL of a repository.
pub fn clone_url(hub: &str, r: &Repo) -> String {
    format!("{}/{}{}", hub.trim_end_matches('/'), r.kind.prefix(), r.id)
}

/// Download, verify and turn into chunks the LFS files of `r`'s main
/// branch (up to `max_lfs_size` each, path excludes applied first).
pub async fn lfs_chunks(
    client: &Client,
    o: &Options,
    r: &Repo,
    filter: &Filter,
    warnings: &mut Vec<String>,
) -> Result<Vec<Chunk>> {
    let hub = o.hub.trim_end_matches('/');
    let web = format!("{hub}/{}{}", r.kind.prefix(), r.id);
    let tree = format!(
        "{hub}/api/{}/{}/tree/main?recursive=true",
        r.kind.api(),
        r.id
    );
    let files = client
        .paginate(Kind::Other, &tree, 100_000)
        .await
        .with_context(|| format!("{}: file list", r.id))?;
    let host = hub.split("://").nth(1).unwrap_or(hub);
    let repository = format!("{host}/{}{}", r.kind.prefix(), r.id);
    let mut out = Vec::new();
    for f in files {
        let (Some(path), Some(lfs)) = (f["path"].as_str(), f.get("lfs").filter(|l| l.is_object()))
        else {
            continue;
        };
        let size = lfs["size"].as_u64().unwrap_or(u64::MAX);
        // Sizes and excludes are checked before anything is downloaded.
        if size == 0 || size > o.max_lfs_size || filter.path_excluded(std::path::Path::new(path)) {
            continue;
        }
        let enc_path = path.split('/').map(enc).collect::<Vec<_>>().join("/");
        let url = format!("{web}/resolve/main/{enc_path}");
        let data = match client.download(Kind::Other, &url, o.max_lfs_size).await {
            Ok(Some(d)) => d,
            Ok(None) => continue,
            Err(e) => {
                warnings.push(format!("{}: {path}: {e:#}", r.id));
                continue;
            }
        };
        let oid = lfs["oid"].as_str().unwrap_or_default();
        if oid.len() == 64 && hex::encode(Sha256::digest(&data)) != oid.to_ascii_lowercase() {
            bail!("{}: {path}: LFS sha256 mismatch; refusing to scan it", r.id);
        }
        let location = Location {
            source: SourceKind::HuggingFace,
            repository: Some(repository.clone()),
            path: Some(path.to_string()),
            link: Some(format!("{web}/blob/main/{enc_path}")).filter(|l| l.starts_with("https://")),
            ..Default::default()
        };
        out.extend(super::bucket::object_chunks(
            data,
            location,
            o.max_file_size,
            filter,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_urls() {
        let r = |kind, id: &str| Repo {
            kind,
            id: id.into(),
        };
        let hub = "https://huggingface.co/";
        assert_eq!(
            clone_url(hub, &r(RepoType::Model, "acme/m")),
            "https://huggingface.co/acme/m"
        );
        assert_eq!(
            clone_url(hub, &r(RepoType::Dataset, "acme/d")),
            "https://huggingface.co/datasets/acme/d"
        );
        assert_eq!(
            clone_url(hub, &r(RepoType::Space, "acme/s")),
            "https://huggingface.co/spaces/acme/s"
        );
        assert!(valid_part("gpt2-small_v1.0") && !valid_part("..") && !valid_part("a/b"));
    }
}
