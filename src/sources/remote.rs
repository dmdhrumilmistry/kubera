//! Remote repository targets: URL parsing, credential handling and web links.
//!
//! Accepted forms:
//!
//! | Input | Transport |
//! |---|---|
//! | `https://github.com/org/repo(.git)` | HTTPS |
//! | `ssh://git@host[:port]/org/repo.git` | SSH |
//! | `git@github.com:org/repo.git` (scp-like) | SSH |
//! | `github.com/org/repo` (shorthand) | HTTPS |
//! | `git://host/repo.git`, `file:///path/repo.git` | git / local file |
//!
//! Credentials never travel on git's command line (where they would be
//! visible in process listings and shell history). A token is passed to git
//! as an `Authorization` header through `GIT_CONFIG_*` environment variables,
//! scoped to the repository's origin so it cannot follow a redirect to
//! another host. Credentials embedded in a URL (`https://user:token@host/…`)
//! are stripped from it and converted the same way.

use std::path::Path;

use anyhow::{Result, bail};
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Https,
    Http,
    Ssh,
    Git,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forge {
    GitHub,
    GitLab,
    Bitbucket,
}

/// A parsed remote repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRepo {
    /// URL handed to `git clone` (credentials removed).
    pub clone_url: String,
    pub transport: Transport,
    /// `scheme://host[:port]` for http(s), used to scope auth headers.
    pub origin: Option<String>,
    /// Browsable base URL (`https://github.com/org/repo`) when the host is a
    /// known forge.
    pub web: Option<(Forge, String)>,
    /// `(user, password)` found embedded in the URL, if any.
    pub embedded_credentials: Option<(String, String)>,
}

impl RemoteRepo {
    /// Display form: the clone URL, which never contains credentials.
    pub fn display(&self) -> &str {
        &self.clone_url
    }

    /// Link to a line of a file at a commit, for known forges.
    pub fn link(&self, commit: &str, path: &str, line: usize) -> Option<String> {
        let (forge, base) = self.web.as_ref()?;
        let path = path.trim_start_matches('/');
        Some(match forge {
            Forge::GitHub => format!("{base}/blob/{commit}/{path}#L{line}"),
            Forge::GitLab => format!("{base}/-/blob/{commit}/{path}#L{line}"),
            Forge::Bitbucket => format!("{base}/src/{commit}/{path}#lines-{line}"),
        })
    }
}

fn forge_for(host: &str) -> Option<Forge> {
    let h = host.to_ascii_lowercase();
    if h == "github.com" || h.starts_with("github.") {
        Some(Forge::GitHub)
    } else if h == "gitlab.com" || h.starts_with("gitlab.") {
        Some(Forge::GitLab)
    } else if h == "bitbucket.org" {
        Some(Forge::Bitbucket)
    } else {
        None
    }
}

fn web_base(host: &str, path: &str) -> Option<(Forge, String)> {
    let forge = forge_for(host)?;
    let path = path.trim_matches('/').trim_end_matches(".git");
    if path.split('/').filter(|s| !s.is_empty()).count() < 2 {
        return None;
    }
    Some((
        forge,
        format!("https://{}/{path}", host.to_ascii_lowercase()),
    ))
}

/// `user@host:path` (scp-like ssh syntax), excluding Windows drive paths.
fn parse_scp_like(s: &str) -> Option<(String, String)> {
    if s.contains("://") {
        return None;
    }
    let (left, path) = s.split_once(':')?;
    if path.is_empty() {
        return None;
    }
    let host = left.rsplit_once('@').map(|(_, h)| h).unwrap_or(left);
    // `C:\dir` is a Windows path, not a host.
    if host.len() < 2 || host.contains('/') || host.contains('\\') {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    Some((host.to_string(), path.to_string()))
}

/// `host.tld/owner/repo` shorthand.
fn parse_shorthand(s: &str) -> Option<(String, String)> {
    let (host, path) = s.split_once('/')?;
    if !host.contains('.') || host.starts_with('.') || path.is_empty() {
        return None;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
    {
        return None;
    }
    if path.split('/').filter(|p| !p.is_empty()).count() < 2 {
        return None;
    }
    Some((host.to_string(), path.to_string()))
}

/// Parse `target` as a remote repository. Returns `None` for local paths
/// (an existing path always wins over shorthand interpretation).
pub fn parse(target: &str) -> Result<Option<RemoteRepo>> {
    let t = target.trim();
    if t.starts_with('-') {
        bail!("refusing suspicious repository `{t}`");
    }
    if t.starts_with("file://") {
        return Ok(Some(RemoteRepo {
            clone_url: t.to_string(),
            transport: Transport::File,
            origin: None,
            web: None,
            embedded_credentials: None,
        }));
    }
    for (scheme, transport) in [
        ("https", Transport::Https),
        ("http", Transport::Http),
        ("ssh", Transport::Ssh),
        ("git", Transport::Git),
        ("git+ssh", Transport::Ssh),
    ] {
        if t.len() > scheme.len() + 3
            && t[..scheme.len() + 3].eq_ignore_ascii_case(&format!("{scheme}://"))
        {
            let mut url = reqwest::Url::parse(t)
                .map_err(|e| anyhow::anyhow!("invalid repository url: {e}"))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("repository url has no host"))?
                .to_string();
            if !matches!(transport, Transport::Https | Transport::Http) && url.password().is_some()
            {
                bail!(
                    "passwords in {scheme}:// URLs are not supported (they would be visible \
                     in process listings); use SSH keys or an agent"
                );
            }
            let mut embedded = None;
            if matches!(transport, Transport::Https | Transport::Http)
                && (!url.username().is_empty() || url.password().is_some())
            {
                let user = percent_decode(url.username());
                let pass = url.password().map(percent_decode).unwrap_or_default();
                // `https://TOKEN@host` puts the token in the user field.
                embedded = Some(if pass.is_empty() {
                    ("x-access-token".to_string(), user)
                } else {
                    (user, pass)
                });
                let _ = url.set_username("");
                let _ = url.set_password(None);
            }
            let origin =
                matches!(transport, Transport::Https | Transport::Http).then(|| match url.port() {
                    Some(p) => format!("{}://{host}:{p}", url.scheme()),
                    None => format!("{}://{host}", url.scheme()),
                });
            let web = web_base(&host, url.path());
            return Ok(Some(RemoteRepo {
                clone_url: url.to_string(),
                transport,
                origin,
                web,
                embedded_credentials: embedded,
            }));
        }
    }
    if Path::new(t).exists() {
        return Ok(None);
    }
    if let Some((host, path)) = parse_scp_like(t) {
        return Ok(Some(RemoteRepo {
            clone_url: t.to_string(),
            transport: Transport::Ssh,
            origin: None,
            web: web_base(&host, &path),
            embedded_credentials: None,
        }));
    }
    if let Some((host, path)) = parse_shorthand(t) {
        let url = format!("https://{host}/{}", path.trim_matches('/'));
        return parse(&url);
    }
    Ok(None)
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// How to authenticate a clone.
#[derive(Debug, Clone, Default)]
pub struct Auth {
    /// Token for HTTPS (from `--token-env`).
    pub token: Option<String>,
    /// Basic-auth username sent with the token.
    pub user: Option<String>,
    /// Permit plain-http remotes to receive credentials (tests only).
    pub allow_http: bool,
    /// Whether a human can answer prompts (SSH passphrases, host keys).
    pub interactive: bool,
}

/// Environment variables to set on the `git clone` process.
pub fn clone_env(repo: &RemoteRepo, auth: &Auth) -> Result<Vec<(String, String)>> {
    let mut env = Vec::new();
    let creds = match (&auth.token, &repo.embedded_credentials) {
        (Some(tok), _) => Some((
            auth.user
                .clone()
                .unwrap_or_else(|| "x-access-token".to_string()),
            tok.clone(),
        )),
        (None, Some(c)) => Some(c.clone()),
        (None, None) => None,
    };
    if let Some((user, secret)) = creds {
        match repo.transport {
            Transport::Https => {}
            Transport::Http if auth.allow_http => {}
            Transport::Http => bail!("refusing to send credentials over plain http"),
            _ => bail!(
                "token authentication only applies to https:// repositories (use your SSH keys for ssh)"
            ),
        }
        let origin = repo.origin.as_deref().unwrap_or_default();
        let value = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
        env.push(("GIT_CONFIG_COUNT".into(), "1".into()));
        env.push((
            "GIT_CONFIG_KEY_0".into(),
            format!("http.{origin}/.extraHeader"),
        ));
        env.push((
            "GIT_CONFIG_VALUE_0".into(),
            format!("Authorization: Basic {value}"),
        ));
    }
    if repo.transport == Transport::Ssh
        && !auth.interactive
        && std::env::var_os("GIT_SSH_COMMAND").is_none()
    {
        // Fail fast instead of hanging on a host-key or passphrase prompt.
        env.push(("GIT_SSH_COMMAND".into(), "ssh -o BatchMode=yes".into()));
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RemoteRepo {
        parse(s)
            .unwrap()
            .unwrap_or_else(|| panic!("{s} parsed as local"))
    }

    #[test]
    fn https_forms_and_web_links() {
        let r = p("https://github.com/Org/Repo.git");
        assert_eq!(r.transport, Transport::Https);
        assert_eq!(r.origin.as_deref(), Some("https://github.com"));
        assert_eq!(
            r.link("abc123", "src/a.rs", 7).unwrap(),
            "https://github.com/Org/Repo/blob/abc123/src/a.rs#L7"
        );
        let g = p("https://gitlab.com/group/sub/proj");
        assert_eq!(
            g.link("c", "x.py", 2).unwrap(),
            "https://gitlab.com/group/sub/proj/-/blob/c/x.py#L2"
        );
        let b = p("https://bitbucket.org/team/repo.git");
        assert_eq!(
            b.link("c", "f", 3).unwrap(),
            "https://bitbucket.org/team/repo/src/c/f#lines-3"
        );
        assert!(p("https://git.example.com/a/b.git").web.is_none());
    }

    #[test]
    fn ssh_forms() {
        let r = p("git@github.com:org/repo.git");
        assert_eq!(r.transport, Transport::Ssh);
        assert_eq!(r.clone_url, "git@github.com:org/repo.git");
        assert_eq!(r.web.as_ref().unwrap().1, "https://github.com/org/repo");
        let r = p("ssh://git@gitlab.com:2222/group/proj.git");
        assert_eq!(r.transport, Transport::Ssh);
        assert_eq!(r.web.unwrap().1, "https://gitlab.com/group/proj");
    }

    #[test]
    fn shorthand_and_local() {
        let r = p("github.com/org/repo");
        assert_eq!(r.clone_url, "https://github.com/org/repo");
        assert_eq!(r.transport, Transport::Https);
        // Existing paths are always local.
        let dir = tempfile::tempdir().unwrap();
        assert!(parse(dir.path().to_str().unwrap()).unwrap().is_none());
        assert!(parse(".").unwrap().is_none());
        assert!(parse("some/relative/dir").unwrap().is_none());
        assert!(parse("--upload-pack=evil").is_err());
    }

    #[test]
    fn embedded_credentials_are_stripped() {
        let r = p("https://alice:s3cr%40t@github.com/org/repo.git");
        assert_eq!(r.clone_url, "https://github.com/org/repo.git");
        assert_eq!(
            r.embedded_credentials,
            Some(("alice".to_string(), "s3cr@t".to_string()))
        );
        let r = p("https://tok123@gitlab.com/g/p.git");
        assert_eq!(r.clone_url, "https://gitlab.com/g/p.git");
        assert_eq!(
            r.embedded_credentials,
            Some(("x-access-token".to_string(), "tok123".to_string()))
        );
    }

    #[test]
    fn ssh_passwords_are_rejected() {
        let err = parse("ssh://git:hunter2@example.com/r.git").unwrap_err();
        assert!(err.to_string().contains("not supported"));
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn token_becomes_scoped_header_not_argv() {
        let r = p("https://github.com/org/private.git");
        let env = clone_env(
            &r,
            &Auth {
                token: Some("TOKEN".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let get = |k: &str| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert_eq!(get("GIT_CONFIG_COUNT").as_deref(), Some("1"));
        assert_eq!(
            get("GIT_CONFIG_KEY_0").as_deref(),
            Some("http.https://github.com/.extraHeader")
        );
        let expected = base64::engine::general_purpose::STANDARD.encode("x-access-token:TOKEN");
        assert_eq!(
            get("GIT_CONFIG_VALUE_0"),
            Some(format!("Authorization: Basic {expected}"))
        );
        assert!(!r.clone_url.contains("TOKEN"));
    }

    #[test]
    fn credential_safety_rules() {
        let http = p("http://example.com/a/b.git");
        let auth = Auth {
            token: Some("t".into()),
            ..Default::default()
        };
        assert!(clone_env(&http, &auth).is_err());
        let ssh = p("git@github.com:o/r.git");
        assert!(clone_env(&ssh, &auth).is_err());
        // Non-interactive ssh never prompts.
        let env = clone_env(&ssh, &Auth::default()).unwrap();
        if std::env::var_os("GIT_SSH_COMMAND").is_none() {
            assert!(env.contains(&(
                "GIT_SSH_COMMAND".to_string(),
                "ssh -o BatchMode=yes".to_string()
            )));
        }
        let env = clone_env(
            &ssh,
            &Auth {
                interactive: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(env.is_empty());
    }
}
