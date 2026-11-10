use std::collections::{BTreeMap, HashMap};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use kubera::config::{Config, Filter};
use kubera::detect::Engine;
use kubera::finding::{Finding, Status};
use kubera::http::{Http, HttpOptions};
use kubera::report::{self, Format, Style};
use kubera::scan;
use kubera::sources::{self, git};
use kubera::template::{self, Loaded, Template};
use kubera::{analyze, rotate, verify};

/// Exit code used by `scan --fail` when findings are reported.
const EXIT_FINDINGS: u8 = 183;

#[derive(Parser)]
#[command(
    name = "kubera",
    version,
    about = "Find, verify, analyze and rotate leaked secrets using configurable templates",
    long_about = None,
    before_help = kubera::brand::banner_plain(),
    styles = cli_styles(),
    after_help = "Run `kubera` with no arguments in a terminal for the interactive TUI."
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Option<Command>,
}

fn cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Color, Style as S};
    let gold = Color::Ansi256(214.into());
    clap::builder::Styles::styled()
        .header(S::new().bold().fg_color(Some(gold)))
        .usage(S::new().bold().fg_color(Some(gold)))
        .literal(
            S::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightWhite))),
        )
        .placeholder(S::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack))))
        .error(S::new().bold().fg_color(Some(Color::Ansi(AnsiColor::Red))))
        .valid(S::new().bold().fg_color(Some(gold)))
        .invalid(S::new().bold().fg_color(Some(Color::Ansi(AnsiColor::Red))))
}

#[derive(Args)]
struct GlobalArgs {
    /// Config file (default: ./.kubera.yaml when present).
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Extra template file or directory (repeatable). Same id overrides a builtin.
    #[arg(short = 't', long = "templates", global = true, value_name = "PATH")]
    templates: Vec<PathBuf>,
    /// Do not load the builtin templates.
    #[arg(long, global = true)]
    no_builtin: bool,
    /// Only use these detectors (comma separated ids).
    #[arg(long, global = true, value_delimiter = ',', value_name = "IDS")]
    detectors: Vec<String>,
    /// Never use these detectors (comma separated ids).
    #[arg(long, global = true, value_delimiter = ',', value_name = "IDS")]
    exclude_detectors: Vec<String>,
    /// HTTP timeout in seconds for verification / analysis / rotation calls.
    #[arg(long, global = true, value_name = "SECS")]
    timeout: Option<u64>,
    /// Allow plain-http endpoints in templates (testing only; credentials
    /// would be sent unencrypted).
    #[arg(long, global = true, hide = true)]
    allow_http: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once from argv
enum Command {
    /// Scan for secrets.
    Scan {
        #[command(subcommand)]
        source: ScanSource,
    },
    /// Check whether a credential is live.
    Verify {
        /// Detector id (see `kubera templates list`). Omit it to let kubera
        /// identify the secret.
        detector: Option<String>,
        #[command(flatten)]
        secret: SecretArgs,
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Show what a credential is and what it can access.
    Analyze {
        /// Detector id; omit to identify the secret automatically.
        detector: Option<String>,
        #[command(flatten)]
        secret: SecretArgs,
        /// Run analysis steps even if verification did not succeed.
        #[arg(long)]
        force: bool,
        /// Print sensitive extracted values unmasked.
        #[arg(long)]
        show_secrets: bool,
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Rotate or revoke a credential (dry run unless --execute).
    Rotate {
        /// Detector id; omit to identify the secret automatically.
        detector: Option<String>,
        #[command(flatten)]
        secret: SecretArgs,
        /// Actually perform the rotation API calls.
        #[arg(long)]
        execute: bool,
        /// Skip the interactive confirmation (required when stdin is not a TTY).
        #[arg(short = 'y', long)]
        yes: bool,
        /// Proceed even if the credential does not verify as live.
        #[arg(long)]
        force: bool,
        /// Template input, `name=value` (repeatable).
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// Write the new credential to this file (created with mode 0600)
        /// instead of printing it.
        #[arg(short = 'o', long, value_name = "FILE")]
        output_file: Option<PathBuf>,
        /// After a successful rotation, also write the new credential where
        /// its consumers read it (repeatable):
        /// `github:<owner>/<repo>:<SECRET_NAME>[=<output>]`,
        /// `vault:<mount>/<path>#<key>[=<output>]`,
        /// `aws-sm:<secret-id>[#<json-key>][=<output>]`.
        #[arg(long = "store", value_name = "DEST")]
        store: Vec<String>,
        /// Environment variable with a GitHub token that may write Actions
        /// secrets (for `github:` stores).
        #[arg(long, value_name = "ENV_VAR")]
        store_token_env: Option<String>,
        /// GitHub API base for `github:` stores (GitHub Enterprise:
        /// https://ghe.example.com/api/v3).
        #[arg(long, value_name = "URL")]
        store_github_api: Option<String>,
        /// AWS region for `aws-sm:` stores [default: $AWS_REGION].
        #[arg(long, value_name = "REGION")]
        store_region: Option<String>,
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Interactive terminal UI: scan, browse findings, verify, analyze and
    /// plan rotations. TARGET is a folder, or a repository path/URL with --git
    /// (URLs are detected automatically).
    Tui {
        target: Option<String>,
        /// Treat TARGET as a git repository (scan its history).
        #[arg(long)]
        git: bool,
        /// Verify findings as soon as the scan finishes.
        #[arg(long)]
        verify: bool,
    },
    /// Run an MCP (Model Context Protocol) server on stdio so AI
    /// assistants can scan for secrets. Findings are redacted; secrets never
    /// reach the model.
    Mcp {
        /// Enable verify/analyze/rotation-plan tools (they contact vendor
        /// APIs with the found secret).
        #[arg(long)]
        allow_verify: bool,
        /// Only allow filesystem / local-repository scans under this directory.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Environment variable with a token for cloning private HTTPS
        /// repositories (set by you, never by the model).
        #[arg(long, value_name = "ENV_VAR")]
        git_token_env: Option<String>,
        /// Username sent with the git token.
        #[arg(long, value_name = "USER")]
        git_token_user: Option<String>,
    },
    /// Act on a findings file (`kubera scan ... -f json > findings.json`):
    /// open one GitHub issue per leaked secret. Dry run unless --execute.
    Remediate {
        /// Findings from `scan -f json` or `-f jsonl` (`-` for stdin).
        /// Redacted files work: issues use fingerprints and locations.
        #[arg(long, value_name = "FILE")]
        findings: PathBuf,
        /// Open issues in this repository: `github:<owner>/<repo>`. It must
        /// be private unless --allow-public-repo.
        #[arg(long, value_name = "DEST")]
        issues: String,
        /// Environment variable with a GitHub token (issues: write).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// GitHub API base (GitHub Enterprise: https://ghe.example.com/api/v3).
        #[arg(long, value_name = "URL", default_value = kubera::store::GITHUB_API)]
        api_url: String,
        /// Label for new issues (repeatable) [default: kubera, leaked-secret].
        #[arg(long = "label", value_name = "LABEL")]
        labels: Vec<String>,
        /// Open issues for every finding, not only verified (live) ones.
        #[arg(long)]
        all: bool,
        /// Look up the GitHub account of the commit author and @mention it.
        #[arg(long)]
        mention_committer: bool,
        /// Allow issues in a public repository (they would be visible to
        /// everyone).
        #[arg(long)]
        allow_public_repo: bool,
        /// Actually open the issues.
        #[arg(long)]
        execute: bool,
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Prepare a git history rewrite that removes the leaked values of a
    /// findings file: writes a `git filter-repo --replace-text` expressions
    /// file and prints the commands. Never rewrites or pushes by itself.
    Purge {
        /// Findings from `scan -f json` (redacted is fine: the repository is
        /// scanned again for the raw values; a --show-secrets file is used
        /// as is).
        #[arg(long, value_name = "FILE")]
        findings: PathBuf,
        /// The repository whose history holds the secrets.
        #[arg(long, value_name = "PATH", default_value = ".")]
        repo: PathBuf,
        /// Expressions file to create (mode 0600, never overwritten, must be
        /// outside the repository) [default: <repo>-kubera-purge.txt next
        /// to the repository].
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Text that replaces each secret.
        #[arg(long, default_value = "***REMOVED***")]
        replacement: String,
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Local web dashboard over the findings database (`scan --db`):
    /// trends, open live findings, breakdowns, and a JSON API.
    Serve {
        /// Findings database [default: `db:` in .kubera.yaml, else <user
        /// data dir>/kubera/findings.jsonl].
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
        /// Address to listen on. Non-loopback addresses need
        /// --allow-remote and --token-env.
        #[arg(long, default_value = kubera::serve::DEFAULT_LISTEN, value_name = "ADDR:PORT")]
        listen: std::net::SocketAddr,
        /// Allow a non-loopback --listen address (plain HTTP: put it behind
        /// TLS or an SSH tunnel).
        #[arg(long)]
        allow_remote: bool,
        /// Environment variable with an access token (at least 16
        /// characters). Required with --allow-remote; optional otherwise.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
    },
    /// Manage detector templates.
    Templates {
        #[command(subcommand)]
        cmd: TemplatesCmd,
    },
    /// Git pre-commit hook that blocks commits adding secrets.
    Hook {
        #[command(subcommand)]
        cmd: HookCmd,
    },
    /// Update kubera to the latest GitHub release. Contacts GitHub only when
    /// you run it; the download is SHA-256 verified before anything changes.
    Update {
        /// Only report whether a newer release exists.
        #[arg(long)]
        check: bool,
        /// Install this release (e.g. v0.3.0) instead of the latest; may
        /// downgrade.
        #[arg(long, value_name = "TAG")]
        version: Option<String>,
        /// Skip the confirmation prompt (required when stdin is not a TTY).
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum HookCmd {
    /// Install the pre-commit hook (runs `kubera scan staged --fail`).
    Install {
        /// Repository (default: the current one).
        #[arg(default_value = ".")]
        repo: PathBuf,
        /// Replace an existing hook kubera did not write (kept as
        /// pre-commit.bak).
        #[arg(long)]
        force: bool,
    },
    /// Remove the pre-commit hook installed by kubera.
    Uninstall {
        #[arg(default_value = ".")]
        repo: PathBuf,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once from argv
enum ScanSource {
    /// Scan files and directories.
    Fs {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan the full history of a git repository.
    ///
    /// REPO can be a local path, an https:// / ssh:// / git:// / file:// URL,
    /// scp-like `git@host:org/repo.git`, or shorthand `github.com/org/repo`.
    Git {
        repo: String,
        /// Only scan this branch / ref (default: all refs).
        #[arg(long)]
        branch: Option<String>,
        /// Only scan commits after this commit.
        #[arg(long)]
        since_commit: Option<String>,
        /// Maximum number of commits to scan (remote clones are shallow).
        #[arg(long)]
        max_depth: Option<usize>,
        /// Environment variable holding an access token for private HTTPS
        /// repositories. Sent as an auth header scoped to the repository's
        /// host; never placed on git's command line.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Username paired with the token (default `x-access-token`; GitLab
        /// accepts any, Bitbucket needs `x-token-auth` or your username).
        #[arg(long, value_name = "USER")]
        token_user: Option<String>,
        /// Incremental scanning: remember the ref tips of the last passing
        /// scan in FILE and only scan commits added since then.
        #[arg(long, value_name = "FILE")]
        state: Option<PathBuf>,
        /// When the state baseline may advance.
        #[arg(long, value_enum, default_value_t = kubera::state::Policy::Pass, requires = "state")]
        state_policy: kubera::state::Policy,
        /// Make the scan resumable: progress and findings are saved to FILE
        /// (mode 0600, holds raw secrets) and an interrupted scan run again
        /// with the same FILE continues where it stopped. Deleted on success.
        #[arg(long, value_name = "FILE")]
        checkpoint: Option<PathBuf>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan many repositories: whole GitHub orgs/users, GitLab groups,
    /// Bitbucket workspaces, a list file, or URLs. Rate-limit aware; with
    /// --cache-dir and --state later runs only fetch and scan new commits.
    Repos {
        /// Repository URLs or local paths.
        repos: Vec<String>,
        /// GitHub organization (repeatable).
        #[arg(long, value_name = "ORG")]
        github_org: Vec<String>,
        /// GitHub user's own repositories (repeatable).
        #[arg(long, value_name = "USER")]
        github_user: Vec<String>,
        /// GitLab group, including subgroups (repeatable).
        #[arg(long, value_name = "GROUP")]
        gitlab_group: Vec<String>,
        /// Bitbucket Cloud workspace (repeatable).
        #[arg(long, value_name = "WORKSPACE")]
        bitbucket_workspace: Vec<String>,
        /// File with one repository URL or path per line (`#` comments).
        #[arg(long, value_name = "FILE")]
        repo_list: Option<PathBuf>,
        /// API base for GitHub Enterprise / self-managed GitLab, e.g.
        /// https://ghe.example.com/api/v3 or https://gitlab.example.com/api/v4.
        #[arg(long, value_name = "URL")]
        api_url: Option<String>,
        /// Environment variable with a token for the forge API and clones.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Username for the token (clones; Bitbucket app passwords).
        #[arg(long, value_name = "USER")]
        token_user: Option<String>,
        /// Include forks.
        #[arg(long)]
        include_forks: bool,
        /// Include archived repositories.
        #[arg(long)]
        include_archived: bool,
        /// Scan at most N repositories.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Repositories scanned in parallel.
        #[arg(long, default_value_t = 4, value_name = "N")]
        repo_concurrency: usize,
        /// Keep bare mirrors here and only fetch changes on later runs.
        #[arg(long, value_name = "DIR")]
        cache_dir: Option<PathBuf>,
        /// Incremental state file (see `scan git --state`).
        #[arg(long, value_name = "FILE")]
        state: Option<PathBuf>,
        /// When a repository's baseline may advance.
        #[arg(long, value_enum, default_value_t = kubera::state::Policy::Pass, requires = "state")]
        state_policy: kubera::state::Policy,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        /// Maximum commits per repository (shallow first clone).
        #[arg(long)]
        max_depth: Option<usize>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan a container image: every layer (including files deleted in
    /// later layers) plus the image config (ENV, labels, build history).
    ///
    /// IMAGE is a registry reference (alpine:3.20, ghcr.io/org/app:tag,
    /// repo@sha256:...) pulled without Docker, a `docker save` / OCI-layout
    /// tarball path, or a local Docker image with --docker.
    Image {
        image: String,
        /// Platform to pick from multi-arch images.
        #[arg(long, default_value = "linux/amd64", value_name = "OS/ARCH")]
        platform: String,
        /// Export the image from the local Docker daemon (`docker save`).
        #[arg(long)]
        docker: bool,
        /// Registry username (with --registry-token-env).
        #[arg(long, value_name = "USER")]
        registry_user: Option<String>,
        /// Environment variable with a registry password / token.
        #[arg(long, value_name = "ENV_VAR")]
        registry_token_env: Option<String>,
        /// Refuse layers larger than this many bytes.
        #[arg(long, value_name = "BYTES", default_value_t = kubera::sources::image::DEFAULT_MAX_LAYER_SIZE)]
        max_layer_size: u64,
        /// Talk to the registry over plain HTTP (local / insecure registries
        /// only; credentials would be sent unencrypted).
        #[arg(long)]
        plain_http: bool,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan standard input.
    Stdin {
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan GitHub beyond the code: issues, pull requests and their
    /// comments, review comments, Actions logs, wikis and gists.
    Github {
        /// Repositories as owner/name.
        repos: Vec<String>,
        /// Every repository of this organization (repeatable).
        #[arg(long, value_name = "ORG")]
        org: Vec<String>,
        /// Every repository and gist of this user (repeatable).
        #[arg(long, value_name = "USER")]
        user: Vec<String>,
        /// What to scan (comma separated) [default: all].
        #[arg(long, value_enum, value_delimiter = ',')]
        what: Vec<kubera::sources::github::What>,
        /// Environment variable with a GitHub token (needed for Actions logs
        /// and private repositories; raises rate limits).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// GitHub Enterprise API base, e.g. https://ghe.example.com/api/v3.
        #[arg(long, value_name = "URL", default_value = "https://api.github.com")]
        api_url: String,
        /// Issues / comments read per repository and kind (newest first).
        #[arg(long, default_value_t = 2000, value_name = "N")]
        max_items: usize,
        /// Actions runs whose logs are read per repository (newest first).
        #[arg(long, default_value_t = 20, value_name = "N")]
        max_runs: usize,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan GitLab beyond the code: issues, merge requests and their
    /// comments, CI job logs, snippets and wikis (gitlab.com or a
    /// self-managed instance).
    Gitlab {
        /// Projects as group/project (subgroups allowed: group/sub/project).
        projects: Vec<String>,
        /// Every project of this group, subgroups included (repeatable).
        #[arg(long, value_name = "GROUP")]
        group: Vec<String>,
        /// What to scan (comma separated) [default: all].
        #[arg(long, value_enum, value_delimiter = ',')]
        what: Vec<kubera::sources::gitlab::What>,
        /// Environment variable with a GitLab token (read_api scope; needed
        /// for private projects, raises rate limits).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Self-managed GitLab API base, e.g. https://gitlab.example.com/api/v4.
        #[arg(long, value_name = "URL", default_value = "https://gitlab.com/api/v4")]
        api_url: String,
        /// Issues / merge requests / comments read per project and kind
        /// (newest first).
        #[arg(long, default_value_t = 2000, value_name = "N")]
        max_items: usize,
        /// CI jobs whose logs are read per project (newest first).
        #[arg(long, default_value_t = 50, value_name = "N")]
        max_jobs: usize,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan Bitbucket Cloud beyond the code: issues, pull requests and
    /// their comments, Pipelines step logs and workspace snippets.
    Bitbucket {
        /// Repositories as workspace/repo.
        repos: Vec<String>,
        /// Every repository and snippet of this workspace (repeatable).
        #[arg(long, value_name = "WORKSPACE")]
        workspace: Vec<String>,
        /// What to scan (comma separated) [default: all].
        #[arg(long, value_enum, value_delimiter = ',')]
        what: Vec<kubera::sources::bitbucket::What>,
        /// Environment variable with a Bitbucket access token (bearer), or
        /// an app password / API token used with --token-user.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// User for app passwords and API tokens (your Bitbucket username,
        /// or your Atlassian email for API tokens).
        #[arg(long, value_name = "USER", requires = "token_env")]
        token_user: Option<String>,
        /// API base (tests and proxies).
        #[arg(
            long,
            value_name = "URL",
            default_value = "https://api.bitbucket.org/2.0"
        )]
        api_url: String,
        /// Issues / pull requests / comments read per repository and kind.
        #[arg(long, default_value_t = 2000, value_name = "N")]
        max_items: usize,
        /// Pipelines whose step logs are read per repository (newest first).
        #[arg(long, default_value_t = 20, value_name = "N")]
        max_runs: usize,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan Slack: channel messages and thread replies, with a bot (xoxb-)
    /// or user (xoxp-) token. Read-only; rate limits are honoured.
    Slack {
        /// Channel name or id (repeatable) [default: every channel the
        /// token can see].
        #[arg(long, value_name = "CHANNEL")]
        channel: Vec<String>,
        /// Only messages after this date (YYYY-MM-DD, RFC 3339 or Unix
        /// seconds).
        #[arg(long, value_name = "DATE")]
        since: Option<String>,
        /// Environment variable with the Slack token (scopes
        /// channels:history, channels:read, groups:history, groups:read).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: String,
        /// Also read direct and group messages (user tokens; im:history,
        /// mpim:history).
        #[arg(long)]
        include_dms: bool,
        /// Also read archived channels.
        #[arg(long)]
        include_archived: bool,
        /// Messages read per channel, thread replies included (newest
        /// first).
        #[arg(long, default_value_t = 10_000, value_name = "N")]
        max_messages: usize,
        /// Web API base (tests).
        #[arg(
            long,
            value_name = "URL",
            default_value = "https://slack.com/api",
            hide = true
        )]
        api_url: String,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan Jira Cloud: issue summaries, descriptions, environments,
    /// comments and earlier values from the change history.
    Jira {
        /// The site, e.g. https://acme.atlassian.net.
        #[arg(long, value_name = "URL")]
        site: String,
        /// JQL selecting the issues [default: every issue, newest first].
        #[arg(long, value_name = "QUERY", conflicts_with = "project")]
        jql: Option<String>,
        /// Only these projects (repeatable).
        #[arg(long, value_name = "KEY")]
        project: Vec<String>,
        /// Environment variable with the Atlassian account email (basic
        /// auth with --token-env).
        #[arg(long, value_name = "ENV_VAR", requires = "token_env")]
        email_env: Option<String>,
        /// Environment variable with an API token (with --email-env), or a
        /// bearer token without it. Omit both for public sites.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Issues read (in JQL order).
        #[arg(long, default_value_t = 10_000, value_name = "N")]
        max_issues: usize,
        /// Skip the change history (earlier summaries and descriptions).
        #[arg(long)]
        no_history: bool,
        /// Longest rate-limit wait (seconds) before giving up.
        #[arg(long, default_value_t = 900, value_name = "SECS")]
        max_rate_wait: u64,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan a cloud storage bucket: s3://bucket[/prefix] (also MinIO, R2
    /// and other S3-compatible stores with --endpoint-url) or
    /// gs://bucket[/prefix]. Archives inside are opened too.
    ///
    /// S3 uses AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
    /// (public buckets: --anonymous). GCS uses --token-env (an OAuth access
    /// token, e.g. from `gcloud auth print-access-token`).
    Bucket {
        url: String,
        /// S3 region (default: detected from the bucket).
        #[arg(long)]
        region: Option<String>,
        /// S3-compatible endpoint, e.g. https://<account>.r2.cloudflarestorage.com.
        #[arg(long, value_name = "URL")]
        endpoint_url: Option<String>,
        /// Send unsigned requests (public buckets).
        #[arg(long)]
        anonymous: bool,
        /// Environment variable with a GCS OAuth access token.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// List at most N objects.
        #[arg(long, default_value_t = 100_000, value_name = "N")]
        max_objects: usize,
        /// Parallel downloads.
        #[arg(long, default_value_t = 16, value_name = "N")]
        downloads: usize,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan a live Kubernetes cluster: Secrets (decoded), ConfigMaps, and
    /// literal env values, args and annotations of workloads (read-only
    /// list calls). Uses the kubeconfig like kubectl, or the pod's service
    /// account with --in-cluster.
    #[command(alias = "kubernetes")]
    K8s {
        /// Kubeconfig file [default: $KUBECONFIG or ~/.kube/config].
        #[arg(long, value_name = "FILE")]
        kubeconfig: Option<PathBuf>,
        /// Context to use [default: current-context].
        #[arg(long)]
        context: Option<String>,
        /// Use the service account of the pod kubera runs in.
        #[arg(long, conflicts_with_all = ["kubeconfig", "context"])]
        in_cluster: bool,
        /// Only these namespaces (repeatable) [default: all].
        #[arg(short = 'n', long = "namespace", value_name = "NS")]
        namespaces: Vec<String>,
        /// What to scan (comma separated) [default: all].
        #[arg(long, value_enum, value_delimiter = ',')]
        what: Vec<kubera::sources::kube::What>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan the staged changes of a repository: only the lines the next
    /// commit adds (what the pre-commit hook runs).
    Staged {
        #[arg(default_value = ".")]
        repo: PathBuf,
        #[command(flatten)]
        opts: ScanArgs,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Verify candidates against the issuing platform (sends each secret to
    /// its vendor's API).
    #[arg(long)]
    verify: bool,
    /// Report only verified secrets (implies --verify).
    #[arg(long)]
    only_verified: bool,
    /// Result kinds to report (comma separated).
    #[arg(long, value_enum, value_delimiter = ',')]
    results: Vec<ResultKind>,
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Pretty)]
    format: Format,
    /// Print secrets unmasked.
    #[arg(long)]
    show_secrets: bool,
    /// Exit with code 183 when findings are reported.
    #[arg(long)]
    fail: bool,
    /// Glob of paths to skip, relative to the scan root (repeatable).
    #[arg(long = "exclude-path", value_name = "GLOB")]
    exclude_paths: Vec<String>,
    /// Baseline / triage file: findings recorded there are not reported
    /// [default: .kubera-baseline.json when present].
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Ignore the baseline file.
    #[arg(long, conflicts_with = "baseline")]
    no_baseline: bool,
    /// Record every finding of this scan in the baseline file (adopting
    /// kubera on a codebase with known findings: later scans only report
    /// new ones). Exits 0.
    #[arg(long, conflicts_with = "no_baseline")]
    update_baseline: bool,
    /// Send an alert when secrets are found, to the webhook URL held in this
    /// environment variable (repeatable). Slack incoming webhooks get a
    /// Slack message, other URLs a JSON payload. Secrets are redacted.
    #[arg(long, value_name = "ENV_VAR")]
    notify_env: Vec<String>,
    /// Environment variable with a key to sign generic webhook payloads
    /// (X-Kubera-Signature: HMAC-SHA256 over "<timestamp>.<body>").
    #[arg(long, value_name = "ENV_VAR")]
    notify_secret_env: Option<String>,
    /// Which findings trigger an alert [default: live ones with --verify,
    /// otherwise all].
    #[arg(long, value_enum, value_name = "WHICH")]
    notify_on: Option<NotifyOn>,
    /// Do not decode base64 / URL-encoded / escaped text before scanning.
    #[arg(long)]
    no_decode: bool,
    /// Also scan dependency directories and lockfiles (node_modules,
    /// vendor, package-lock.json, ...), which are skipped by default.
    #[arg(long)]
    no_default_excludes: bool,
    /// Skip files larger than this many bytes (git history: larger files
    /// are not diffed at all).
    #[arg(long, value_name = "BYTES")]
    max_file_size: Option<u64>,
    /// Parallel workers for git history (0: one per CPU).
    #[arg(short = 'j', long, default_value_t = 0, value_name = "N")]
    jobs: usize,
    /// Concurrent verification requests.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Browse the results in the interactive TUI instead of printing them.
    #[arg(short = 'i', long)]
    interactive: bool,
    /// Record this scan in the findings database for `kubera serve`
    /// (redacted values and fingerprints only) [default PATH: <user data
    /// dir>/kubera/findings.jsonl]. Also `db:` in .kubera.yaml. Put it
    /// after the paths, or write `--db=PATH`.
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "")]
    db: Option<PathBuf>,
    /// Do not record this scan, even if .kubera.yaml enables `db:`.
    #[arg(long, conflicts_with = "db")]
    no_db: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NotifyOn {
    /// Only verified (live) secrets.
    Live,
    /// Every reported finding.
    All,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ResultKind {
    Verified,
    Unknown,
    Invalid,
    /// Detector has no verifier.
    Unverifiable,
    /// Verification was not run.
    Unverified,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutFormat {
    Pretty,
    Json,
}

#[derive(Args)]
struct SecretArgs {
    /// Secret part as NAME=VALUE (or just VALUE for single-part detectors).
    /// Visible in process listings and shell history - prefer --secret-env
    /// or --secret-stdin.
    #[arg(short = 's', long = "secret", value_name = "NAME=VALUE")]
    secret: Vec<String>,
    /// Read a secret part from an environment variable: NAME=ENV_VAR
    /// (or just ENV_VAR for single-part detectors).
    #[arg(short = 'e', long = "secret-env", value_name = "NAME=ENV_VAR")]
    secret_env: Vec<String>,
    /// Read the secret from stdin (the value itself for single-part
    /// detectors, otherwise one NAME=VALUE per line).
    #[arg(long)]
    secret_stdin: bool,
}

#[derive(Subcommand)]
enum TemplatesCmd {
    /// List available detectors.
    List {
        #[arg(long, value_enum, default_value_t = OutFormat::Pretty)]
        format: OutFormat,
    },
    /// Print a template as YAML.
    Show { id: String },
    /// Validate template files (schema, regexes, variables, samples).
    Validate {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Run the positive/negative samples of the active templates.
    Test,
    /// Print a skeleton template to start a new detector from.
    New { id: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        // `kubera ... | head` closing the pipe early is not an error.
        Err(e)
            if e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
            }) =>
        {
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

struct Ctx {
    cfg: Config,
    templates: Vec<Loaded>,
    http: Http,
    style: Style,
}

fn context(g: &GlobalArgs) -> Result<Ctx> {
    let cfg = Config::load(g.config.as_deref())?;
    let mut extra = cfg.templates.clone();
    extra.extend(g.templates.iter().cloned());
    let mut only = cfg.detectors.clone();
    only.extend(g.detectors.iter().cloned());
    let mut excl = cfg.exclude_detectors.clone();
    excl.extend(g.exclude_detectors.iter().cloned());
    let templates = template::load_set(&extra, !(cfg.no_builtin || g.no_builtin), &only, &excl)?;
    if g.allow_http {
        eprintln!("warning: --allow-http enabled; credentials may be sent unencrypted");
    }
    let http = Http::new(HttpOptions {
        allow_http: g.allow_http,
        timeout: g.timeout,
    })?;
    Ok(Ctx {
        cfg,
        templates,
        http,
        style: Style {
            color: report::use_color(),
        },
    })
}

async fn run(cli: Cli) -> Result<u8> {
    let Some(command) = cli.command else {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return cmd_tui(&cli.global, None, false, false);
        }
        use clap::CommandFactory;
        Cli::command().print_help()?;
        return Ok(0);
    };
    match command {
        Command::Scan { source } => cmd_scan(&cli.global, source).await,
        Command::Tui {
            target,
            git,
            verify,
        } => cmd_tui(&cli.global, target, git, verify),
        Command::Verify {
            detector,
            secret,
            format,
        } => {
            let ctx = context(&cli.global)?;
            let (t, parts) = resolve_secret(&ctx, detector.as_deref(), &secret)?;
            let out = verify::verify(&ctx.http, t, &parts).await;
            let v = out.verification;
            match format {
                OutFormat::Json => println!("{}", serde_json::to_string_pretty(&v)?),
                OutFormat::Pretty => {
                    let st = &ctx.style;
                    println!("{} {}", st.bold(&t.name), st.status(v.status));
                    if let Some(m) = &v.message {
                        println!("  {:<14} {m}", st.dim("message"));
                    }
                    for (k, val) in &v.details {
                        println!("  {:<14} {}", st.dim(k), report::display_value(val));
                    }
                }
            }
            Ok(match v.status {
                Status::Verified => 0,
                Status::Invalid => 2,
                _ => 3,
            })
        }
        Command::Analyze {
            detector,
            secret,
            force,
            show_secrets,
            format,
        } => {
            let ctx = context(&cli.global)?;
            let (t, parts) = resolve_secret(&ctx, detector.as_deref(), &secret)?;
            if t.analyze.is_none() && t.verify.is_none() {
                bail!(
                    "detector `{}` supports neither verification nor analysis",
                    t.id
                );
            }
            let rep = analyze::analyze(&ctx.http, t, &parts, force).await;
            let rep = if show_secrets { rep } else { rep.redacted() };
            match format {
                OutFormat::Json => println!("{}", serde_json::to_string_pretty(&rep)?),
                OutFormat::Pretty => print_analysis(&rep, &ctx.style),
            }
            Ok(if rep.verification.status == Status::Verified {
                0
            } else {
                2
            })
        }
        Command::Rotate {
            detector,
            secret,
            execute,
            yes,
            force,
            set,
            output_file,
            store,
            store_token_env,
            store_github_api,
            store_region,
            format,
        } => {
            let ctx = context(&cli.global)?;
            let (t, parts) = resolve_secret(&ctx, detector.as_deref(), &secret)?;
            let mut inputs = BTreeMap::new();
            for s in set {
                let (k, v) = s
                    .split_once('=')
                    .with_context(|| format!("--set expects NAME=VALUE, got `{s}`"))?;
                inputs.insert(k.to_string(), v.to_string());
            }
            cmd_rotate(
                &ctx,
                t,
                &parts,
                inputs,
                RotateFlags {
                    execute,
                    yes,
                    force,
                    stdin_used: secret.secret_stdin,
                    output_file,
                    stores: store,
                    store_config: kubera::store::Config::from_env(
                        store_token_env.as_deref(),
                        store_github_api.as_deref(),
                        store_region.as_deref(),
                        cli.global.allow_http,
                    ),
                    format,
                },
            )
            .await
        }
        Command::Remediate {
            findings,
            issues,
            token_env,
            api_url,
            labels,
            all,
            mention_committer,
            allow_public_repo,
            execute,
            format,
        } => {
            let (owner, repo) = kubera::remediate::parse_github(&issues)?;
            let list = kubera::remediate::load_findings(&findings)?;
            let total = list.len();
            let valid: Vec<Finding> = list
                .into_iter()
                .filter(|f| kubera::remediate::valid_fingerprint(&f.fingerprint))
                .collect();
            // One issue per secret; it is live if any sighting verified.
            let mut groups = kubera::remediate::group(&valid);
            groups.retain(|g| all || g[0].status() == Some(Status::Verified));
            let token = match &token_env {
                Some(var) => Some(std::env::var(var).with_context(|| {
                    format!("environment variable `{var}` (from --token-env) is not set")
                })?),
                None => None,
            };
            let st = Style {
                color: report::use_color(),
            };
            if groups.is_empty() {
                eprintln!(
                    "nothing to do: {total} finding(s), none {}",
                    if all {
                        "with a valid fingerprint"
                    } else {
                        "verified as live (scan with --verify, or pass --all)"
                    }
                );
                return Ok(0);
            }
            let client = match token {
                Some(t) => {
                    let mut c = kubera::forge::Client::new(
                        Some(t),
                        None,
                        std::time::Duration::from_secs(900),
                    )?;
                    c.allow_http = cli.global.allow_http;
                    Some(c)
                }
                None => None,
            };
            let o = kubera::remediate::IssueOptions {
                owner,
                repo,
                api: api_url.trim_end_matches('/').to_string(),
                labels: if labels.is_empty() {
                    vec!["kubera".into(), "leaked-secret".into()]
                } else {
                    labels
                },
                mention_committer,
                allow_public: allow_public_repo,
                execute,
                max_existing: 5000,
            };
            let rep = kubera::remediate::issues(client.as_ref(), &o, &groups).await?;
            match format {
                OutFormat::Json => println!("{}", serde_json::to_string_pretty(&rep)?),
                OutFormat::Pretty => print_issues(&rep, &st),
            }
            Ok(if rep.results.iter().any(|r| r.action == "failed") {
                1
            } else {
                0
            })
        }
        Command::Purge {
            findings,
            repo,
            output,
            replacement,
            format,
        } => cmd_purge(&cli.global, findings, repo, output, replacement, format),
        Command::Serve {
            db,
            listen,
            allow_remote,
            token_env,
        } => {
            let cfg = Config::load(cli.global.config.as_deref())?;
            let path = match db {
                Some(p) => p,
                None => cfg
                    .db_path(None, false)?
                    .map(Ok)
                    .unwrap_or_else(kubera::db::default_path)?,
            };
            let token = match &token_env {
                Some(var) => Some(std::env::var(var).with_context(|| {
                    format!("environment variable `{var}` (from --token-env) is not set")
                })?),
                None => None,
            };
            if !path.exists() {
                eprintln!(
                    "warning: {} does not exist yet; record scans with `kubera scan ... --db`",
                    path.display()
                );
            }
            let has_token = token.is_some();
            let shown = path.display().to_string();
            kubera::serve::serve(
                kubera::serve::Options {
                    db: path,
                    listen,
                    allow_remote,
                    token,
                },
                move |addr| {
                    eprintln!("kubera dashboard: http://{addr}/ (database {shown})");
                    if has_token {
                        eprintln!("open http://{addr}/?token=<token> once to sign in");
                    }
                    eprintln!("press Ctrl-C to stop");
                },
            )
            .await?;
            Ok(0)
        }
        Command::Templates { cmd } => cmd_templates(&cli.global, cmd),
        Command::Update {
            check,
            version,
            yes,
        } => cmd_update(check, version.as_deref(), yes).await,
        Command::Hook { cmd } => {
            let st = Style {
                color: report::use_color(),
            };
            match cmd {
                HookCmd::Install { repo, force } => match kubera::hook::install(&repo, force)? {
                    kubera::hook::Installed::New(p) => {
                        println!("{} installed {}", st.green("✓"), p.display())
                    }
                    kubera::hook::Installed::Updated(p) => {
                        println!("{} updated {}", st.green("✓"), p.display())
                    }
                    kubera::hook::Installed::Replaced { hook, backup } => println!(
                        "{} installed {} (previous hook kept as {})",
                        st.green("✓"),
                        hook.display(),
                        backup.display()
                    ),
                },
                HookCmd::Uninstall { repo } => match kubera::hook::uninstall(&repo)? {
                    Some(p) => println!("{} removed {}", st.green("✓"), p.display()),
                    None => println!("no kubera pre-commit hook installed"),
                },
            }
            Ok(0)
        }
        Command::Mcp {
            allow_verify,
            root,
            git_token_env,
            git_token_user,
        } => {
            let ctx = context(&cli.global)?;
            let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
            let mut filter = Filter::new(&ctx.cfg.excludes(&[], false), &ctx.cfg.allowlist)?;
            filter.suppress(kubera::baseline::Baseline::resolve(None)?.fingerprints());
            let token = match git_token_env {
                Some(var) => Some(std::env::var(&var).with_context(|| {
                    format!("environment variable `{var}` (from --git-token-env) is not set")
                })?),
                None => None,
            };
            let server = kubera::mcp::Server::new(
                engine,
                filter,
                ctx.templates,
                ctx.http,
                kubera::mcp::Options {
                    allow_verify,
                    root,
                    git_auth: kubera::sources::remote::Auth {
                        token,
                        user: git_token_user,
                        allow_http: cli.global.allow_http,
                        interactive: false,
                    },
                    max_file_size: ctx
                        .cfg
                        .max_file_size
                        .unwrap_or(sources::fs::DEFAULT_MAX_FILE_SIZE),
                    allow_http: cli.global.allow_http,
                },
            );
            server.serve().await?;
            Ok(0)
        }
    }
}

async fn cmd_scan(g: &GlobalArgs, source: ScanSource) -> Result<u8> {
    let ctx = context(g)?;
    let opts = match &source {
        ScanSource::Fs { opts, .. }
        | ScanSource::Git { opts, .. }
        | ScanSource::Repos { opts, .. }
        | ScanSource::Image { opts, .. }
        | ScanSource::Staged { opts, .. }
        | ScanSource::Github { opts, .. }
        | ScanSource::Gitlab { opts, .. }
        | ScanSource::Bitbucket { opts, .. }
        | ScanSource::Slack { opts, .. }
        | ScanSource::Jira { opts, .. }
        | ScanSource::Bucket { opts, .. }
        | ScanSource::K8s { opts, .. }
        | ScanSource::Stdin { opts } => opts,
    };
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let mut engine = engine;
    engine.decode = !opts.no_decode;
    let excludes = ctx
        .cfg
        .excludes(&opts.exclude_paths, opts.no_default_excludes);
    let mut filter = Filter::new(&excludes, &ctx.cfg.allowlist)?;
    let mut baseline = if opts.no_baseline {
        None
    } else {
        Some(kubera::baseline::Baseline::resolve(
            opts.baseline.as_deref(),
        )?)
    };
    if let Some(b) = &baseline {
        filter.suppress(b.fingerprints());
    }
    let max_size = opts
        .max_file_size
        .or(ctx.cfg.max_file_size)
        .unwrap_or(sources::fs::DEFAULT_MAX_FILE_SIZE);
    let notify_secret = match &opts.notify_secret_env {
        Some(var) => Some(std::env::var(var).with_context(|| {
            format!("environment variable `{var}` (from --notify-secret-env) is not set")
        })?),
        None => None,
    };
    let notify_targets = opts
        .notify_env
        .iter()
        .map(|v| kubera::notify::Target::from_env(v, notify_secret.clone(), g.allow_http))
        .collect::<Result<Vec<_>>>()?;
    let notify_on = opts
        .notify_on
        .unwrap_or(if opts.verify || opts.only_verified {
            NotifyOn::Live
        } else {
            NotifyOn::All
        });
    if notify_on == NotifyOn::Live
        && !notify_targets.is_empty()
        && !(opts.verify || opts.only_verified)
    {
        bail!("--notify-on live needs --verify (otherwise nothing is known to be live)");
    }
    let target = match &source {
        ScanSource::Fs { paths, .. } => scan::Target::Paths(paths.clone()),
        ScanSource::Git {
            repo,
            branch,
            since_commit,
            max_depth,
            token_env,
            token_user,
            state,
            checkpoint,
            ..
        } => {
            let token = match token_env {
                Some(var) => Some(std::env::var(var).with_context(|| {
                    format!("environment variable `{var}` (from --token-env) is not set")
                })?),
                None => None,
            };
            if let Some(cp) = checkpoint {
                let cp = cp.display().to_string();
                // First Ctrl-C: stop after the current commit and save the
                // checkpoint; a second one exits at once.
                tokio::spawn(async move {
                    let mut first = true;
                    while tokio::signal::ctrl_c().await.is_ok() {
                        if !first {
                            std::process::exit(130);
                        }
                        first = false;
                        eprintln!(
                            "\ninterrupted: saving progress to {cp} (Ctrl-C again to quit now)"
                        );
                        kubera::checkpoint::request_stop();
                    }
                });
            }
            scan::Target::Git {
                repo: repo.clone(),
                options: git::GitOptions {
                    branch: branch.clone(),
                    since_commit: since_commit.clone(),
                    max_depth: *max_depth,
                    jobs: opts.jobs,
                    checkpoint: checkpoint.clone(),
                    ..Default::default()
                },
                baseline: match state {
                    Some(p) => kubera::state::State::load(p)?
                        .get(&kubera::state::repo_key(repo))
                        .map(|r| r.refs.clone()),
                    None => None,
                },
                mirror: None,
                auth: kubera::sources::remote::Auth {
                    token,
                    user: token_user.clone(),
                    allow_http: g.allow_http,
                    interactive: std::io::stdin().is_terminal(),
                },
            }
        }
        ScanSource::Stdin { .. } => {
            let mut text = String::new();
            std::io::stdin()
                .take(max_size)
                .read_to_string(&mut text)
                .context("reading stdin")?;
            scan::Target::Text(text)
        }
        ScanSource::Repos { .. } => scan::Target::Text(String::new()),
        ScanSource::Staged { repo, .. } => scan::Target::Staged(repo.clone()),
        ScanSource::Github { .. } | ScanSource::Bucket { .. } | ScanSource::K8s { .. } => {
            scan::Target::Text(String::new())
        }
        // API sources, scanned by `cmd_scan_api`.
        ScanSource::Gitlab { .. }
        | ScanSource::Bitbucket { .. }
        | ScanSource::Slack { .. }
        | ScanSource::Jira { .. } => scan::Target::Text(String::new()),
        ScanSource::Image {
            image,
            platform,
            docker,
            registry_user,
            registry_token_env,
            max_layer_size,
            plain_http,
            ..
        } => {
            use kubera::sources::image;
            let img = if std::path::Path::new(image).is_file() {
                image::open_archive(std::path::Path::new(image), platform)?
            } else if *docker {
                image::from_docker(image, platform)?
            } else {
                let token = match registry_token_env {
                    Some(var) => Some(std::env::var(var).with_context(|| {
                        format!(
                            "environment variable `{var}` (from --registry-token-env) is not set"
                        )
                    })?),
                    None => None,
                };
                if show_progress_early(opts) {
                    eprintln!("{} pulling {image} ({platform})", ctx.style.dim("›"));
                }
                image::pull(
                    image,
                    &image::PullOptions {
                        platform: platform.clone(),
                        user: registry_user.clone(),
                        token,
                        allow_http: g.allow_http || *plain_http,
                        max_layer_size: *max_layer_size,
                    },
                )
                .await?
            };
            scan::Target::Image(std::sync::Arc::new(img))
        }
    };
    let show_progress = std::io::stderr().is_terminal() && opts.format == Format::Pretty;
    let quiet = matches!(source, ScanSource::Staged { .. });
    if show_progress && !opts.interactive && !quiet {
        kubera::brand::print_banner_stderr();
    }
    let progress = |p: scan::Progress| {
        if !show_progress {
            return;
        }
        if let scan::Progress::Cloning(url) = p {
            eprintln!("{} cloning {url}", ctx.style.dim("›"));
        }
    };
    let mut mass_results: Option<Vec<kubera::mass::RepoResult>> = None;
    let (commits_scanned, tips, mut findings) = if let ScanSource::K8s {
        kubeconfig,
        context,
        in_cluster,
        namespaces,
        what,
        ..
    } = &source
    {
        use kubera::sources::kube;
        let cluster = if *in_cluster {
            kube::Cluster::in_cluster()?
        } else {
            let path = kubeconfig
                .clone()
                .or_else(kube::default_kubeconfig)
                .context("no kubeconfig found; pass --kubeconfig")?;
            kube::Cluster::from_kubeconfig(&path, context.as_deref(), g.allow_http)?
        };
        if show_progress {
            eprintln!(
                "{} cluster {} ({})",
                ctx.style.dim("›"),
                cluster.name,
                cluster.server
            );
        }
        let what = if what.is_empty() {
            kube::ALL.to_vec()
        } else {
            what.clone()
        };
        let (chunks, warnings) = kube::collect(&cluster, &what, namespaces).await?;
        for w in warnings {
            eprintln!("warning: {w}");
        }
        (
            0,
            Default::default(),
            scan::scan_chunks(&engine, &filter, &chunks),
        )
    } else if let ScanSource::Bucket {
        url,
        region,
        endpoint_url,
        anonymous,
        token_env,
        max_objects,
        downloads,
        ..
    } = &source
    {
        use kubera::sources::bucket;
        let b = bucket::parse(url)?;
        let gcs_token = match token_env {
            Some(var) => Some(std::env::var(var).with_context(|| {
                format!("environment variable `{var}` (from --token-env) is not set")
            })?),
            None => None,
        };
        let aws = if *anonymous {
            None
        } else {
            bucket::AwsCreds::from_env()
        };
        if b.store == bucket::Store::S3 && aws.is_none() && !anonymous {
            bail!(
                "no AWS credentials in the environment; set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, or pass --anonymous for a public bucket"
            );
        }
        let o = bucket::Options {
            aws,
            gcs_token,
            region: region.clone(),
            endpoint: endpoint_url.clone(),
            max_objects: *max_objects,
            max_file_size: max_size,
            concurrency: *downloads,
            allow_http: g.allow_http,
        };
        let collector = scan::Collector::default();
        let n = bucket::scan(&b, &o, &filter, &mut |c| {
            collector.push(scan::scan_chunk(&engine, &filter, &c))
        })
        .await?;
        if show_progress {
            eprintln!("{} {n} object(s) scanned", ctx.style.dim("›"));
        }
        (0, Default::default(), collector.into_findings())
    } else if let ScanSource::Github { .. } = &source {
        let findings = cmd_scan_github(
            g,
            &source,
            &engine,
            &filter,
            max_size,
            show_progress,
            &ctx.style,
        )
        .await?;
        (0, Default::default(), findings)
    } else if let Some(findings) = cmd_scan_api(
        g,
        &source,
        &engine,
        &filter,
        max_size,
        show_progress,
        &ctx.style,
    )
    .await?
    {
        (0, Default::default(), findings)
    } else if let ScanSource::Repos { .. } = &source {
        let results = cmd_scan_repos(g, &source, &engine, &filter, max_size, &ctx.style).await?;
        let commits = results.iter().map(|r| r.commits_scanned).sum();
        let findings = results.iter().flat_map(|r| r.findings.clone()).collect();
        mass_results = Some(results);
        (commits, Default::default(), findings)
    } else {
        let outcome = scan::run_detailed(&engine, &filter, &target, max_size, &progress)?;
        (outcome.commits_scanned, outcome.tips, outcome.findings)
    };
    let do_verify = opts.verify || opts.only_verified;
    if do_verify && !findings.is_empty() {
        let map: HashMap<String, Arc<Template>> = engine
            .detectors
            .iter()
            .map(|d| (d.template.id.clone(), d.template.clone()))
            .collect();
        verify::verify_findings(&ctx.http, &map, &mut findings, opts.concurrency).await;
    }

    let mut kinds = opts.results.clone();
    if opts.only_verified {
        kinds = vec![ResultKind::Verified];
    }
    if !kinds.is_empty() {
        findings.retain(|f| {
            let k = match f.status() {
                Some(Status::Verified) => ResultKind::Verified,
                Some(Status::Invalid) => ResultKind::Invalid,
                Some(Status::Unknown) => ResultKind::Unknown,
                Some(Status::Unsupported) => ResultKind::Unverifiable,
                None => ResultKind::Unverified,
            };
            kinds.contains(&k)
        });
    }
    if opts.update_baseline {
        let b = baseline.as_mut().expect("baseline enabled");
        let added = findings
            .iter()
            .filter(|f| b.add(f, kubera::baseline::Decision::Baseline, None))
            .count();
        b.save()?;
        eprintln!(
            "{} recorded {added} new finding(s) in {} ({} total); later scans report only new ones",
            ctx.style.green("✓"),
            b.path.display(),
            b.entries.len()
        );
        return Ok(0);
    }
    let label = match &source {
        ScanSource::Fs { paths, .. } => paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ScanSource::Git { repo, .. } => kubera::sources::remote::parse(repo)
            .ok()
            .flatten()
            .map(|r| r.display().to_string())
            .unwrap_or_else(|| repo.clone()),
        ScanSource::Stdin { .. } => "stdin".into(),
        ScanSource::Staged { repo, .. } => format!("staged changes in {}", repo.display()),
        ScanSource::Github {
            repos, org, user, ..
        } => repos
            .iter()
            .chain(org)
            .chain(user)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        ScanSource::Gitlab {
            projects, group, ..
        } => projects
            .iter()
            .chain(group)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        ScanSource::Bitbucket {
            repos, workspace, ..
        } => repos
            .iter()
            .chain(workspace)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        ScanSource::Slack { channel, .. } if !channel.is_empty() => format!(
            "Slack {}",
            channel
                .iter()
                .map(|c| format!("#{}", c.trim_start_matches('#')))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScanSource::Slack { .. } => "Slack".into(),
        ScanSource::Jira { site, .. } => format!("Jira {site}"),
        ScanSource::Image { image, .. } => image.clone(),
        ScanSource::Bucket { url, .. } => url.clone(),
        ScanSource::K8s { context, .. } => {
            format!(
                "Kubernetes {}",
                context.as_deref().unwrap_or("current context")
            )
        }
        ScanSource::Repos { .. } => format!(
            "{} repositories",
            mass_results.as_ref().map(|r| r.len()).unwrap_or(0)
        ),
    };
    let mut notify_failed = false;
    if let Some(path) = ctx.cfg.db_path(opts.db.as_deref(), opts.no_db)? {
        let (target, kind, incremental) = db_target(&source, &label);
        let rec = kubera::db::ScanRecord::new(
            &target,
            kind,
            // Filtered results (--only-verified, --results) are partial too.
            incremental || !kinds.is_empty(),
            do_verify,
            &findings,
            baseline.as_ref(),
        );
        match kubera::db::append(&path, &rec) {
            Ok(()) => {
                if show_progress {
                    eprintln!("{} recorded in {}", ctx.style.dim("›"), path.display());
                }
            }
            Err(e) => {
                // A scheduled scan whose record was lost must not look clean.
                notify_failed = true;
                eprintln!("warning: findings database: {e:#}");
            }
        }
    }
    if !notify_targets.is_empty() {
        let alert: Vec<Finding> = findings
            .iter()
            .filter(|f| notify_on == NotifyOn::All || f.status() == Some(Status::Verified))
            .cloned()
            .collect();
        if !alert.is_empty() {
            for t in &notify_targets {
                match kubera::notify::send(&ctx.http, t, &alert, &label).await {
                    Ok(()) => eprintln!(
                        "{} alert sent to {} ({} finding(s))",
                        ctx.style.dim("›"),
                        t.display(),
                        alert.len()
                    ),
                    Err(e) => {
                        notify_failed = true;
                        eprintln!("warning: alert to {} failed: {e:#}", t.display());
                    }
                }
            }
        }
    }
    if opts.interactive {
        if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
            bail!("--interactive needs a terminal");
        }
        let svc = services(ctx, engine, filter, max_size);
        tokio::task::block_in_place(|| {
            kubera::tui::run(svc, kubera::tui::Start::Results(findings, label))
        })?;
        return Ok(0);
    }
    let shown: Vec<Finding> = if opts.show_secrets {
        findings
    } else {
        findings.iter().map(Finding::redact).collect()
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    report::write_findings(&mut out, &shown, opts.format, &ctx.style)?;
    out.flush()?;
    let err_style = Style {
        color: ctx.style.color && std::io::stderr().is_terminal(),
    };
    eprintln!("{}", report::summary(&shown, &err_style));
    if let ScanSource::Git {
        repo,
        state: Some(path),
        state_policy,
        ..
    } = &source
    {
        let key = kubera::state::repo_key(repo);
        let passed = shown.is_empty();
        let mut st = kubera::state::State::load(path)?;
        if passed || *state_policy == kubera::state::Policy::Always {
            st.set(
                &key,
                kubera::state::RepoState {
                    refs: tips,
                    scanned_at: kubera::state::now(),
                    commits_scanned,
                },
            );
            st.save()?;
            eprintln!(
                "{} {commits_scanned} new commit(s) scanned; baseline advanced",
                err_style.dim("state:")
            );
        } else {
            eprintln!(
                "{} {commits_scanned} new commit(s) scanned; baseline kept (findings must be fixed or allowlisted)",
                err_style.dim("state:")
            );
        }
    }
    if let (
        ScanSource::Repos {
            state: Some(path),
            state_policy,
            ..
        },
        Some(results),
    ) = (&source, &mass_results)
    {
        // A repository passes when none of its findings survived filtering.
        let remaining: std::collections::HashSet<&str> =
            shown.iter().map(|f| f.fingerprint.as_str()).collect();
        let mut st = kubera::state::State::load(path)?;
        let (mut advanced, mut kept) = (0, 0);
        for r in results.iter().filter(|r| r.error.is_none()) {
            let passed = !r
                .findings
                .iter()
                .any(|f| remaining.contains(f.fingerprint.as_str()));
            if passed || *state_policy == kubera::state::Policy::Always {
                st.set(
                    &r.key,
                    kubera::state::RepoState {
                        refs: r.tips.clone(),
                        scanned_at: kubera::state::now(),
                        commits_scanned: r.commits_scanned,
                    },
                );
                advanced += 1;
            } else {
                kept += 1;
            }
        }
        st.save()?;
        eprintln!(
            "{} {advanced} baseline(s) advanced, {kept} kept (unresolved findings), {commits_scanned} commit(s) scanned",
            err_style.dim("state:")
        );
    }
    let failed_repos = mass_results
        .as_ref()
        .map(|r| r.iter().filter(|r| r.error.is_some()).count())
        .unwrap_or(0);
    if failed_repos > 0 {
        eprintln!(
            "{} {failed_repos} repository scan(s) failed (see above)",
            err_style.red("error:")
        );
    }
    Ok(if opts.fail && !shown.is_empty() {
        EXIT_FINDINGS
    } else if notify_failed {
        // A scheduled scan whose alert was lost must not look clean.
        1
    } else {
        0
    })
}

/// Database identity of a scan: a stable target key, the kind, and whether
/// it read only part of the target.
fn db_target(source: &ScanSource, label: &str) -> (String, &'static str, bool) {
    match source {
        ScanSource::Fs { paths, .. } => (
            paths
                .iter()
                .map(|p| {
                    std::fs::canonicalize(p)
                        .unwrap_or_else(|_| p.clone())
                        .display()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(", "),
            "fs",
            false,
        ),
        ScanSource::Git {
            repo,
            branch,
            since_commit,
            max_depth,
            state,
            ..
        } => (
            kubera::state::repo_key(repo),
            "git",
            state.is_some() || since_commit.is_some() || max_depth.is_some() || branch.is_some(),
        ),
        ScanSource::Repos {
            repos,
            github_org,
            github_user,
            gitlab_group,
            bitbucket_workspace,
            repo_list,
            state,
            limit,
            ..
        } => {
            let mut parts: Vec<String> = Vec::new();
            parts.extend(github_org.iter().map(|o| format!("github-org:{o}")));
            parts.extend(github_user.iter().map(|o| format!("github-user:{o}")));
            parts.extend(gitlab_group.iter().map(|o| format!("gitlab-group:{o}")));
            parts.extend(bitbucket_workspace.iter().map(|o| format!("bitbucket:{o}")));
            parts.extend(repo_list.iter().map(|p| format!("list:{}", p.display())));
            parts.extend(repos.iter().cloned());
            (
                format!("repos {}", parts.join(", ")),
                "repos",
                state.is_some() || limit.is_some(),
            )
        }
        ScanSource::Image { .. } => (label.to_string(), "image", false),
        ScanSource::Stdin { .. } => ("stdin".into(), "stdin", true),
        ScanSource::Staged { .. } => (label.to_string(), "staged", true),
        ScanSource::Github { what, .. } => (format!("github {label}"), "github", !what.is_empty()),
        ScanSource::Bucket { url, .. } => (url.clone(), "bucket", false),
        ScanSource::K8s {
            namespaces, what, ..
        } => (
            label.to_string(),
            "k8s",
            !namespaces.is_empty() || !what.is_empty(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan_github(
    g: &GlobalArgs,
    source: &ScanSource,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    show_progress: bool,
    style: &Style,
) -> Result<Vec<Finding>> {
    use kubera::sources::github;
    let ScanSource::Github {
        repos,
        org,
        user,
        what,
        token_env,
        api_url,
        max_items,
        max_runs,
        max_rate_wait,
        opts,
    } = source
    else {
        unreachable!()
    };
    let token = match token_env {
        Some(var) => Some(std::env::var(var).with_context(|| {
            format!("environment variable `{var}` (from --token-env) is not set")
        })?),
        None => None,
    };
    let mut client = kubera::forge::Client::new(
        token.clone(),
        None,
        std::time::Duration::from_secs(*max_rate_wait),
    )?;
    client.allow_http = g.allow_http;
    let api = api_url.trim_end_matches('/');
    let custom_api = (api != "https://api.github.com").then_some(api);
    let mut all_repos = repos.clone();
    for o in org {
        let list = client
            .list(&kubera::forge::Source::GitHubOrg(o.clone()), custom_api)
            .await?;
        all_repos.extend(list.into_iter().map(|r| r.full_name));
    }
    for u in user {
        let list = client
            .list(&kubera::forge::Source::GitHubUser(u.clone()), custom_api)
            .await?;
        all_repos.extend(list.into_iter().map(|r| r.full_name));
    }
    all_repos.sort();
    all_repos.dedup();
    if all_repos.is_empty() && user.is_empty() {
        bail!("nothing to scan: pass owner/name repositories, --org or --user");
    }
    let what = if what.is_empty() {
        github::ALL.to_vec()
    } else {
        what.clone()
    };
    let o = github::Options {
        api: api.to_string(),
        repos: all_repos,
        gist_users: user.clone(),
        what,
        max_items: *max_items,
        max_runs: *max_runs,
        max_log_size: 256 * 1024 * 1024,
        max_file_size: max_size,
    };
    let progress = |m: String| {
        if show_progress {
            eprintln!("{} {m}", style.dim("›"));
        }
    };
    let collected = github::collect(&client, &o, &progress).await?;
    for w in &collected.warnings {
        eprintln!("warning: {w}");
    }
    let mut findings = scan::scan_chunks(engine, filter, &collected.chunks);
    let auth = kubera::sources::remote::Auth {
        token: token.clone(),
        user: None,
        allow_http: g.allow_http,
        interactive: false,
    };
    findings.extend(scan_git_repos(
        &collected.git,
        &auth,
        engine,
        filter,
        max_size,
        opts.jobs,
        &progress,
    ));
    Ok(findings)
}

/// Scan the git repositories an API source returned (wikis, snippets,
/// gists, model repositories) with the history scanner.
fn scan_git_repos(
    repos: &[(String, String)],
    auth: &kubera::sources::remote::Auth,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    jobs: usize,
    progress: &dyn Fn(String),
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (url, label) in repos {
        progress(format!("{label}: history"));
        let target = scan::Target::Git {
            repo: url.clone(),
            options: git::GitOptions {
                jobs,
                ..Default::default()
            },
            auth: auth.clone(),
            baseline: None,
            mirror: None,
        };
        match scan::run_detailed(engine, filter, &target, max_size, &|_| {}) {
            Ok(out) => findings.extend(out.findings),
            // Repositories without a wiki have no wiki repository.
            Err(_) if label.ends_with("(wiki)") => {
                progress(format!("{label}: skipped (no wiki, or no access)"));
            }
            Err(e) => eprintln!("warning: {label}: {e:#}"),
        }
    }
    findings
}

/// The value of the environment variable named by a `--*-env` flag.
fn env_secret(var: Option<&String>, flag: &str) -> Result<Option<String>> {
    match var {
        Some(var) => Ok(Some(std::env::var(var).with_context(|| {
            format!("environment variable `{var}` (from {flag}) is not set")
        })?)),
        None => Ok(None),
    }
}

/// API sources added after `scan github`: `None` when `source` is not one.
async fn cmd_scan_api(
    g: &GlobalArgs,
    source: &ScanSource,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    show_progress: bool,
    style: &Style,
) -> Result<Option<Vec<Finding>>> {
    let progress = |m: String| {
        if show_progress {
            eprintln!("{} {m}", style.dim("›"));
        }
    };
    let findings = match source {
        ScanSource::Gitlab { .. } => {
            cmd_scan_gitlab(g, source, engine, filter, max_size, &progress).await?
        }
        ScanSource::Bitbucket { .. } => {
            cmd_scan_bitbucket(g, source, engine, filter, max_size, &progress).await?
        }
        ScanSource::Slack {
            channel,
            since,
            token_env,
            api_url,
            include_dms,
            include_archived,
            max_messages,
            max_rate_wait,
            ..
        } => {
            use kubera::sources::slack;
            let token = env_secret(Some(token_env), "--token-env")?;
            let mut client = kubera::forge::Client::new(
                token,
                None,
                std::time::Duration::from_secs(*max_rate_wait),
            )?;
            client.allow_http = g.allow_http;
            let o = slack::Options {
                api: api_url.clone(),
                channels: channel.clone(),
                oldest: since.as_deref().map(slack::parse_since).transpose()?,
                include_dms: *include_dms,
                include_archived: *include_archived,
                max_messages: *max_messages,
            };
            let collected = slack::collect(&client, &o, &progress).await?;
            for w in &collected.warnings {
                eprintln!("warning: {w}");
            }
            scan::scan_chunks(engine, filter, &collected.chunks)
        }
        ScanSource::Jira {
            site,
            jql,
            project,
            email_env,
            token_env,
            max_issues,
            no_history,
            max_rate_wait,
            ..
        } => {
            use kubera::sources::jira;
            let site = jira::site_base(site, g.allow_http)?;
            let email = env_secret(email_env.as_ref(), "--email-env")?;
            let token = env_secret(token_env.as_ref(), "--token-env")?;
            if email.is_some() && token.is_none() {
                bail!("--email-env needs --token-env (the API token)");
            }
            let mut client = kubera::forge::Client::new(
                token,
                email,
                std::time::Duration::from_secs(*max_rate_wait),
            )?;
            client.allow_http = g.allow_http;
            let jql = match (jql, project.is_empty()) {
                (Some(q), _) => q.clone(),
                (None, true) => jira::DEFAULT_JQL.to_string(),
                (None, false) => format!(
                    "project in ({}) ORDER BY created DESC",
                    project
                        .iter()
                        .map(|p| format!("\"{}\"", p.replace(['"', '\\'], "")))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let o = jira::Options {
                site,
                jql,
                max_issues: *max_issues,
                history: !no_history,
            };
            let collected = jira::collect(&client, &o, &progress).await?;
            for w in &collected.warnings {
                eprintln!("warning: {w}");
            }
            scan::scan_chunks(engine, filter, &collected.chunks)
        }
        _ => return Ok(None),
    };
    Ok(Some(findings))
}

async fn cmd_scan_bitbucket(
    g: &GlobalArgs,
    source: &ScanSource,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    progress: &dyn Fn(String),
) -> Result<Vec<Finding>> {
    use kubera::sources::bitbucket;
    let ScanSource::Bitbucket {
        repos,
        workspace,
        what,
        token_env,
        token_user,
        api_url,
        max_items,
        max_runs,
        max_rate_wait,
        opts,
    } = source
    else {
        unreachable!()
    };
    let token = env_secret(token_env.as_ref(), "--token-env")?;
    let mut client = kubera::forge::Client::new(
        token.clone(),
        token_user.clone(),
        std::time::Duration::from_secs(*max_rate_wait),
    )?;
    client.allow_http = g.allow_http;
    let api = api_url.trim_end_matches('/');
    let mut all = repos.clone();
    for ws in workspace {
        progress(format!("workspace {ws}: listing repositories"));
        let list = client
            .list(
                &kubera::forge::Source::BitbucketWorkspace(ws.clone()),
                Some(api),
            )
            .await?;
        all.extend(list.into_iter().map(|r| r.full_name));
    }
    all.sort();
    all.dedup();
    if all.is_empty() {
        bail!("nothing to scan: pass workspace/repo repositories or --workspace");
    }
    // Snippets belong to workspaces: those named, and those of the repos.
    let mut snippet_workspaces: Vec<String> = workspace.clone();
    snippet_workspaces.extend(
        all.iter()
            .filter_map(|r| r.split_once('/').map(|(w, _)| w.to_string())),
    );
    snippet_workspaces.sort();
    snippet_workspaces.dedup();
    let o = bitbucket::Options {
        api: api.to_string(),
        repos: all,
        snippet_workspaces,
        what: if what.is_empty() {
            bitbucket::ALL.to_vec()
        } else {
            what.clone()
        },
        max_items: *max_items,
        max_runs: *max_runs,
        max_log_size: 256 * 1024 * 1024,
        max_file_size: max_size,
    };
    let collected = bitbucket::collect(&client, &o, progress).await?;
    for w in &collected.warnings {
        eprintln!("warning: {w}");
    }
    let mut findings = scan::scan_chunks(engine, filter, &collected.chunks);
    let auth = kubera::sources::remote::Auth {
        token,
        // Access tokens clone as `x-token-auth`; app passwords and API
        // tokens with their user.
        user: Some(token_user.clone().unwrap_or_else(|| "x-token-auth".into())),
        allow_http: g.allow_http,
        interactive: false,
    };
    findings.extend(scan_git_repos(
        &collected.git,
        &auth,
        engine,
        filter,
        max_size,
        opts.jobs,
        progress,
    ));
    Ok(findings)
}

async fn cmd_scan_gitlab(
    g: &GlobalArgs,
    source: &ScanSource,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    progress: &dyn Fn(String),
) -> Result<Vec<Finding>> {
    use kubera::sources::gitlab;
    let ScanSource::Gitlab {
        projects,
        group,
        what,
        token_env,
        api_url,
        max_items,
        max_jobs,
        max_rate_wait,
        opts,
    } = source
    else {
        unreachable!()
    };
    let token = env_secret(token_env.as_ref(), "--token-env")?;
    let mut client = kubera::forge::Client::new(
        token.clone(),
        None,
        std::time::Duration::from_secs(*max_rate_wait),
    )?;
    client.allow_http = g.allow_http;
    let api = api_url.trim_end_matches('/');
    let mut all = projects.clone();
    for grp in group {
        progress(format!("group {grp}: listing projects"));
        let list = client
            .list(&kubera::forge::Source::GitLabGroup(grp.clone()), Some(api))
            .await?;
        all.extend(list.into_iter().map(|r| r.full_name));
    }
    all.sort();
    all.dedup();
    if all.is_empty() {
        bail!("nothing to scan: pass group/project paths or --group");
    }
    let o = gitlab::Options {
        api: api.to_string(),
        projects: all,
        what: if what.is_empty() {
            gitlab::ALL.to_vec()
        } else {
            what.clone()
        },
        max_items: *max_items,
        max_jobs: *max_jobs,
        max_log_size: 256 * 1024 * 1024,
        max_file_size: max_size,
    };
    let collected = gitlab::collect(&client, &o, progress).await?;
    for w in &collected.warnings {
        eprintln!("warning: {w}");
    }
    let mut findings = scan::scan_chunks(engine, filter, &collected.chunks);
    let auth = kubera::sources::remote::Auth {
        token,
        // GitLab takes any user name with a token; `oauth2` works for
        // personal, project and OAuth tokens alike.
        user: Some("oauth2".into()),
        allow_http: g.allow_http,
        interactive: false,
    };
    findings.extend(scan_git_repos(
        &collected.git,
        &auth,
        engine,
        filter,
        max_size,
        opts.jobs,
        progress,
    ));
    Ok(findings)
}

/// Collect the secret parts for `t` from flags, env and stdin.
fn read_secret(t: &Template, a: &SecretArgs) -> Result<BTreeMap<String, String>> {
    let names: Vec<String> = t.detect.patterns.iter().map(|p| p.name.clone()).collect();
    let single = names.len() == 1;
    let mut parts: BTreeMap<String, String> = BTreeMap::new();

    let mut assign = |raw: &str, from_env: bool| -> Result<()> {
        let (name, val) = match raw.split_once('=') {
            Some((n, v)) if names.iter().any(|x| x == n) => (n.to_string(), v.to_string()),
            _ if single => (names[0].clone(), raw.to_string()),
            _ => bail!("expected NAME=VALUE with NAME one of: {}", names.join(", ")),
        };
        let val = if from_env {
            std::env::var(&val).with_context(|| format!("environment variable `{val}` not set"))?
        } else {
            val
        };
        parts.insert(name, val);
        Ok(())
    };

    if !a.secret.is_empty() {
        eprintln!(
            "warning: secrets passed with --secret can leak via shell history and process \
             listings; prefer --secret-env or --secret-stdin"
        );
    }
    for s in &a.secret {
        assign(s, false)?;
    }
    for s in &a.secret_env {
        assign(s, true)?;
    }
    if a.secret_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .take(1024 * 1024)
            .read_to_string(&mut buf)
            .context("reading secret from stdin")?;
        if single {
            parts.insert(names[0].clone(), buf.trim().to_string());
        } else {
            for line in buf.lines().map(str::trim).filter(|l| !l.is_empty()) {
                assign(line, false)?;
            }
        }
    }
    let nothing_given = a.secret.is_empty() && a.secret_env.is_empty() && !a.secret_stdin;
    if nothing_given && std::io::stdin().is_terminal() {
        for p in &t.detect.patterns {
            let label = format!("{} - {}: ", t.name, p.name.replace('_', " "));
            let v = if p.secret {
                rpassword::prompt_password(format!("{label}(hidden) "))?
            } else {
                prompt_line(&label)?
            };
            parts.insert(p.name.clone(), v.trim().to_string());
        }
    }
    for n in &names {
        match parts.get(n) {
            Some(v) if !v.is_empty() => {}
            _ => bail!(
                "missing secret part `{n}` for {} (parts: {})",
                t.id,
                names.join(", ")
            ),
        }
    }
    // Derive extra named captures (e.g. a key id embedded in the key).
    for p in &t.detect.patterns {
        if p.captures.is_empty() {
            continue;
        }
        let re = regex::Regex::new(&p.regex)?;
        let value = parts[&p.name].clone();
        match re.captures(&value) {
            Some(c) => {
                for name in &p.captures {
                    if let Some(m) = c.name(name) {
                        parts.insert(name.clone(), m.as_str().to_string());
                    }
                }
            }
            None => eprintln!(
                "warning: `{}` does not look like a {} {}; derived values may be missing",
                p.name, t.name, p.name
            ),
        }
    }
    Ok(parts)
}

/// Resolve the repositories to scan and run the mass scan.
async fn cmd_scan_repos(
    g: &GlobalArgs,
    source: &ScanSource,
    engine: &Engine,
    filter: &Filter,
    max_size: u64,
    style: &Style,
) -> Result<Vec<kubera::mass::RepoResult>> {
    use kubera::forge::{Client, Source};
    let ScanSource::Repos {
        repos,
        github_org,
        github_user,
        gitlab_group,
        bitbucket_workspace,
        repo_list,
        api_url,
        token_env,
        token_user,
        include_forks,
        include_archived,
        limit,
        repo_concurrency,
        cache_dir,
        state,
        max_rate_wait,
        max_depth,
        opts,
        ..
    } = source
    else {
        unreachable!()
    };
    let token = match token_env {
        Some(var) => Some(std::env::var(var).with_context(|| {
            format!("environment variable `{var}` (from --token-env) is not set")
        })?),
        None => None,
    };
    let mut targets: Vec<String> = repos.clone();
    if let Some(file) = repo_list {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        targets.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    let mut sources: Vec<Source> = Vec::new();
    sources.extend(github_org.iter().cloned().map(Source::GitHubOrg));
    sources.extend(github_user.iter().cloned().map(Source::GitHubUser));
    sources.extend(gitlab_group.iter().cloned().map(Source::GitLabGroup));
    sources.extend(
        bitbucket_workspace
            .iter()
            .cloned()
            .map(Source::BitbucketWorkspace),
    );
    let default_user = match sources.first() {
        Some(Source::GitLabGroup(_)) => "oauth2",
        Some(Source::BitbucketWorkspace(_)) => "x-token-auth",
        _ => "x-access-token",
    };
    if !sources.is_empty() {
        let mut client = Client::new(
            token.clone(),
            token_user.clone(),
            std::time::Duration::from_secs(*max_rate_wait),
        )?;
        client.allow_http = g.allow_http;
        for src in &sources {
            let found = client.list(src, api_url.as_deref()).await?;
            let total = found.len();
            let kept: Vec<_> = found
                .into_iter()
                .filter(|r| *include_forks || !r.fork)
                .filter(|r| *include_archived || !r.archived)
                .collect();
            eprintln!(
                "{} {:?}: {} repositories ({} skipped: forks/archived)",
                style.dim("discover:"),
                src,
                kept.len(),
                total - kept.len()
            );
            targets.extend(kept.into_iter().map(|r| r.clone_url));
        }
    }
    targets.sort();
    targets.dedup();
    if let Some(n) = limit {
        targets.truncate(*n);
    }
    if targets.is_empty() {
        bail!("no repositories to scan");
    }
    let baselines = match state {
        Some(p) => kubera::state::State::load(p)?
            .repos()
            .map(|(k, v)| (k.clone(), v.refs.clone()))
            .collect(),
        None => Default::default(),
    };
    let opts = kubera::mass::Options {
        concurrency: *repo_concurrency,
        cache_dir: cache_dir.clone(),
        git: git::GitOptions {
            max_depth: *max_depth,
            // Repositories already run in parallel: share the CPUs.
            jobs: if opts.jobs > 0 {
                opts.jobs
            } else {
                (git::effective_jobs(0) / (*repo_concurrency).max(1)).max(1)
            },
            ..Default::default()
        },
        auth: kubera::sources::remote::Auth {
            token,
            user: Some(
                token_user
                    .clone()
                    .unwrap_or_else(|| default_user.to_string()),
            ),
            allow_http: g.allow_http,
            interactive: false,
        },
        baselines,
        max_file_size: max_size,
    };
    let total = targets.len();
    let done = std::sync::atomic::AtomicUsize::new(0);
    let on_done = |r: &kubera::mass::RepoResult| {
        let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let status = match &r.error {
            Some(e) => style.red(&format!("error: {e}")),
            None if r.findings.is_empty() => style.green("clean"),
            None => style.yellow(&format!("{} finding(s)", r.findings.len())),
        };
        eprintln!(
            "{} [{n}/{total}] {} - {} new commit(s), {status}",
            style.dim("scan:"),
            r.key,
            r.commits_scanned
        );
    };
    let results = tokio::task::block_in_place(|| {
        kubera::mass::run(engine, filter, &targets, &opts, &on_done)
    });
    Ok(results)
}

fn show_progress_early(opts: &ScanArgs) -> bool {
    std::io::stderr().is_terminal() && opts.format == Format::Pretty
}

fn prompt_line(label: &str) -> Result<String> {
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Detector + secret parts for verify/analyze/rotate. With no detector id,
/// the secret is read (flag, env, stdin or hidden prompt) and identified by
/// running the detection engine over it.
fn resolve_secret<'a>(
    ctx: &'a Ctx,
    detector: Option<&str>,
    a: &SecretArgs,
) -> Result<(&'a Template, BTreeMap<String, String>)> {
    if let Some(id) = detector {
        let t = template::find(&ctx.templates, id)?;
        return Ok((t, read_secret(t, a)?));
    }
    let mut raw = String::new();
    if let Some(v) = a.secret.first() {
        eprintln!(
            "warning: secrets passed with --secret can leak via shell history and process \
             listings; prefer --secret-env or --secret-stdin"
        );
        raw = v.clone();
    } else if let Some(var) = a.secret_env.first() {
        raw =
            std::env::var(var).with_context(|| format!("environment variable `{var}` not set"))?;
    } else if a.secret_stdin {
        std::io::stdin()
            .take(1024 * 1024)
            .read_to_string(&mut raw)
            .context("reading secret from stdin")?;
    } else if std::io::stdin().is_terminal() {
        raw = rpassword::prompt_password("Paste the secret (hidden): ")?;
    } else {
        bail!("pass a detector id and the secret (see --help)");
    }
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let mut seen = std::collections::BTreeSet::new();
    let candidates: Vec<_> = engine
        .scan(&raw)
        .into_iter()
        .filter(|c| seen.insert(c.detector))
        .collect();
    let chosen = match candidates.len() {
        0 => bail!(
            "could not identify this secret; pass the detector id (see `kubera templates list`)"
        ),
        1 => &candidates[0],
        _ if std::io::stdin().is_terminal() && !a.secret_stdin => {
            eprintln!("This could be one of:");
            for (i, c) in candidates.iter().enumerate() {
                eprintln!(
                    "  {}. {}",
                    i + 1,
                    engine.detectors[c.detector].template.name
                );
            }
            let pick: usize = prompt_line("Choose [1]: ")?.parse().unwrap_or(1);
            candidates
                .get(pick.saturating_sub(1))
                .context("invalid choice")?
        }
        _ => bail!(
            "the secret matches several detectors ({}); pass one explicitly",
            candidates
                .iter()
                .map(|c| engine.detectors[c.detector].template.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let id = engine.detectors[chosen.detector].template.id.clone();
    let t = template::find(&ctx.templates, &id)?;
    eprintln!("identified: {} ({})", t.name, t.id);
    Ok((t, chosen.parts.clone()))
}

fn services(ctx: Ctx, engine: Engine, filter: Filter, max_file_size: u64) -> kubera::tui::Services {
    kubera::tui::Services {
        engine,
        filter,
        templates: ctx.templates,
        http: ctx.http,
        max_file_size,
        runtime: Some(tokio::runtime::Handle::current()),
        baseline: Some(PathBuf::from(kubera::baseline::DEFAULT_FILE)),
    }
}

fn cmd_tui(g: &GlobalArgs, target: Option<String>, git: bool, verify: bool) -> Result<u8> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        bail!("the TUI needs an interactive terminal");
    }
    let ctx = context(g)?;
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let mut filter = Filter::new(&ctx.cfg.excludes(&[], false), &ctx.cfg.allowlist)?;
    filter.suppress(kubera::baseline::Baseline::resolve(None)?.fingerprints());
    let max = ctx
        .cfg
        .max_file_size
        .unwrap_or(sources::fs::DEFAULT_MAX_FILE_SIZE);
    let start = match target {
        None => kubera::tui::Start::Home,
        Some(t) => {
            let is_repo = git
                || (!std::path::Path::new(&t).exists()
                    && kubera::sources::remote::parse(&t)?.is_some());
            let kind = if is_repo {
                kubera::tui::app::InputKind::Repository
            } else {
                kubera::tui::app::InputKind::Folder
            };
            let (target, label) =
                kubera::tui::App::target_from_input(kind, &t).map_err(anyhow::Error::msg)?;
            kubera::tui::Start::Scan(target, label)
        }
    };
    let svc = services(ctx, engine, filter, max);
    tokio::task::block_in_place(|| {
        if verify {
            kubera::tui::run_with(svc, start, true)
        } else {
            kubera::tui::run(svc, start)
        }
    })?;
    Ok(0)
}

fn print_analysis(rep: &analyze::Report, st: &Style) {
    println!(
        "{} {}  {}",
        st.bold(&rep.name),
        st.dim(&format!("({})", rep.detector)),
        st.status(rep.verification.status)
    );
    if let Some(m) = &rep.verification.message {
        println!("  {:<16} {m}", st.dim("message"));
    }
    for (k, v) in &rep.verification.details {
        println!("  {:<16} {}", st.dim(k), report::display_value(v));
    }
    if let Some(n) = &rep.notes {
        println!();
        for l in n.trim().lines() {
            println!("  {}", st.dim(l));
        }
    }
    for s in &rep.steps {
        println!();
        let mark = if s.ok { st.green("✔") } else { st.red("✘") };
        let desc = if s.description.is_empty() {
            String::new()
        } else {
            format!(" - {}", s.description)
        };
        println!("{mark} {}{}", st.bold(&s.name), st.dim(&desc));
        if let Some(e) = &s.error {
            println!("    {:<16} {e}", st.dim("error"));
        }
        for v in &s.values {
            println!(
                "    {:<16} {}",
                st.dim(&v.label),
                report::display_value(&v.value)
            );
        }
    }
}

/// `kubera update`: see `kubera::update` for the security properties.
async fn cmd_update(check: bool, version: Option<&str>, yes: bool) -> Result<u8> {
    use kubera::update::{self, Updater};

    let st = Style {
        color: report::use_color(),
    };
    let current = update::current_version();
    let exe = std::env::current_exe().context("locating the running executable")?;
    // Replace the real file, not a symlink pointing at it.
    let real = exe.canonicalize().unwrap_or_else(|_| exe.clone());
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| PathBuf::from(h).join(".cargo"))
        });
    let manager = update::managed_by(&exe, cargo_home.as_deref())
        .or_else(|| update::managed_by(&real, cargo_home.as_deref()));
    let target = update::platform_target();
    if let Some(tag) = version {
        update::normalize_tag(tag)?;
    }
    // Refuse before any network call when there is nothing we may do.
    if !check {
        if let Some(m) = manager {
            bail!(
                "{} is managed by {}; update it with: {}",
                real.display(),
                m.name(),
                m.upgrade_command()
            );
        }
        if target.is_none() {
            bail!(
                "no prebuilt release exists for {}; update from source: cargo install kubera-cli --locked",
                update::BUILD_TARGET
            );
        }
        update::check_writable(&real)?;
        if !yes && !std::io::stdin().is_terminal() {
            bail!("stdin is not interactive; pass --yes to update");
        }
    }

    let updater = Updater::new(update::Source::default())?;
    let release = updater.release(version).await?;
    let newer = release.version > current;

    if check {
        if release.version == current {
            println!("kubera {current} is up to date");
        } else if newer {
            println!(
                "{} kubera {} is available (running {current}): {}",
                st.yellow("!"),
                release.version,
                format_args!(
                    "https://github.com/{}/releases/tag/{}",
                    update::REPO,
                    release.tag
                )
            );
        } else {
            println!("kubera {current} is newer than release {}", release.version);
        }
        match (manager, target) {
            (Some(m), _) => println!(
                "installed with {}; update with: {}",
                m.name(),
                m.upgrade_command()
            ),
            (None, None) => println!(
                "no prebuilt release exists for {}; update from source: cargo install kubera-cli --locked",
                update::BUILD_TARGET
            ),
            (None, Some(_)) if newer => println!("run `kubera update` to install it"),
            _ => {}
        }
        return Ok(0);
    }
    let target = target.expect("checked above");

    if release.version == current {
        println!("kubera {current} is up to date");
        return Ok(0);
    }
    if !newer && version.is_none() {
        println!(
            "kubera {current} is newer than the latest release ({})",
            release.version
        );
        return Ok(0);
    }

    if !yes {
        eprint!(
            "Replace {} (kubera {current}) with kubera {}{}? [y/N] ",
            real.display(),
            release.version,
            if newer { "" } else { ", a downgrade" }
        );
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted");
            return Ok(1);
        }
    }

    let asset = update::asset_name(target);
    eprintln!("downloading {asset} ({})", release.tag);
    let archive = updater.download(&release, target).await?;
    eprintln!("{} SHA-256 verified", st.green("✓"));
    if std::env::var("KUBERA_VERIFY_ATTESTATION").as_deref() == Ok("1") {
        update::verify_attestation(&archive, &asset)?;
        eprintln!("{} build provenance attestation verified", st.green("✓"));
    }
    let binary = update::extract_binary(&archive, target)?;
    update::replace_exe(&real, &binary, &release.version)?;
    println!(
        "{} updated {} from {current} to {}",
        st.green("✓"),
        real.display(),
        release.version
    );
    Ok(0)
}

struct RotateFlags {
    execute: bool,
    yes: bool,
    force: bool,
    stdin_used: bool,
    output_file: Option<PathBuf>,
    stores: Vec<String>,
    store_config: kubera::store::Config,
    format: OutFormat,
}

async fn cmd_rotate(
    ctx: &Ctx,
    t: &Template,
    parts: &BTreeMap<String, String>,
    inputs: BTreeMap<String, String>,
    f: RotateFlags,
) -> Result<u8> {
    let st = &ctx.style;
    let r = t
        .rotate
        .as_ref()
        .with_context(|| format!("detector `{}` has no rotation support", t.id))?;
    if f.execute && r.steps.is_empty() {
        bail!(
            "`{}` has no automated rotation; follow the manual instructions (run without --execute)",
            t.id
        );
    }
    if let Some(p) = &f.output_file
        && p.exists()
    {
        bail!("{} already exists; refusing to overwrite", p.display());
    }

    // Secret stores are parsed and checked before anything is sent, so a
    // typo never surfaces after the old credential is gone.
    use kubera::store;
    if !f.stores.is_empty() && r.steps.is_empty() {
        bail!(
            "`{}` has no automated rotation, so there is no new credential to --store",
            t.id
        );
    }
    let (outs, default_out) = store::outputs_of(t);
    let specs = f
        .stores
        .iter()
        .map(|s| store::parse(s, &outs, default_out.as_deref()))
        .collect::<Result<Vec<_>>>()?;
    let groups = store::group(&specs)?;
    let problems = f.store_config.problems(&groups);
    if f.execute && !problems.is_empty() {
        bail!(
            "cannot update the secret stores (nothing was rotated):\n  {}",
            problems.join("\n  ")
        );
    }
    for p in &problems {
        eprintln!("warning: {p}");
    }

    let mut opts = rotate::Options {
        execute: false,
        force: f.force,
        inputs,
    };

    if f.execute && !f.yes {
        if f.stdin_used || !std::io::stdin().is_terminal() {
            bail!("stdin is not interactive; pass --yes to confirm the rotation");
        }
        let mut plan = rotate::rotate(&ctx.http, t, parts, &opts).await?;
        plan.stores = store::plan(&f.store_config, &groups);
        print_rotation(&plan, st);
        eprint!(
            "\n{} This will call {}'s API and may revoke the current credential.\n\
             Type the detector id ({}) to continue: ",
            st.yellow("!"),
            if t.platform.is_empty() {
                &t.name
            } else {
                &t.platform
            },
            t.id
        );
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != t.id {
            eprintln!("aborted");
            return Ok(1);
        }
    }

    // Read what the stores need (GitHub public keys) before rotating: a bad
    // token fails here, while the old credential still works.
    let keys = if f.execute && !groups.is_empty() {
        store::preflight(&ctx.http, &f.store_config, &groups)
            .await
            .context("secret store check failed; nothing was rotated")?
    } else {
        Default::default()
    };

    opts.execute = f.execute;
    let mut rep = rotate::rotate(&ctx.http, t, parts, &opts).await?;
    let new_outputs = rep.outputs.clone();
    // Outputs that are safe somewhere and need not be printed.
    let mut secured: std::collections::BTreeSet<String> = Default::default();

    // Persist the new credential before anything else can fail.
    if let Some(path) = &f.output_file
        && !rep.outputs.is_empty()
    {
        write_private(path, &serde_json::to_vec_pretty(&rep.outputs)?)?;
        eprintln!("new credential written to {}", path.display());
        secured.extend(rep.outputs.keys().cloned());
    }

    let mut store_failed = false;
    if !rep.executed {
        rep.stores = store::plan(&f.store_config, &groups);
    } else if !groups.is_empty() {
        if rep.completed && !new_outputs.is_empty() {
            rep.stores = store::write_all(
                &ctx.http,
                &f.store_config,
                &groups,
                &keys,
                &new_outputs,
                parts,
            )
            .await;
            // An output counts as secured only if every store that wanted
            // it got it: a failed store needs the value to be fixed by hand.
            let mut stored = std::collections::BTreeSet::new();
            let mut missing = std::collections::BTreeSet::new();
            for (g, res) in groups.iter().zip(&rep.stores) {
                let outs = g.entries.iter().map(|(_, o)| o.clone());
                if res.ok {
                    stored.extend(outs);
                } else {
                    store_failed = true;
                    missing.extend(outs);
                }
            }
            secured.extend(stored.difference(&missing).cloned());
        } else {
            store_failed = true;
            rep.stores = store::plan(&f.store_config, &groups)
                .into_iter()
                .map(|mut s| {
                    s.error = Some("skipped: the rotation did not complete".into());
                    s
                })
                .collect();
        }
    }
    // A credential that did not reach a store or the output file is
    // printed (once), so it is never lost.
    rep.outputs.retain(|k, _| !secured.contains(k));

    let mut shown = rep.clone();
    shown.steps = shown.steps.iter().map(|s| s.redacted()).collect();
    match f.format {
        OutFormat::Json => println!("{}", serde_json::to_string_pretty(&shown)?),
        OutFormat::Pretty => print_rotation(&shown, st),
    }
    Ok(if rep.executed && !rep.completed {
        2
    } else if store_failed {
        4
    } else {
        0
    })
}

fn print_rotation(rep: &rotate::Report, st: &Style) {
    println!(
        "{} {}  current credential: {}",
        st.bold("rotate"),
        rep.detector,
        st.status(rep.verification.status)
    );
    if let Some(i) = &rep.instructions {
        println!("\n{}", st.bold("Instructions"));
        for l in i.trim().lines() {
            println!("  {l}");
        }
    }
    if !rep.plan.is_empty() {
        println!(
            "\n{} {}",
            st.bold("Planned API calls"),
            st.dim("(dry run - pass --execute to perform)")
        );
        for (i, p) in rep.plan.iter().enumerate() {
            println!(
                "  {}. {} {}",
                i + 1,
                st.bold(&p.name),
                st.dim(&p.description)
            );
            for l in p.request.lines() {
                println!("     {l}");
            }
        }
    }
    if !rep.steps.is_empty() {
        println!("\n{}", st.bold("Executed"));
        for s in &rep.steps {
            let mark = if s.ok { st.green("✔") } else { st.red("✘") };
            let code = s
                .http_status
                .map(|c| format!(" (HTTP {c})"))
                .unwrap_or_default();
            println!("  {mark} {}{}", s.name, st.dim(&code));
            if let Some(e) = &s.error {
                println!("      {e}");
            }
        }
        if rep.completed {
            println!("\n{}", st.green("Rotation completed."));
        } else {
            println!(
                "\n{}",
                st.red("Rotation did NOT complete - review the steps above and finish manually.")
            );
        }
    }
    if !rep.stores.is_empty() {
        if rep.executed {
            println!("\n{}", st.bold("Secret stores"));
        } else {
            println!(
                "\n{} {}",
                st.bold("Secret store updates"),
                st.dim("(after a successful rotation, with --execute)")
            );
        }
        for s in &rep.stores {
            let mark = match (s.executed, s.ok) {
                (false, _) if s.error.is_none() => st.dim("·"),
                (_, true) => st.green("✔"),
                _ => st.red("✘"),
            };
            println!(
                "  {mark} {} {}",
                st.bold(&s.target),
                st.dim(&format!("({})", s.values.join(", ")))
            );
            if !s.executed {
                for l in s.plan.lines() {
                    println!("     {l}");
                }
            }
            if let Some(e) = &s.error {
                println!("      {e}");
            }
        }
        if rep.stores.iter().any(|s| s.executed && !s.ok) {
            println!(
                "\n{}",
                st.red("A secret store was NOT updated - the new credential is below (or in --output-file); store it by hand.")
            );
        }
    }
    if !rep.outputs.is_empty() {
        println!(
            "\n{} {}",
            st.bold("New credential"),
            st.yellow("(shown once - store it in your secret manager now)")
        );
        for (k, v) in &rep.outputs {
            println!("  {k} = {v}");
        }
    }
}

/// Create a new file readable only by the current user.
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn print_issues(rep: &kubera::remediate::IssuesReport, st: &Style) {
    println!(
        "{} {}  {}",
        st.bold("remediate"),
        rep.repository,
        if rep.executed {
            String::new()
        } else {
            st.dim("(dry run - pass --execute to open the issues)")
        }
    );
    for w in &rep.warnings {
        println!("  {} {w}", st.yellow("!"));
    }
    for r in &rep.results {
        let (mark, what) = match r.action.as_str() {
            "opened" => (st.green("✔"), format!("opened #{}", r.issue.unwrap_or(0))),
            "exists" => (
                st.dim("="),
                format!("already open #{}", r.issue.unwrap_or(0)),
            ),
            "failed" => (st.red("✘"), "failed".to_string()),
            _ => (st.dim("·"), "would open".to_string()),
        };
        println!(
            "  {mark} {:<16} {} {}",
            what,
            st.bold(&r.title),
            st.dim(&format!(
                "[{}, {} location(s){}]",
                r.status,
                r.locations,
                r.mention
                    .as_ref()
                    .map(|m| format!(", @{m}"))
                    .unwrap_or_default()
            ))
        );
        if let Some(u) = &r.url {
            println!("      {}", st.dim(u));
        }
        if let Some(e) = &r.error {
            println!("      {}", st.red(e));
        }
    }
    let n = |a: &str| rep.results.iter().filter(|r| r.action == a).count();
    println!(
        "\n{} to open, {} opened, {} already open, {} failed",
        n("would_open"),
        n("opened"),
        n("exists"),
        n("failed")
    );
}

fn cmd_purge(
    g: &GlobalArgs,
    findings: PathBuf,
    repo: PathBuf,
    output: Option<PathBuf>,
    replacement: String,
    format: OutFormat,
) -> Result<u8> {
    use kubera::remediate;
    let ctx = context(g)?;
    let wanted: Vec<Finding> = remediate::load_findings(&findings)?
        .into_iter()
        .filter(|f| remediate::valid_fingerprint(&f.fingerprint))
        .collect();
    if wanted.is_empty() {
        bail!("{} holds no findings", findings.display());
    }
    let top = remediate::toplevel(&repo)?;
    let output = output.unwrap_or_else(|| {
        let name = top
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "repo".into());
        top.parent()
            .unwrap_or(std::path::Path::new("."))
            .join(format!("{name}-kubera-purge.txt"))
    });
    let fps: std::collections::BTreeSet<&str> =
        wanted.iter().map(|f| f.fingerprint.as_str()).collect();
    // Raw values: from a --show-secrets file (checked against the
    // fingerprint), otherwise from a fresh scan of the history.
    let mut found: Vec<Finding> = Vec::new();
    for f in wanted.iter().filter(|f| !f.redacted) {
        if let Ok(t) = template::find(&ctx.templates, &f.detector) {
            let raw = Finding::new(t, f.secret.clone(), f.location.clone());
            if raw.fingerprint == f.fingerprint {
                found.push(raw);
            }
        }
    }
    let missing: Vec<&str> = fps
        .iter()
        .copied()
        .filter(|fp| !found.iter().any(|f| f.fingerprint == *fp))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "{} scanning the history of {} for {} redacted finding(s)",
            ctx.style.dim("›"),
            top.display(),
            missing.len()
        );
        let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
        // No excludes, allowlist or baseline: every copy must be found.
        let filter = Filter::new(&[], &Default::default())?;
        let target = scan::Target::Git {
            repo: top.display().to_string(),
            options: git::GitOptions::default(),
            auth: Default::default(),
            baseline: None,
            mirror: None,
        };
        let out = scan::run_detailed(&engine, &filter, &target, u64::MAX / 2, &|_| {})?;
        found.extend(
            out.findings
                .into_iter()
                .filter(|f| missing.contains(&f.fingerprint.as_str())),
        );
    }
    let rep = remediate::purge(
        &remediate::PurgeOptions {
            repo: top,
            output,
            replacement,
        },
        &wanted,
        &found,
    )?;
    let st = &ctx.style;
    match format {
        OutFormat::Json => println!("{}", serde_json::to_string_pretty(&rep)?),
        OutFormat::Pretty => {
            println!(
                "{} wrote {} expression(s) for {} secret(s) to {} {}",
                st.green("✓"),
                rep.values,
                rep.resolved.len(),
                st.bold(&rep.expressions_file),
                st.dim("(mode 0600: it holds the raw secrets)")
            );
            if !rep.not_found.is_empty() {
                println!(
                    "{} {} finding(s) not found in the history (uncommitted, another repository, or already removed): {}",
                    st.yellow("!"),
                    rep.not_found.len(),
                    rep.not_found.join(", ")
                );
            }
            for w in &rep.warnings {
                println!("{} {w}", st.yellow("!"));
            }
            println!(
                "\n{}\n  - Rotate first: a rewrite never un-leaks a live secret; anyone may already have a copy.\n  - Every commit hash after the first leak changes, and the push must be forced.\n  - Collaborators must re-clone (a pull or merge brings the old history back); open pull requests need rebasing.\n  - Forks, other clones, CI caches and the forge's pull request refs keep the old commits (GitHub Support can purge cached views).\n  - Kubera changed nothing: review the commands and run them yourself.",
                st.red("Before you run this")
            );
            println!("\n{}", st.bold("Commands (need git-filter-repo)"));
            for c in &rep.commands {
                if c.starts_with('#') {
                    println!("  {}", st.dim(c));
                } else {
                    println!("  {c}");
                }
            }
        }
    }
    Ok(0)
}

fn cmd_templates(g: &GlobalArgs, cmd: TemplatesCmd) -> Result<u8> {
    match cmd {
        TemplatesCmd::List { format } => {
            let ctx = context(g)?;
            match format {
                OutFormat::Json => {
                    let rows: Vec<_> = ctx
                        .templates
                        .iter()
                        .map(|l| {
                            let t = &l.template;
                            serde_json::json!({
                                "id": t.id, "name": t.name, "platform": t.platform,
                                "severity": t.severity, "source": l.source,
                                "verify": t.verify.is_some(),
                                "analyze": t.analyze.is_some(),
                                "rotate": t.rotate.as_ref().map(|r| if r.steps.is_empty() { "manual" } else { "api" }),
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                OutFormat::Pretty => {
                    let st = &ctx.style;
                    println!(
                        "{}",
                        st.bold(&format!(
                            "{:<26} {:<14} {:<9} {:<7} {:<8} {:<7}",
                            "ID", "PLATFORM", "SEVERITY", "VERIFY", "ANALYZE", "ROTATE"
                        ))
                    );
                    for l in &ctx.templates {
                        let t = &l.template;
                        let yn = |b: bool| if b { "yes" } else { "-" };
                        let rot = match &t.rotate {
                            Some(r) if !r.steps.is_empty() => "api",
                            Some(_) => "manual",
                            None => "-",
                        };
                        println!(
                            "{:<26} {:<14} {:<9} {:<7} {:<8} {:<7}",
                            t.id,
                            t.platform,
                            t.severity.to_string(),
                            yn(t.verify.is_some()),
                            yn(t.analyze.is_some()),
                            rot
                        );
                    }
                }
            }
            Ok(0)
        }
        TemplatesCmd::Show { id } => {
            let ctx = context(g)?;
            let t = template::find(&ctx.templates, &id)?;
            print!("{}", serde_yaml::to_string(t)?);
            Ok(0)
        }
        TemplatesCmd::Validate { paths } => {
            let mut failed = false;
            for p in paths {
                match template::load_path(&p) {
                    Ok(list) => {
                        for l in list {
                            let fails = template::testing::run(&l.template)?;
                            if fails.is_empty() {
                                println!("ok    {} ({})", l.template.id, l.source);
                            } else {
                                failed = true;
                                println!("FAIL  {} ({})", l.template.id, l.source);
                                for f in fails {
                                    println!("      {f}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        failed = true;
                        println!("FAIL  {}: {e:#}", p.display());
                    }
                }
            }
            Ok(if failed { 1 } else { 0 })
        }
        TemplatesCmd::Test => {
            let ctx = context(g)?;
            let mut failed = 0;
            for l in &ctx.templates {
                let t = &l.template;
                let fails = template::testing::run(t)?;
                let n = t
                    .tests
                    .as_ref()
                    .map(|x| x.positive.len() + x.negative.len())
                    .unwrap_or(0);
                if fails.is_empty() {
                    println!("ok    {:<26} {n} sample(s)", t.id);
                } else {
                    failed += 1;
                    println!("FAIL  {}", t.id);
                    for f in fails {
                        println!("      {f}");
                    }
                }
            }
            Ok(if failed > 0 { 1 } else { 0 })
        }
        TemplatesCmd::New { id } => {
            print!("{}", SKELETON.replace("__ID__", &id));
            Ok(0)
        }
    }
}

const SKELETON: &str = r#"# Kubera detector template. Reference: docs/TEMPLATES.md
id: __ID__
name: Example API Key
platform: Example
description: API key for the Example platform.
severity: high
references:
  - https://docs.example.com/api/authentication

detect:
  # Cheap case-insensitive prefilter; keep these specific.
  keywords: [exk_]
  patterns:
    - name: token
      regex: '\b(exk_[A-Za-z0-9]{32})\b'
      min_entropy: 3.5
      exclude: ['(?i)example|dummy|x{8}']

verify:
  request:
    method: GET
    url: https://api.example.com/v1/me
    auth: { type: bearer, token: "{{ token }}" }
  valid:   { status: [200] }
  invalid: { status: [401, 403] }
  extract:
    - { name: account, label: Account, json: email }

analyze:
  notes: What the key can do.
  steps:
    - name: permissions
      description: List the scopes attached to the key
      request:
        url: https://api.example.com/v1/me/scopes
        auth: { type: bearer, token: "{{ token }}" }
      extract:
        - { name: scopes, label: Scopes, json: "scopes.*.name" }

rotate:
  instructions: |
    1. Create a new key at https://example.com/settings/keys
    2. Deploy it, then delete the leaked key.
  inputs:
    - { name: key_name, default: "rotated-by-kubera-{{ date }}" }
  steps:
    - name: create
      description: Create a replacement key
      request:
        method: POST
        url: https://api.example.com/v1/keys
        auth: { type: bearer, token: "{{ token }}" }
        json: { name: "{{ key_name }}" }
      expect: { status: [201] }
      extract:
        - { name: new_token, json: key, secret: true }
    - name: revoke
      description: Revoke the leaked key
      request:
        method: DELETE
        url: https://api.example.com/v1/keys/current
        auth: { type: bearer, token: "{{ token }}" }
      expect: { status: [204] }
  outputs: [new_token]

tests:
  # Samples are rendered first: split literals with {{'...'}} so realistic
  # fake tokens are not committed verbatim.
  positive:
    - "EXAMPLE_KEY=exk{{'_'}}a8Fj2kLm9QpZx7Wv3RtYb6NcHd4Gs1Ue"
  negative:
    - "EXAMPLE_KEY=exk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"#;
