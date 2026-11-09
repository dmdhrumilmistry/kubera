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
                    format,
                },
            )
            .await
        }
        Command::Templates { cmd } => cmd_templates(&cli.global, cmd),
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
            let filter = Filter::new(&ctx.cfg.excludes(&[], false), &ctx.cfg.allowlist)?;
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
        | ScanSource::Stdin { opts } => opts,
    };
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let mut engine = engine;
    engine.decode = !opts.no_decode;
    let excludes = ctx
        .cfg
        .excludes(&opts.exclude_paths, opts.no_default_excludes);
    let filter = Filter::new(&excludes, &ctx.cfg.allowlist)?;
    let max_size = opts
        .max_file_size
        .or(ctx.cfg.max_file_size)
        .unwrap_or(sources::fs::DEFAULT_MAX_FILE_SIZE);
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
    let (commits_scanned, tips, mut findings) = if let ScanSource::Repos { .. } = &source {
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
    if opts.interactive {
        if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
            bail!("--interactive needs a terminal");
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
            ScanSource::Image { image, .. } => image.clone(),
            ScanSource::Repos { .. } => format!(
                "{} repositories",
                mass_results.as_ref().map(|r| r.len()).unwrap_or(0)
            ),
        };
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
    } else {
        0
    })
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
    }
}

fn cmd_tui(g: &GlobalArgs, target: Option<String>, git: bool, verify: bool) -> Result<u8> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        bail!("the TUI needs an interactive terminal");
    }
    let ctx = context(g)?;
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let filter = Filter::new(&ctx.cfg.excludes(&[], false), &ctx.cfg.allowlist)?;
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

struct RotateFlags {
    execute: bool,
    yes: bool,
    force: bool,
    stdin_used: bool,
    output_file: Option<PathBuf>,
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

    let mut opts = rotate::Options {
        execute: false,
        force: f.force,
        inputs,
    };

    if f.execute && !f.yes {
        if f.stdin_used || !std::io::stdin().is_terminal() {
            bail!("stdin is not interactive; pass --yes to confirm the rotation");
        }
        let plan = rotate::rotate(&ctx.http, t, parts, &opts).await?;
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

    opts.execute = f.execute;
    let mut rep = rotate::rotate(&ctx.http, t, parts, &opts).await?;

    // Persist the new credential before printing anything else.
    if let Some(path) = &f.output_file
        && !rep.outputs.is_empty()
    {
        write_private(path, &serde_json::to_vec_pretty(&rep.outputs)?)?;
        eprintln!("new credential written to {}", path.display());
        rep.outputs.clear();
    }

    let mut shown = rep.clone();
    shown.steps = shown.steps.iter().map(|s| s.redacted()).collect();
    match f.format {
        OutFormat::Json => println!("{}", serde_json::to_string_pretty(&shown)?),
        OutFormat::Pretty => print_rotation(&shown, st),
    }
    Ok(if rep.executed && !rep.completed { 2 } else { 0 })
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
