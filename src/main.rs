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
    /// Manage detector templates.
    Templates {
        #[command(subcommand)]
        cmd: TemplatesCmd,
    },
}

#[derive(Subcommand)]
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
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Scan standard input.
    Stdin {
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
    /// Skip files larger than this many bytes.
    #[arg(long, value_name = "BYTES")]
    max_file_size: Option<u64>,
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
    }
}

async fn cmd_scan(g: &GlobalArgs, source: ScanSource) -> Result<u8> {
    let ctx = context(g)?;
    let opts = match &source {
        ScanSource::Fs { opts, .. } | ScanSource::Git { opts, .. } | ScanSource::Stdin { opts } => {
            opts
        }
    };
    let engine = Engine::new(ctx.templates.iter().map(|l| l.template.clone()).collect())?;
    let mut excludes = ctx.cfg.exclude_paths.clone();
    excludes.extend(opts.exclude_paths.iter().cloned());
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
            ..
        } => {
            let token = match token_env {
                Some(var) => Some(std::env::var(var).with_context(|| {
                    format!("environment variable `{var}` (from --token-env) is not set")
                })?),
                None => None,
            };
            scan::Target::Git {
                repo: repo.clone(),
                options: git::GitOptions {
                    branch: branch.clone(),
                    since_commit: since_commit.clone(),
                    max_depth: *max_depth,
                },
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
    };
    let show_progress = std::io::stderr().is_terminal() && opts.format == Format::Pretty;
    if show_progress && !opts.interactive {
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
    let mut findings = scan::run(&engine, &filter, &target, max_size, &progress)?;
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
    let filter = Filter::new(&ctx.cfg.exclude_paths, &ctx.cfg.allowlist)?;
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
