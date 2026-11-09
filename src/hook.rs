//! Git pre-commit hook: block commits that add secrets.
//!
//! `kubera hook install` writes a small `pre-commit` script that runs
//! `kubera scan staged --fail`, so only the lines a commit adds are scanned
//! (fast, and pre-existing findings never block unrelated commits). The
//! hooks directory comes from git itself, so `core.hooksPath` and worktrees
//! are honoured. Hooks kubera did not write are never overwritten without
//! `--force`, and are then kept as a backup.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// Marks hooks written by kubera.
const MARKER: &str = "# kubera-hook";

/// The interpreter line: `/bin/sh`, except where it does not exist
/// (Android / Termux keeps its shell under `$PREFIX/bin`).
fn shebang() -> String {
    if cfg!(unix)
        && !Path::new("/bin/sh").exists()
        && let Some(prefix) = std::env::var_os("PREFIX")
    {
        let sh = Path::new(&prefix).join("bin/sh");
        if sh.exists() {
            return format!("#!{}", sh.display());
        }
    }
    "#!/bin/sh".into()
}

pub fn script() -> String {
    format!(
        r#"{shebang}
{MARKER} (installed by `kubera hook install`; remove with `kubera hook uninstall`)
# Blocks commits that add secrets. To commit anyway (e.g. a false positive
# you are about to allowlist in .kubera.yaml): git commit --no-verify
if ! command -v kubera >/dev/null 2>&1; then
    echo "kubera pre-commit hook: kubera is not on PATH; install it or commit with --no-verify" >&2
    exit 1
fi
kubera scan staged --fail
status=$?
if [ "$status" -eq 183 ]; then
    echo "kubera: commit blocked - the staged changes add the secret(s) above." >&2
    echo "        Remove them (and rotate any that were real), or mark a false positive" >&2
    echo "        with a 'kubera:ignore' comment or an allowlist entry in .kubera.yaml." >&2
fi
exit $status
"#,
        shebang = shebang()
    )
}

/// The repository's hooks directory (`core.hooksPath` aware).
pub fn hooks_dir(repo: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(repo)
        .args(["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
        .stdin(Stdio::null())
        .output()
        .context("running git (is git installed?)")?;
    if !out.status.success() {
        bail!("{} is not inside a git repository", repo.display());
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    New(PathBuf),
    Updated(PathBuf),
    /// Replaced a foreign hook, kept at the given backup path.
    Replaced {
        hook: PathBuf,
        backup: PathBuf,
    },
}

pub fn install(repo: &Path, force: bool) -> Result<Installed> {
    let dir = hooks_dir(repo)?;
    std::fs::create_dir_all(&dir)?;
    let hook = dir.join("pre-commit");
    let result = match std::fs::read_to_string(&hook) {
        Ok(old) if old.contains(MARKER) => Installed::Updated(hook.clone()),
        Ok(_) if !force => bail!(
            "{} already exists and was not written by kubera; re-run with --force to \
             replace it (it is kept as pre-commit.bak), or call `kubera scan staged --fail` \
             from it yourself",
            hook.display()
        ),
        Ok(_) => {
            let backup = dir.join("pre-commit.bak");
            std::fs::rename(&hook, &backup)?;
            Installed::Replaced {
                hook: hook.clone(),
                backup,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Installed::New(hook.clone()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", hook.display())),
    };
    std::fs::write(&hook, script())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(result)
}

/// Remove the hook if kubera wrote it. Returns its path when removed.
pub fn uninstall(repo: &Path) -> Result<Option<PathBuf>> {
    let hook = hooks_dir(repo)?.join("pre-commit");
    match std::fs::read_to_string(&hook) {
        Ok(s) if s.contains(MARKER) => {
            std::fs::remove_file(&hook)?;
            Ok(Some(hook))
        }
        Ok(_) => bail!(
            "{} was not written by kubera; leaving it alone",
            hook.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let ok = Command::new("git")
            .args(["init", "-q"])
            .current_dir(d.path())
            .status()
            .unwrap()
            .success();
        assert!(ok);
        d
    }

    #[test]
    fn install_update_uninstall_and_foreign_hooks() {
        let d = repo();
        // git reports resolved paths (macOS: /var -> /private/var).
        let hook = d
            .path()
            .canonicalize()
            .unwrap()
            .join(".git/hooks/pre-commit");
        assert!(matches!(
            install(d.path(), false).unwrap(),
            Installed::New(_)
        ));
        assert!(
            std::fs::read_to_string(&hook)
                .unwrap()
                .contains("scan staged --fail")
        );
        assert!(matches!(
            install(d.path(), false).unwrap(),
            Installed::Updated(_)
        ));
        assert_eq!(uninstall(d.path()).unwrap(), Some(hook.clone()));
        assert_eq!(uninstall(d.path()).unwrap(), None);

        std::fs::write(&hook, "#!/bin/sh\nmake lint\n").unwrap();
        assert!(install(d.path(), false).is_err());
        assert!(uninstall(d.path()).is_err());
        let r = install(d.path(), true).unwrap();
        assert!(matches!(r, Installed::Replaced { .. }));
        let bak = d.path().join(".git/hooks/pre-commit.bak");
        assert_eq!(
            std::fs::read_to_string(bak).unwrap(),
            "#!/bin/sh\nmake lint\n"
        );
    }

    #[test]
    fn honours_core_hooks_path() {
        let d = repo();
        let ok = Command::new("git")
            .args(["config", "core.hooksPath", "githooks"])
            .current_dir(d.path())
            .status()
            .unwrap()
            .success();
        assert!(ok);
        install(d.path(), false).unwrap();
        assert!(d.path().join("githooks/pre-commit").exists());
    }
}
