//! An interrupted history scan, resumed from its checkpoint, reports
//! exactly what an uninterrupted scan reports, including repeated changes
//! whose first commit is only met after the resume.
//!
//! In its own test binary: stopping a scan sets a process-wide flag.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// `n` commits on main, a token every 40th; two more branches, later in
/// time, each add a token of their own and replay the same changes (other
/// commit ids, same blobs). Scans meet
/// the copies first (rev-list is newest first), so the first commit of
/// each repeated change comes late.
fn repo(d: &Path, n: usize) {
    let st = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(d)
        .status()
        .unwrap();
    assert!(st.success());
    let files = |i: usize| {
        let mut f = vec![(format!("src/f{i}.txt"), format!("line {i}\n"))];
        if i.is_multiple_of(40) {
            let tok = format!("gh{}_{}{i:04}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5A");
            f.push((format!("conf/c{i}.env"), format!("TOKEN={tok}\n")));
        }
        f
    };
    let mut s = String::new();
    let mut mark = 0;
    let mut commit = |s: &mut String,
                      branch: &str,
                      from: usize,
                      t: usize,
                      f: Vec<(String, String)>| {
        mark += 1;
        s.push_str(&format!(
            "commit refs/heads/{branch}\nmark :{mark}\ncommitter T <t@example.com> {} +0000\ndata 2\nc\n",
            1_700_000_000 + t
        ));
        if from > 0 {
            s.push_str(&format!("from :{from}\n"));
        }
        for (p, b) in f {
            s.push_str(&format!("M 644 inline {p}\ndata {}\n{b}\n", b.len()));
        }
        mark
    };
    let mut prev = 0;
    for i in 0..n {
        prev = commit(&mut s, "main", prev, i, files(i));
    }
    for k in 0..2 {
        let t = 100_000 * (k + 1);
        // A token of the branch's own, met (and finished) before the stop:
        // only the checkpoint remembers it.
        let tok = format!("gh{}_{}{k:04}", "p", "Bb9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg");
        let own = vec![(format!("conf/b{k}.env"), format!("TOKEN={tok}\n"))];
        let mut prev = commit(&mut s, &format!("copy{k}"), 1, t, own);
        for i in 1..n {
            prev = commit(&mut s, &format!("copy{k}"), prev, t + i, files(i));
        }
    }
    let mut child = Command::new("git")
        .args(["fast-import", "--quiet"])
        .current_dir(d)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    assert!(child.wait().unwrap().success());
}

fn cli_scan(d: &Path, extra: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(["scan", "git", ".", "-f", "json", "-j", "2"])
        .args(extra)
        .current_dir(d)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn resumed_scan_reports_what_an_uninterrupted_one_does() {
    use kubera::config::{Config, Filter};
    use kubera::scan::{Progress, Target};

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    repo(d, 1200);
    let expected = cli_scan(d, &[]);
    assert_eq!(expected.as_array().unwrap().len(), 32, "{expected:#}");

    // The same scan (same detectors, filter and options as the CLI's), in
    // process, stopped halfway.
    let cp = d.join("scan.ckpt");
    let templates = kubera::template::load_set(&[], true, &[], &[]).unwrap();
    let engine =
        kubera::detect::Engine::new(templates.iter().map(|l| l.template.clone()).collect())
            .unwrap();
    let filter = Filter::new(&Config::default().excludes(&[], false), &Default::default()).unwrap();
    let target = Target::Git {
        repo: d.display().to_string(),
        options: kubera::sources::git::GitOptions {
            jobs: 2,
            checkpoint: Some(cp.clone()),
            ..Default::default()
        },
        auth: Default::default(),
        baseline: None,
        mirror: None,
    };
    let stop = |p: Progress| {
        if let Progress::Commits { done, total } = p
            && done * 2 >= total
        {
            kubera::checkpoint::request_stop();
        }
    };
    let max = kubera::sources::fs::DEFAULT_MAX_FILE_SIZE;
    let err = kubera::scan::run_detailed(&engine, &filter, &target, max, &stop).unwrap_err();
    assert!(format!("{err:#}").contains("progress saved"), "{err:#}");
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cp).unwrap()).unwrap();
    let done = saved["done"].as_array().unwrap().len();
    assert!(done > 0 && done < 3598, "{done} commits done");
    assert!(
        !saved["changes"].as_array().unwrap().is_empty(),
        "repeated changes with findings are checkpointed"
    );

    // Resumed by the CLI: identical output, checkpoint removed.
    let resumed = cli_scan(d, &["--checkpoint", cp.to_str().unwrap()]);
    assert_eq!(resumed, expected);
    assert!(!cp.exists());
}
