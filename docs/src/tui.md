# Interactive TUI

Run `kubera` with no arguments in a terminal (or `kubera tui`) to open the interactive interface:

<img class="kubera-shot" src="images/tui-home.svg" alt="Kubera TUI home screen with logo and menu">

```bash
kubera                                  # home menu
kubera tui ./services/api               # scan a folder straight away
kubera tui github.com/org/repo          # scan a repository (URLs are detected)
kubera tui . --git --verify             # this repo's history, verify when done
kubera scan git . --verify -i           # any CLI scan, results in the TUI
```

`-i` / `--interactive` works with every `scan` source and all its flags (including `--token-env` for private repositories).

## Browsing findings

<img class="kubera-shot" src="images/tui-results.svg" alt="Findings list on the left, details of the selected finding on the right">

The list shows each finding's verification status (`●` live, `✓` invalid, `?` unknown, `·` not verified yet) and severity. The detail pane has three tabs:

| Tab | Shows |
|---|---|
| **1 Overview** | Location, commit, author, link, the (redacted) secret, fingerprint and verification result |
| **2 Analysis** | Identity, scopes and permission probes from read-only API calls |
| **3 Rotation** | The rotation runbook and the dry-run API plan |

<img class="kubera-shot" src="images/tui-analysis.svg" alt="Analysis tab: IAM policies, groups and access keys of a leaked AWS key">

## Keys

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k` | Move |
| `g` / `G` | First / last finding |
| `v` | Verify the selected finding (on the home screen: toggle verify-after-scan) |
| `V` | Verify every unverified finding |
| `a` | Analyze the selected finding |
| `p` | Rotation plan (dry run) for the selected finding |
| `1` `2` `3` / `Tab` | Switch detail tab |
| `PgUp` / `PgDn` | Scroll the detail pane |
| `r` | Reveal / hide the secret |
| `/` | Filter by text (detector, name, path, commit) |
| `f` | Filter by status: all → live → not invalid → invalid |
| `e` | Export findings to `kubera-findings-<time>.json` |
| `x` | Mark the selected finding as a false positive (saved to the baseline) |
| `m` | Mark it as an accepted risk (saved to the baseline) |
| `u` | Undo the last mark |
| `?` | Help |
| `q` / `Esc` | Back / quit |
| `Ctrl+C` | Quit |

Network work (verification, analysis, rotation plans) runs in the background, so the interface never freezes. A spinner marks findings that are being checked.

## Triage

`x` and `m` remove the finding from the list and record the decision in `.kubera-baseline.json` in the current directory, straight away. Findings already in that file are not shown, in this session or later ones, and CLI scans, the pre-commit hook and CI skip them too once you commit the file. `u` undoes the last mark. See [Baselines and triage](triage.md).

## Safe by design

- Secrets are masked until you press `r`, and hidden again as soon as you move to another finding.
- `e` always exports **redacted** findings, to a new file with mode `0600`.
- Rotation in the TUI is plan-only. Applying a rotation stays an explicit CLI step (`kubera rotate … --execute`), with its confirmation prompt.
- The TUI never lets SSH prompt (it owns the terminal). For private repositories, use `kubera scan git URL --token-env VAR -i`.

## Phones and small terminals

The layout adapts to the terminal size: below 100 columns the list and the details stack vertically, so it works in Termux on a phone.

<img class="kubera-shot" src="images/tui-phone.svg" alt="Kubera TUI on a 50-column phone terminal" style="max-width: 460px">
