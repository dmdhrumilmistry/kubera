# Published packages

What gets published is not always what is in the repository. A build step writes a config file, a stray `.env` or `.npmrc` sits in the working directory when `npm publish` runs, a test fixture holds a real key. `kubera scan package` downloads what users actually install, from the official registry, and scans every file inside it.

```bash
kubera scan package npm:left-pad                       # latest version
kubera scan package npm:@acme/cli@2.1.0                # a scoped package, one version
kubera scan package pypi:requests==2.32.3              # sdist and a wheel
kubera scan package crates:serde@1.0.200
kubera scan package npm:@acme/cli pypi:acme-tool --all-versions --max-versions 50
```

## What gets downloaded

| Spec | Registry | Files |
|---|---|---|
| `npm:<name>[@version]` | `registry.npmjs.org` | The package tarball |
| `pypi:<name>[==version]` | `pypi.org`, files from `files.pythonhosted.org` | The sdist and one wheel (a pure-Python `none-any` wheel when there is one) |
| `crates:<name>[@version]` | `crates.io`, files from `static.crates.io` | The `.crate` file |

Without a version, the latest one is scanned (npm `latest` tag, PyPI's current release, crates.io's default version). `--all-versions` scans every published version, newest first, up to `--max-versions` (default 20). Yanked crates are included: yanking does not unpublish a version, and a leak is a common reason to yank one.

Findings point at the file inside the package:

```text
repository: npm:@acme/cli@2.1.0
path:       cli-2.1.0.tgz
entry:      package/.env
link:       https://www.npmjs.com/package/@acme/cli/v/2.1.0
```

## Integrity and limits

- Every file is checked against the digest the registry publishes before it is opened: npm `integrity` (sha512), PyPI and crates.io sha256. A mismatch stops the scan with an error. Old npm versions that only have a SHA-1 `shasum` are scanned with a warning that they could not be verified.
- Files are only downloaded over HTTPS from the registry or its own file host; a download URL pointing anywhere else is refused.
- Sizes the registry declares are checked before downloading; `--max-package-size` (default 512 MiB) caps every download. Packages are opened in memory with the [archive limits](scanning.md#archives) and never extracted to disk.
- No credentials are used: only public packages can be scanned.

| Flag | Meaning |
|---|---|
| `--all-versions` | Scan every published version, newest first. |
| `--max-versions N` | With `--all-versions`: at most N versions per package (default 20). |
| `--max-package-size BYTES` | Largest file downloaded (default 512 MiB). |

All [common scan options](scanning.md#common-options) work too. [Default excludes](scanning.md#default-excludes) apply to the files inside packages (a crate's `vendor/` directory, for example); pass `--no-default-excludes` to scan them as well.
