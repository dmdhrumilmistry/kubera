//! Archives: zip family (zip, jar, war, ear, apk, aar, whl, nupkg, vsix,
//! docx/xlsx/pptx, ...), tar, gzip and tar.gz, nested.
//!
//! Archives are recognised by their magic bytes, not their names. Every
//! limit is enforced on the bytes actually decompressed, never on sizes an
//! archive claims in its headers, so zip bombs and lying headers only waste
//! a bounded amount of work:
//!
//! * text entries larger than `max_entry` are skipped,
//! * nested archives are buffered in memory only up to `max_nested`,
//! * one top-level archive decompresses at most `max_total` bytes and
//!   `max_entries` entries, and nesting stops at `max_depth`.
//!
//! Entries are never written to disk, so hostile paths (`../`, absolute,
//! symlinks) cannot affect anything; they only appear in locations.

use std::io::{BufRead, BufReader, Read, Seek};

use anyhow::Result;

use super::is_binary;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest text entry scanned.
    pub max_entry: u64,
    /// Largest nested archive (buffered in memory).
    pub max_nested: u64,
    /// Decompressed bytes per top-level archive.
    pub max_total: u64,
    /// Entries per top-level archive.
    pub max_entries: usize,
    /// Archive nesting depth (1: no archives inside archives).
    pub max_depth: usize,
}

impl Limits {
    pub fn new(max_entry: u64) -> Self {
        Self {
            max_entry,
            max_nested: 64 * 1024 * 1024,
            max_total: 1024 * 1024 * 1024,
            max_entries: 100_000,
            max_depth: 4,
        }
    }
}

/// Largest archive file read by filesystem scans (independent of
/// `--max-file-size`, which applies to the text inside).
pub const DEFAULT_MAX_ARCHIVE_SIZE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    Gzip,
}

/// Recognise an archive from its first bytes (at least 512 for tar).
pub fn kind(head: &[u8]) -> Option<Kind> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if head.starts_with(&[0x1f, 0x8b]) {
        Some(Kind::Gzip)
    } else if head.len() >= 262 && &head[257..262] == b"ustar" {
        Some(Kind::Tar)
    } else {
        None
    }
}

/// File names that are worth reading past `--max-file-size` as archives.
pub fn archive_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".zip", ".jar", ".war", ".ear", ".apk", ".aar", ".whl", ".egg", ".nupkg", ".vsix", ".xpi",
        ".crx", ".ipa", ".tar", ".tgz", ".gz", ".tbz", ".docx", ".xlsx", ".pptx", ".odt",
    ]
    .iter()
    .any(|e| n.ends_with(e))
}

/// A text entry found inside an archive.
pub struct Entry {
    /// Path inside the top-level archive; nested archives are joined with
    /// `!/` (`lib/app.jar!/config/application.yml`).
    pub path: String,
    pub text: String,
}

struct Walk<'a> {
    limits: Limits,
    total: u64,
    entries: usize,
    emit: &'a mut dyn FnMut(Entry),
}

impl Walk<'_> {
    fn exhausted(&self) -> bool {
        self.total >= self.limits.max_total || self.entries >= self.limits.max_entries
    }

    /// Read at most `cap + 1` bytes, charging them to the budget.
    fn read_capped(&mut self, r: &mut dyn Read, cap: u64) -> Result<Option<Vec<u8>>> {
        let room = self.limits.max_total.saturating_sub(self.total);
        let mut buf = Vec::new();
        r.take(cap.min(room) + 1).read_to_end(&mut buf)?;
        self.total += buf.len() as u64;
        Ok((buf.len() as u64 <= cap && buf.len() as u64 <= room).then_some(buf))
    }

    /// Handle one entry's content: nested archive, text, or skip.
    fn entry(&mut self, path: String, r: &mut dyn Read, depth: usize) -> Result<()> {
        self.entries += 1;
        let mut br = BufReader::with_capacity(64 * 1024, r);
        let head = br.fill_buf()?.to_vec();
        let nested = kind(&head);
        let cap = match nested {
            Some(_) if depth < self.limits.max_depth => self.limits.max_nested,
            Some(_) => return Ok(()),
            None => self.limits.max_entry,
        };
        let Some(data) = self.read_capped(&mut br, cap)? else {
            return Ok(());
        };
        match nested {
            Some(k) => {
                let prefix = format!("{path}!/");
                self.archive(k, std::io::Cursor::new(data), &prefix, depth + 1)
            }
            None if data.is_empty() || is_binary(&data) => Ok(()),
            None => {
                (self.emit)(Entry {
                    path,
                    text: String::from_utf8_lossy(&data).into_owned(),
                });
                Ok(())
            }
        }
    }

    fn archive<R: Read + Seek>(
        &mut self,
        k: Kind,
        mut r: R,
        prefix: &str,
        depth: usize,
    ) -> Result<()> {
        match k {
            Kind::Zip => {
                let mut z = zip::ZipArchive::new(r)?;
                for i in 0..z.len() {
                    if self.exhausted() {
                        break;
                    }
                    let mut f = match z.by_index(i) {
                        Ok(f) => f,
                        // Encrypted or unsupported compression: skip entry.
                        Err(_) => continue,
                    };
                    if !f.is_file() {
                        continue;
                    }
                    let Ok(inner) = f.name().map(|n| n.into_owned()) else {
                        continue;
                    };
                    let name = format!("{prefix}{inner}");
                    self.entry(name, &mut f, depth)?;
                }
                Ok(())
            }
            Kind::Gzip | Kind::Tar => {
                r.rewind()?;
                self.stream(k, &mut r, prefix, depth)
            }
        }
    }

    /// tar / gzip are streamed (no seeking needed).
    fn stream(&mut self, k: Kind, r: &mut dyn Read, prefix: &str, depth: usize) -> Result<()> {
        match k {
            Kind::Gzip => {
                let mut gz = BufReader::with_capacity(64 * 1024, flate2::read::GzDecoder::new(r));
                let head = gz.fill_buf()?.to_vec();
                if kind(&head) == Some(Kind::Tar) {
                    return self.stream(Kind::Tar, &mut gz, prefix, depth);
                }
                // A single compressed file: name it after the archive.
                let name = format!("{prefix}{}", "(gzip)");
                self.entry(name, &mut gz, depth)
            }
            Kind::Tar => {
                let mut ar = tar::Archive::new(r);
                for e in ar.entries()? {
                    if self.exhausted() {
                        break;
                    }
                    let mut e = e?;
                    if !e.header().entry_type().is_file() {
                        continue;
                    }
                    let name = format!(
                        "{prefix}{}",
                        e.path()?.to_string_lossy().trim_start_matches("./")
                    );
                    self.entry(name, &mut e, depth)?;
                }
                Ok(())
            }
            Kind::Zip => {
                // Zip needs random access: buffer (bounded).
                let Some(data) = self.read_capped(r, self.limits.max_nested)? else {
                    return Ok(());
                };
                self.archive(Kind::Zip, std::io::Cursor::new(data), prefix, depth)
            }
        }
    }
}

/// Walk a seekable archive (a file on disk, or bytes in memory).
pub fn walk<R: Read + Seek>(
    k: Kind,
    r: R,
    limits: Limits,
    emit: &mut dyn FnMut(Entry),
) -> Result<()> {
    let mut w = Walk {
        limits,
        total: 0,
        entries: 0,
        emit,
    };
    w.archive(k, r, "", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in files {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    fn tgz_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (n, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, n, *d).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    fn entries(data: &[u8], limits: Limits) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let k = kind(data).expect("archive");
        walk(k, Cursor::new(data), limits, &mut |e| {
            out.push((e.path, e.text))
        })
        .unwrap();
        out
    }

    #[test]
    fn nested_jar_in_tgz_in_zip() {
        let jar = zip_of(&[("BOOT-INF/classes/application.yml", b"password: hunter22\n")]);
        let tgz = tgz_of(&[("./app/lib/app.jar", &jar), ("./README", b"hello\n")]);
        let outer = zip_of(&[("dist/release.tgz", &tgz), ("bin/tool", &[0u8, 1, 2, 3])]);
        let got = entries(&outer, Limits::new(1 << 20));
        assert_eq!(
            got,
            vec![
                (
                    "dist/release.tgz!/app/lib/app.jar!/BOOT-INF/classes/application.yml".into(),
                    "password: hunter22\n".into()
                ),
                ("dist/release.tgz!/README".into(), "hello\n".into()),
            ]
        );
    }

    #[test]
    fn limits_hold_against_bombs_and_depth() {
        // 50 MB of zeros-as-text compresses to ~50 KB.
        let big = vec![b'a'; 50 * 1024 * 1024];
        let bomb = zip_of(&[("big.txt", &big), ("small.txt", b"ok\n")]);
        assert!(bomb.len() < 1024 * 1024);
        let mut l = Limits::new(1 << 20);
        l.max_total = 8 * 1024 * 1024;
        let got = entries(&bomb, l);
        assert_eq!(got.len(), 1, "the oversized entry is skipped, not read");

        let mut nested = zip_of(&[("deep.txt", b"x\n")]);
        for i in 0..6 {
            nested = zip_of(&[(&format!("l{i}.zip"), &nested)]);
        }
        assert!(entries(&nested, Limits::new(1 << 20)).is_empty());
        let mut l = Limits::new(1 << 20);
        l.max_depth = 8;
        assert_eq!(entries(&nested, l).len(), 1);
    }

    #[test]
    fn plain_gzip_and_magic_detection() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"TOKEN=abc\n").unwrap();
        let data = gz.finish().unwrap();
        assert_eq!(
            entries(&data, Limits::new(1 << 20)),
            vec![("(gzip)".into(), "TOKEN=abc\n".into())]
        );
        assert_eq!(kind(b"just text"), None);
        assert!(archive_name("lib/Foo.JAR") && !archive_name("notes.txt"));
    }
}
