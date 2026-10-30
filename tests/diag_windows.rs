//! Local diagnostic (#[ignore]d, run by hand): decrypt a .tsb, unpack it,
//! and diff the tar's entries against the unpacked tree to find which
//! entries diverge on Windows.
//!
//! Run:  DIAG_TSB=path/to/file.tsb DIAG_PW=secret cargo test --test
//!       diag_windows -- --ignored --nocapture

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
struct EntryRec {
    kind: char, // 'f' file, 'd' dir, 'l' symlink
    size: u64,
    hash_or_target: String,
}

fn walk_tree(
    root: &Path,
    current: &Path,
    out: &mut BTreeMap<String, EntryRec>,
) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if meta.is_dir() {
            out.insert(
                rel,
                EntryRec {
                    kind: 'd',
                    size: 0,
                    hash_or_target: String::new(),
                },
            );
            walk_tree(root, &path, out)?;
        } else if meta.is_file() {
            let mut h = Sha256::new();
            std::io::copy(&mut std::fs::File::open(&path)?, &mut h)?;
            out.insert(
                rel,
                EntryRec {
                    kind: 'f',
                    size: meta.len(),
                    hash_or_target: hex_of(&h.finalize()),
                },
            );
        } else if meta.is_symlink() {
            let t = std::fs::read_link(&path)?;
            out.insert(
                rel,
                EntryRec {
                    kind: 'l',
                    size: 0,
                    hash_or_target: t.to_string_lossy().to_string(),
                },
            );
        }
        // other (sockets, fifos): skipped, same as pack/verify
    }
    Ok(())
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[ignore]
#[test]
fn diagnose_unpack_mismatch() {
    let tsb = std::env::var("DIAG_TSB").expect("set DIAG_TSB to the .tsb path");
    let pw = std::env::var("DIAG_PW").expect("set DIAG_PW to the backup password");

    let payload =
        termius_secure_backup::container::read_and_decrypt(Path::new(&tsb), pw.as_bytes())
            .expect("decrypt failed");

    // Expand zstd -> tar and record every entry.
    let mut tar_buf = Vec::new();
    zstd::stream::Decoder::new(&payload[..])
        .expect("zstd")
        .read_to_end(&mut tar_buf)
        .expect("zstd read");

    let tar_entries: BTreeMap<String, EntryRec> = {
        let mut m = BTreeMap::new();
        let mut archive = tar::Archive::new(&tar_buf[..]);
        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let name = entry
                .path()
                .expect("path")
                .to_string_lossy()
                .to_string()
                .replace('\\', "/");
            let et = entry.header().entry_type();
            if et.is_file() {
                let mut content = Vec::new();
                entry.read_to_end(&mut content).expect("read file");
                let mut hh = Sha256::new();
                hh.update(&content);
                m.insert(
                    name,
                    EntryRec {
                        kind: 'f',
                        size: content.len() as u64,
                        hash_or_target: hex_of(&hh.finalize()),
                    },
                );
            } else if et.is_dir() {
                m.entry(name).or_insert(EntryRec {
                    kind: 'd',
                    size: 0,
                    hash_or_target: String::new(),
                });
            } else if et.is_symlink() {
                m.insert(
                    name,
                    EntryRec {
                        kind: 'l',
                        size: 0,
                        hash_or_target: entry
                            .link_name()
                            .expect("io")
                            .expect("ln")
                            .to_string_lossy()
                            .to_string(),
                    },
                );
            }
            // __meta.json is a file entry too; it is filtered out below.
        }
        m.remove("__meta.json");
        m
    };

    // Unpack into a fresh temp dir and walk the result.
    let staging = tempfile::tempdir().expect("tempdir");
    let (meta, _) =
        termius_secure_backup::archive::unpack(&payload, staging.path()).expect("unpack");
    let mut tree = BTreeMap::new();
    walk_tree(staging.path(), staging.path(), &mut tree).expect("walk");

    println!(
        "tar entries: {}   tree entries: {}   meta: {} entries / {} bytes",
        tar_entries.len(),
        tree.len(),
        meta.entry_count,
        meta.byte_size
    );
    println!("meta.source_dir    = {}", meta.source_dir);
    println!("meta.tool_version  = {}", meta.tool_version);
    println!("meta.sha256_root   = {}", meta.sha256_root);

    // Case-insensitive duplicates in the tar?
    let mut ci: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in tar_entries.keys() {
        ci.entry(n.to_ascii_lowercase())
            .or_default()
            .push(n.clone());
    }
    println!("\n== tar entries that collide case-insensitively ==");
    for (k, vs) in ci.iter().filter(|(_, vs)| vs.len() > 1) {
        for v in vs {
            println!("  CI[{k}]: {v:?}  ({:?})", tar_entries[v]);
        }
    }

    println!("\n== in tar but missing from tree (exact) ==");
    for (n, r) in tar_entries.iter() {
        if !tree.contains_key(n) {
            println!("  MISSING: {n:?}  ({r:?})");
        }
    }
    println!("\n== in tree but not in tar (exact) ==");
    for (n, r) in tree.iter() {
        if !tar_entries.contains_key(n) {
            println!("  EXTRA:   {n:?}  ({r:?})");
        }
    }
    println!("\n== present in both but differing ==");
    for (n, r) in tar_entries.iter() {
        if let Some(tr) = tree.get(n) {
            if r.kind != tr.kind || r.size != tr.size || r.hash_or_target != tr.hash_or_target {
                println!("  DIFF:    {n:?}\n    tar : {r:?}\n    tree: {tr:?}");
            }
        }
    }

    // Also: any tree entry whose case differs from a tar entry?
    let mut ci_tree: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in tree.keys() {
        ci_tree
            .entry(n.to_ascii_lowercase())
            .or_default()
            .push(n.clone());
    }
    println!("\n== tree entries that collide case-insensitively ==");
    for (k, vs) in ci_tree.iter().filter(|(_, vs)| vs.len() > 1) {
        for v in vs {
            println!("  CI[{k}]: {v:?}  ({:?})", tree[v]);
        }
    }
}
