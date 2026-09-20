use std::io::Read;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

/// A file's above this size is skipped entirely rather than read into
/// memory — large binary layers (base OS images, compiled artifacts)
/// have no business being scanned line-by-line for secrets, and this
/// keeps memory bounded regardless of how large a single layer file
/// happens to be.
pub const MAX_SCANNED_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

/// One regular file (or whiteout marker) found inside a single layer's
/// tar. `content` is `None` for whiteout markers, directories, and
/// files skipped for being over `MAX_SCANNED_FILE_BYTES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerFile {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub whiteout: Option<Whiteout>,
}

/// What an OCI/Docker "whiteout" marker file hides. Deleting a file in
/// a later layer never rewrites the earlier layer that added it — the
/// filesystem union just adds one of these markers so the merged view
/// stops showing the file. The original bytes stay exactly where they
/// were, in the earlier layer's own tar, which is the entire premise
/// this tool exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whiteout {
    /// `.wh.<name>` hides exactly one path from an earlier layer.
    Exact(String),
    /// `.wh..wh..opq` hides every pre-existing entry directly inside
    /// this directory (from any earlier layer) — used when e.g. an
    /// entire directory is replaced rather than one file removed.
    OpaqueDir(String),
}

fn normalize_path(path: &str) -> String {
    path.strip_prefix("./").unwrap_or(path).to_string()
}

fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(idx) => &path[..idx],
        None => "",
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn classify_whiteout(path: &str) -> Option<Whiteout> {
    let dir = parent_dir(path);
    let basename = &path[dir.len() + usize::from(!dir.is_empty())..];
    if basename == ".wh..wh..opq" {
        return Some(Whiteout::OpaqueDir(dir.to_string()));
    }
    basename
        .strip_prefix(".wh.")
        .map(|target_name| Whiteout::Exact(join(dir, target_name)))
}

/// Parses one layer's raw bytes (as pulled straight out of the outer
/// save tarball) into its individual files. Transparently handles both
/// plain tar and gzip-compressed tar layers by sniffing the gzip magic
/// bytes (`1f 8b`) — different Docker/BuildKit versions and other OCI
/// producers use either.
pub fn parse_layer(bytes: &[u8]) -> Result<Vec<LayerFile>> {
    let is_gzip = bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
    if is_gzip {
        let decoder = GzDecoder::new(bytes);
        parse_tar_entries(decoder)
    } else {
        parse_tar_entries(bytes)
    }
}

fn parse_tar_entries<R: Read>(reader: R) -> Result<Vec<LayerFile>> {
    let mut archive = Archive::new(reader);
    let mut files = Vec::new();

    for entry in archive.entries().context("reading layer tar entries")? {
        let mut entry = entry.context("reading a layer tar entry header")?;
        let entry_type = entry.header().entry_type();
        let path = normalize_path(
            &entry
                .path()
                .context("reading entry path")?
                .to_string_lossy(),
        );

        if entry_type != EntryType::Regular {
            continue;
        }

        if let Some(whiteout) = classify_whiteout(&path) {
            files.push(LayerFile {
                path,
                content: None,
                whiteout: Some(whiteout),
            });
            continue;
        }

        let size = entry.header().size().unwrap_or(0);
        let content = if size <= MAX_SCANNED_FILE_BYTES {
            let mut buf = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut buf)
                .context("reading file content")?;
            Some(buf)
        } else {
            None
        };

        files.push(LayerFile {
            path,
            content,
            whiteout: None,
        });
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tar::{Builder, Header};

    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, content) in files {
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *content).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn parses_a_plain_regular_file() {
        let tar = build_tar(&[("secret.txt", b"hello")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "secret.txt");
        assert_eq!(files[0].content.as_deref(), Some(b"hello".as_slice()));
        assert_eq!(files[0].whiteout, None);
    }

    #[test]
    fn parses_a_gzip_compressed_layer() {
        let tar = build_tar(&[("secret.txt", b"hello")]);
        let gz = gzip(&tar);
        let files = parse_layer(&gz).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].content.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn recognizes_an_exact_whiteout_at_root() {
        let tar = build_tar(&[(".wh.secret.txt", b"")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].whiteout,
            Some(Whiteout::Exact("secret.txt".to_string()))
        );
    }

    #[test]
    fn recognizes_an_exact_whiteout_in_a_subdirectory() {
        let tar = build_tar(&[("app/config/.wh.secret.txt", b"")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(
            files[0].whiteout,
            Some(Whiteout::Exact("app/config/secret.txt".to_string()))
        );
    }

    #[test]
    fn recognizes_an_opaque_directory_whiteout() {
        let tar = build_tar(&[("app/data/.wh..wh..opq", b"")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(
            files[0].whiteout,
            Some(Whiteout::OpaqueDir("app/data".to_string()))
        );
    }

    #[test]
    fn strips_leading_dot_slash_from_paths() {
        // Some tar producers write "./secret.txt" instead of
        // "secret.txt" - both mean the same file at the layer root.
        let tar = build_tar(&[("./secret.txt", b"x")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(files[0].path, "secret.txt");
    }

    #[test]
    fn skips_directory_entries() {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, "proc/", &[][..]).unwrap();
        let tar = builder.into_inner().unwrap();

        let files = parse_layer(&tar).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn skips_files_over_the_size_cap() {
        let big_content = vec![b'a'; (MAX_SCANNED_FILE_BYTES + 1) as usize];
        let tar = build_tar(&[("big.bin", &big_content)]);

        let files = parse_layer(&tar).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "big.bin");
        assert_eq!(files[0].content, None);
    }

    #[test]
    fn multiple_files_in_one_layer_all_parsed() {
        let tar = build_tar(&[("a.txt", b"aaa"), ("dir/b.txt", b"bbb")]);
        let files = parse_layer(&tar).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "a.txt");
        assert_eq!(files[1].path, "dir/b.txt");
    }

    #[test]
    fn empty_layer_has_no_files() {
        let tar = build_tar(&[]);
        let files = parse_layer(&tar).unwrap();
        assert!(files.is_empty());
    }
}
