use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tar::Archive;

/// Reads one entry's raw bytes out of the outer `docker save` tarball
/// by exact path match (e.g. `"manifest.json"` or
/// `"blobs/sha256/<digest>"`). The save tarball is opened fresh for
/// each call rather than cached/indexed, since `tar::Archive` reads
/// sequentially — for the handful of lookups this tool does per run
/// (one manifest + one pass per layer) that's simpler and plenty fast
/// enough, at the cost of re-reading the file's headers each time
/// rather than building a full path index up front.
pub fn read_entry(save_tar_path: &Path, wanted: &str) -> Result<Option<Vec<u8>>> {
    let file = File::open(save_tar_path)
        .with_context(|| format!("opening {}", save_tar_path.display()))?;
    let mut archive = Archive::new(file);

    for entry in archive.entries().context("reading save tarball entries")? {
        let mut entry = entry.context("reading a save tarball entry header")?;
        let path = entry
            .path()
            .context("reading entry path")?
            .to_string_lossy()
            .to_string();
        let normalized = path.strip_prefix("./").unwrap_or(&path);
        if normalized == wanted {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("reading entry content")?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

/// Reads and parses `manifest.json` out of the save tarball.
pub fn read_manifest_json(save_tar_path: &Path) -> Result<String> {
    let bytes = read_entry(save_tar_path, "manifest.json")?.ok_or_else(|| {
        anyhow!(
            "no manifest.json found in {} - is this a real `docker save` tarball?",
            save_tar_path.display()
        )
    })?;
    String::from_utf8(bytes).context("manifest.json is not valid UTF-8")
}

/// Reads one layer blob's raw bytes by the path given in
/// `manifest.json`'s `Layers` array.
pub fn read_layer_blob(save_tar_path: &Path, layer_path: &str) -> Result<Vec<u8>> {
    read_entry(save_tar_path, layer_path)?.ok_or_else(|| {
        anyhow!("layer '{layer_path}' listed in manifest.json but not found in the tarball")
    })
}
