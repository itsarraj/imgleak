use anyhow::{Context, Result};
use serde::Deserialize;

/// One entry of the classic Docker `manifest.json` array (still written
/// by `docker save` today for backward compatibility, alongside the
/// newer OCI `index.json`/`blobs/` layout). Only the fields this tool
/// actually needs are modeled — `Config`, `LayerSources`, and anything
/// else in a real `manifest.json` is ignored via serde's default
/// "unknown fields are fine" behavior.
#[derive(Debug, Deserialize)]
struct ManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// Parses `manifest.json`'s raw text and returns every layer blob path
/// referenced by any image entry in it, in order, de-duplicated (a
/// multi-tag save can list the same image, and thus the same layers,
/// under more than one `RepoTags` entry).
///
/// Paths come back exactly as written in the manifest (e.g.
/// `"blobs/sha256/<digest>"`), ready to look up directly inside the
/// outer save tarball.
pub fn parse_manifest(json: &str) -> Result<Vec<String>> {
    let entries: Vec<ManifestEntry> =
        serde_json::from_str(json).context("manifest.json is not the expected array shape")?;

    let mut seen = std::collections::HashSet::new();
    let mut layers = Vec::new();
    for entry in entries {
        for layer in entry.layers {
            if seen.insert(layer.clone()) {
                layers.push(layer);
            }
        }
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_realistic_single_image_manifest() {
        // Shaped exactly like a real `docker save` manifest.json for a
        // 3-layer image (this is the actual structure Docker 29
        // produces - confirmed live, see this tool's README).
        let json = r#"[
            {
                "Config": "blobs/sha256/aaa",
                "RepoTags": ["myimage:test"],
                "Layers": [
                    "blobs/sha256/layer0",
                    "blobs/sha256/layer1",
                    "blobs/sha256/layer2"
                ],
                "LayerSources": {}
            }
        ]"#;
        let layers = parse_manifest(json).unwrap();
        assert_eq!(
            layers,
            vec![
                "blobs/sha256/layer0",
                "blobs/sha256/layer1",
                "blobs/sha256/layer2"
            ]
        );
    }

    #[test]
    fn dedups_layers_shared_across_multiple_manifest_entries() {
        let json = r#"[
            {"Config": "c1", "RepoTags": ["a:1"], "Layers": ["L0", "L1"]},
            {"Config": "c1", "RepoTags": ["a:2"], "Layers": ["L0", "L1"]}
        ]"#;
        let layers = parse_manifest(json).unwrap();
        assert_eq!(layers, vec!["L0", "L1"]);
    }

    #[test]
    fn unions_distinct_layers_across_multiple_images_preserving_first_seen_order() {
        let json = r#"[
            {"Config": "c1", "RepoTags": ["a:1"], "Layers": ["L0", "L1"]},
            {"Config": "c2", "RepoTags": ["b:1"], "Layers": ["L1", "L2"]}
        ]"#;
        let layers = parse_manifest(json).unwrap();
        assert_eq!(layers, vec!["L0", "L1", "L2"]);
    }

    #[test]
    fn empty_manifest_array_yields_no_layers() {
        assert!(parse_manifest("[]").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_errors_instead_of_panicking() {
        assert!(parse_manifest("not json at all").is_err());
        assert!(parse_manifest(r#"{"not": "an array"}"#).is_err());
    }

    #[test]
    fn missing_layers_field_errors() {
        let json = r#"[{"Config": "c1", "RepoTags": ["a:1"]}]"#;
        assert!(parse_manifest(json).is_err());
    }
}
