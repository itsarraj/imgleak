use crate::layer::{LayerFile, Whiteout};
use crate::rules::{scan_content, suspicious_filename_reason, SecretKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub layer_index: usize,
    pub path: String,
    pub kind: SecretKind,
    pub detail: String,
    /// `Some(layer_index)` of the first later layer that hides this
    /// exact path via a whiteout marker — the file is still fully
    /// present in `layer_index`'s own tar either way, this is purely
    /// informational context about the "COPY then rm" pattern.
    pub hidden_in_later_layer: Option<usize>,
}

fn path_hidden_by(
    path: &str,
    whiteouts: &[(usize, Whiteout)],
    after_layer: usize,
) -> Option<usize> {
    whiteouts
        .iter()
        .filter(|(idx, _)| *idx > after_layer)
        .filter(|(_, w)| match w {
            Whiteout::Exact(target) => target == path,
            Whiteout::OpaqueDir(dir) => {
                path.starts_with(dir.as_str())
                    && path[dir.len()..].starts_with('/')
                    && !dir.is_empty()
            }
        })
        .map(|(idx, _)| *idx)
        .min()
}

/// Applies the secret-detection rules across every already-parsed
/// layer and cross-references whiteout markers, so a secret added in
/// an early layer and later "removed" is still reported — annotated
/// with exactly which later layer tried to hide it, rather than
/// silently passing because the final merged filesystem view no
/// longer shows the file.
///
/// This is the heart of what makes this tool different from just
/// running a secrets scanner against `docker export`'s flattened
/// output (which only ever sees the final, already-hidden state).
pub fn analyze_layers(layers: &[Vec<LayerFile>]) -> Vec<Finding> {
    let mut whiteouts: Vec<(usize, Whiteout)> = Vec::new();
    for (idx, files) in layers.iter().enumerate() {
        for file in files {
            if let Some(w) = &file.whiteout {
                whiteouts.push((idx, w.clone()));
            }
        }
    }

    let mut findings = Vec::new();
    for (idx, files) in layers.iter().enumerate() {
        for file in files {
            if file.whiteout.is_some() {
                continue;
            }

            if let Some(reason) = suspicious_filename_reason(&file.path) {
                findings.push(Finding {
                    layer_index: idx,
                    path: file.path.clone(),
                    kind: SecretKind::SuspiciousFilename,
                    detail: reason,
                    hidden_in_later_layer: path_hidden_by(&file.path, &whiteouts, idx),
                });
            }

            if let Some(content) = &file.content {
                if let Ok(text) = std::str::from_utf8(content) {
                    for m in scan_content(text) {
                        findings.push(Finding {
                            layer_index: idx,
                            path: file.path.clone(),
                            kind: m.kind,
                            detail: m.detail,
                            hidden_in_later_layer: path_hidden_by(&file.path, &whiteouts, idx),
                        });
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, content: &str) -> LayerFile {
        LayerFile {
            path: path.to_string(),
            content: Some(content.as_bytes().to_vec()),
            whiteout: None,
        }
    }

    fn whiteout(path: &str, target: &str) -> LayerFile {
        LayerFile {
            path: path.to_string(),
            content: None,
            whiteout: Some(Whiteout::Exact(target.to_string())),
        }
    }

    #[test]
    fn secret_added_then_removed_in_a_later_layer_is_still_reported() {
        // This is exactly the scenario the task defining this tool
        // describes: COPY secret.txt in layer 0, RUN rm secret.txt in
        // layer 1. The bytes never actually leave the image.
        let layers = vec![
            vec![file("secret.txt", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")],
            vec![whiteout(".wh.secret.txt", "secret.txt")],
        ];
        let findings = analyze_layers(&layers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].layer_index, 0);
        assert_eq!(findings[0].kind, SecretKind::AwsAccessKey);
        assert_eq!(findings[0].hidden_in_later_layer, Some(1));
    }

    #[test]
    fn secret_never_removed_has_no_hidden_annotation() {
        let layers = vec![vec![file(
            "secret.txt",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        )]];
        let findings = analyze_layers(&layers);
        assert_eq!(findings[0].hidden_in_later_layer, None);
    }

    #[test]
    fn whiteout_in_an_earlier_layer_does_not_count() {
        // A whiteout can only hide something from a *preceding* layer;
        // if for some reason a marker at the same target path appears
        // before the secret's own layer, it must not be treated as
        // having hidden it (that would be temporally backwards).
        let layers = vec![
            vec![whiteout(".wh.secret.txt", "secret.txt")],
            vec![file("secret.txt", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")],
        ];
        let findings = analyze_layers(&layers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].hidden_in_later_layer, None);
    }

    #[test]
    fn whiteout_with_no_matching_secret_produces_no_findings() {
        let layers = vec![
            vec![file("readme.txt", "just docs")],
            vec![whiteout(".wh.readme.txt", "readme.txt")],
        ];
        let findings = analyze_layers(&layers);
        assert!(findings.is_empty());
    }

    #[test]
    fn opaque_directory_whiteout_hides_everything_under_it() {
        let layers = vec![
            vec![file(
                "secrets/aws.env",
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            )],
            vec![LayerFile {
                path: "secrets/.wh..wh..opq".to_string(),
                content: None,
                whiteout: Some(Whiteout::OpaqueDir("secrets".to_string())),
            }],
        ];
        let findings = analyze_layers(&layers);
        assert_eq!(findings[0].hidden_in_later_layer, Some(1));
    }

    #[test]
    fn suspicious_filename_finding_generated_even_without_content_match() {
        let layers = vec![vec![LayerFile {
            path: "home/.ssh/id_rsa".to_string(),
            content: Some(b"binary key material, not utf8-parseable text".to_vec()),
            whiteout: None,
        }]];
        let findings = analyze_layers(&layers);
        assert!(findings
            .iter()
            .any(|f| f.kind == SecretKind::SuspiciousFilename));
    }

    #[test]
    fn skipped_large_file_with_suspicious_name_still_flagged_by_filename_alone() {
        let layers = vec![vec![LayerFile {
            path: "id_rsa".to_string(),
            content: None, // as if skipped for size
            whiteout: None,
        }]];
        let findings = analyze_layers(&layers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SecretKind::SuspiciousFilename);
    }

    #[test]
    fn multiple_layers_multiple_findings_all_attributed_to_correct_layer() {
        let layers = vec![
            vec![file("a.txt", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")],
            vec![file("b.txt", "ordinary content")],
            vec![file("c.txt", "DB_PASSWORD=realvalue123")],
        ];
        let findings = analyze_layers(&layers);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].layer_index, 0);
        assert_eq!(findings[1].layer_index, 2);
    }

    #[test]
    fn non_utf8_content_without_suspicious_filename_is_silently_skipped() {
        let layers = vec![vec![LayerFile {
            path: "data.bin".to_string(),
            content: Some(vec![0xff, 0xfe, 0x00, 0x01]),
            whiteout: None,
        }]];
        let findings = analyze_layers(&layers);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_layers_list_has_no_findings() {
        assert!(analyze_layers(&[]).is_empty());
    }
}
