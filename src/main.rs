use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use imgleak::archive::{read_layer_blob, read_manifest_json};
use imgleak::layer::parse_layer;
use imgleak::manifest::parse_manifest;
use imgleak::scan::analyze_layers;

#[derive(Parser)]
#[command(
    name = "imgleak",
    about = "Scans a saved Docker image's real layer tarballs for secrets baked into any layer"
)]
struct Cli {
    /// Path to a tarball produced by `docker save <image> -o <path>`.
    tarball: PathBuf,

    /// Also fail (exit 1) on filename-only findings (e.g. a `.pem` file
    /// found with unreadable/skipped content), not just findings that
    /// matched actual secret content.
    #[arg(long)]
    strict: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let manifest_json = match read_manifest_json(&cli.tarball) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("imgleak: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let layer_paths = match parse_manifest(&manifest_json) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("imgleak: could not parse manifest.json: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    if layer_paths.is_empty() {
        println!("no layers listed in manifest.json - nothing to scan");
        return ExitCode::SUCCESS;
    }

    let mut layers = Vec::with_capacity(layer_paths.len());
    for (idx, layer_path) in layer_paths.iter().enumerate() {
        let bytes = match read_layer_blob(&cli.tarball, layer_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("imgleak: layer {idx} ({layer_path}): {e:#}");
                return ExitCode::FAILURE;
            }
        };
        let files = match parse_layer(&bytes) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("imgleak: layer {idx} ({layer_path}): could not parse tar: {e:#}");
                return ExitCode::FAILURE;
            }
        };
        layers.push(files);
    }

    let findings = analyze_layers(&layers);

    if findings.is_empty() {
        println!("scanned {} layer(s): no secrets found", layers.len());
        return ExitCode::SUCCESS;
    }

    let mut content_hits = 0;
    let mut filename_hits = 0;
    for f in &findings {
        let hidden_note = match f.hidden_in_later_layer {
            Some(later) => {
                format!(" (hidden by a whiteout in layer {later}, but still present here)")
            }
            None => String::new(),
        };
        println!(
            "[layer {}] {} - {}: {}{}",
            f.layer_index,
            f.path,
            f.kind.label(),
            f.detail,
            hidden_note
        );
        if f.kind.is_content_match() {
            content_hits += 1;
        } else {
            filename_hits += 1;
        }
    }

    println!();
    println!(
        "{} finding(s) across {} layer(s): {} content match(es), {} filename-only",
        findings.len(),
        layers.len(),
        content_hits,
        filename_hits
    );

    let fail = content_hits > 0 || (cli.strict && filename_hits > 0);
    if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
