# imgleak

Scans a saved Docker image's real layer tarballs for secrets baked into
any layer — including one a later layer only *hides*, not removes. The
classic mistake: `COPY secret.txt .` in one `RUN`/layer, then `RUN rm
secret.txt` in a later one. The final container filesystem looks clean,
but the file's full bytes are still sitting in the earlier layer's tar,
permanently part of the image's history — anyone who pulls the image and
inspects its layers (or just `docker save`s it, like this tool does) can
recover it. `leakscan` (also in this workspace) scans a git diff; this
scans the other place a secret can permanently leak into a shipped
artifact — the image itself.

## Usage

```bash
docker save myimage:latest -o image.tar
imgleak image.tar
imgleak image.tar --strict   # also fail on filename-only findings, not just content matches
```

Exit code `1` if anything is found (content matches always fail; a
filename-only hit like `/etc/shadow` existing only fails with `--strict`).

## How it works

`docker save` produces a tarball containing `manifest.json` (which layer
blobs make up the image, in order) plus one gzipped tar per layer.
`imgleak` reads `manifest.json`, then reads and decompresses **every**
layer's tar independently — not just the final merged filesystem view a
`docker export`/running container would show — and scans each layer's
files for secrets. A file removed in a later layer is recorded via that
layer's whiteout marker (`.wh.<filename>`, Docker's real convention for
"this path is gone as of this layer"), but the earlier layer's copy is
still scanned and reported, with a note that it was later hidden — since
hidden is not the same as gone.

Detection is two-pronged: known-shape content patterns (AWS access key
IDs, PEM private key headers, a naive `password = "..."` assignment, a
contextual `api_key = "..."` assignment — the same category of patterns
`leakscan` uses, written independently for this tool's own content-scan
shape) and suspicious filenames (`.pem`, `.pfx`, `id_rsa`, `.env`,
`shadow`, `.git-credentials`) that are flagged even if their content is
binary/unreadable. Files over 2 MiB are skipped entirely rather than read
into memory — a base OS layer's compiled binaries have no business being
scanned line-by-line.

## Status: built and verified against a real, actually-built Docker image, not just synthetic tar fixtures

- **38 unit tests** (`cargo test --lib`): `manifest.json` parsing
  (multi-tag images correctly de-duplicating shared layers, a malformed
  manifest failing cleanly); layer tar parsing (regular files, whiteout
  markers recognized by the real `.wh.` prefix convention, directories
  and non-regular entries skipped, a file over the 2 MiB cap recorded
  with `content: None` rather than read); every content rule (AWS key,
  private key header, password, contextual API key) plus their
  false-positive guards; suspicious-filename matching; and
  `analyze_layers`' whiteout cross-referencing — a secret in layer 0
  later whited-out in layer 2 is reported once, against layer 0, with
  `hidden_in_later_layer: Some(2)` set correctly.
- **Live-verified against a real, actually-built and actually-saved
  Docker image** — not a hand-constructed fake tarball: built a real
  2-`RUN`-layer image from a real `Dockerfile` (`FROM alpine:3.19`,
  `COPY secret.txt /secret.txt`, `RUN rm /secret.txt`), ran `docker
  build` and `docker save` for real, and pointed the actual compiled
  binary at the real resulting tarball. Result: correctly found the real
  AWS-example-key content in the layer that added `secret.txt`, correctly
  annotated it `(hidden by a whiteout in layer 2, but still present
  here)`, and — an honest finding this wasn't specifically planted for —
  also flagged `etc/shadow` as a suspicious filename in the base
  `alpine:3.19` layer itself (a real file that really exists in that real
  base image, correctly caught by the filename heuristic). Exit code was
  `1`, matching a real "content match found" outcome.

**Not done / deliberately deferred**: OCI image layout (`index.json` +
content-addressed `blobs/` directory with no `manifest.json`) — only the
classic Docker `manifest.json` format `docker save` still writes by
default is parsed; a registry-pulled-then-saved image in pure OCI form
isn't handled. Secrets split across a base64/binary encoding inside a
file aren't decoded before scanning — only plain-text content matches.
No entropy-based fallback detector (unlike `leakscan`'s pattern-free
high-entropy check) — this only catches the same named shapes
`leakscan` catches by pattern, not an arbitrary high-entropy token with
no recognizable prefix.
