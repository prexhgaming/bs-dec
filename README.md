# APKPure APK / split-APK fetcher

A dependency-free Python 3.9+ tool that resolves a package on APKPure, finds the
release you want, and pulls **the exact file you asked for** — the standalone
APK, a whole `.xapk` bundle, or a single per-architecture split out of that
bundle — without downloading the parts you don't need.

It is built for GitHub Actions: probe mode resolves and verifies a plan in a
second, sample mode proves the pipeline on a tiny transfer, and only the CI job
runs full downloads. Range requests + `.part` files make long transfers
resumable.

No `pip install` step, no third-party packages: `urllib` and `zipfile`-level
parsing of the remote index only.

## Quick start

```bash
# 1) What would be downloaded? (headers + remote zip index only, no payload)
python fetch_apk.py --package com.netease.newspike --version-code 169 --arch universal

# 2) Prove the pipeline on ~256 KiB instead of 50 MB
python fetch_apk.py --package com.netease.newspike --version-code 169 --mode sample

# 3) Real transfer (this is what CI runs)
python fetch_apk.py --package com.netease.newspike --version-code 169 \
    --mode download --verify --resume

# Per-architecture split + the base APK it needs
python fetch_apk.py --package com.netease.newspike --version-code 169 \
    --arch armeabi-v7a --with-base --mode download --verify

# Everything the bundle offers (base + each ABI split), or the whole bundle
python fetch_apk.py --package com.xapi.polydev --arch all --mode download
python fetch_apk.py --package com.xapi.polydev --variant xapk --mode download
```

`--help` lists every flag; `--list-versions` and `--list-variants` show what is
available before you commit to a download.

## How architectures actually work on APKPure

APKPure publishes two shapes of release per version, and the CDN **silently
ignores** `arch=` / `abi=` query parameters (verified: identical bytes and
identical `Content-Length` for `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`,
`arm64_v8a`, `64`, `32`). So an architecture is not a URL parameter — it is a
member of the bundle:

| You ask for | You get | Blood Strike 169 footprint |
| --- | --- | --- |
| `--arch universal` | the standalone universal APK (all ABIs inside) | 50.3 MiB |
| `--arch armeabi-v7a` | `config.armeabi_v7a.apk` from the bundle | 111.8 MiB |
| `--arch arm64-v8a` | clear error: this bundle has no such split | n/a for 169 |
| `--arch all` | base APK + every ABI split | 162.1 MiB |
| `--variant xapk` | the complete `.xapk` archive | 635.8 MiB |
| `--with-assets` | adds bulk asset packs (`base_mpk.apk`) | +470.1 MiB |

Measured on `com.netease.newspike` (package `com.netease.newspike`, versionCode
169, versionName `1.003.650026`): universal APK 52,770,316 B; XAPK
666,673,555 B; `config.armeabi_v7a.apk` 117,250,407 B; `base_mpk.apk`
492,933,672 B.

Two consequences worth knowing:

* **Downloading one split beats downloading the bundle.** Fetching
  `config.armeabi_v7a.apk` out of a 635.8 MiB XAPK transfers 111.8 MiB, not
  635.8 MiB, because the tool reads the zip central directory (a few KiB at the
  end of the file) and then requests only that entry's byte range.
* **An app may ship no split for your ABI at all.** Blood Strike 169's bundle
  contains *only* `config.armeabi_v7a.apk` — requesting `--arch arm64-v8a`
  there fails with the list of ABIs that do exist. The universal APK is the
  practical choice for that release.

`--arch all` deliberately means *every architecture*, not *the whole bundle*:
it adds the base APK and each ABI split but leaves the hundreds-of-MB asset
packs and locale/density splits behind (the plan prints a note when such splits
exist). Use `--variant xapk` when you want the archive exactly as published.

### One version number, several versionCodes (where the 64-bit build hides)

A version *number* is often published under several versionCodes, and the
metadata never says which architecture a build carries: a 1.1 MB payload for
Blood Strike contains the strings `arm64`, `armeabi`, `v7a` and `v8a` **zero**
times, and the app-level sha1 (field 7) is identical for every build. The
architecture only exists *inside* the archive, so `--abi-scan` reads each build's
zip index — a few KiB each, no payload — and reports what it found:

```bash
python fetch_apk.py --package com.netease.newspike \
  --version-name 1.003.650026 --abi-scan --require-abi arm64-v8a,armeabi-v7a
```

Live result (all four builds claim version name `1.003.650026`):

| versionCode | build size | ABI in the bundle |
| --- | --- | --- |
| 169 | 635.8 / 634.4 MiB | `armeabi-v7a` (32-bit) |
| 168 | 622.6 MiB | `armeabi-v7a` (32-bit) |
| 166 | 665.2 / 664.7 MiB | **`arm64-v8a` (64-bit)** |
| 166 | 622.4 MiB | `armeabi-v7a` (32-bit) |

So the newest versionCode is 32-bit only, while the 64-bit package of the *same
version number* sits on versionCode **166**. Extracting just its 64-bit parts
transfers 207.0 MiB (`base` 50.2 MiB + `config.arm64_v8a.apk` 156.8 MiB) instead
of 665 MB:

```bash
python fetch_apk.py --package com.netease.newspike --version-code 166 --build 1 \
  --arch arm64-v8a --variant splits --mode download   # --arch all = base + split
```

`--require-abi` turns that answer into a gate: it fails with the verification
exit code when the archive — or, in `--abi-scan`, *any* build of the version
name — lacks a requested ABI, so CI does not have to parse output text.

## Modes

| Mode | Traffic | Purpose |
| --- | --- | --- |
| `probe` (default) | headers + zip index only | resolve, sanity-check, print the plan |
| `sample` | `--sample-bytes` per file (default 256 KiB) | prove connectivity/redirects/zip layout without a full download |
| `download` | the real files | CI and production use |

Exit codes: `0` success, `1` resolution/network failure, `2` usage error,
`3` verification failure (size or hash mismatch), `130` interrupted.

## Where files land

```
downloads/<package>/<versionName>/<arch>/
├── com.netease.newspike_1.003.650026_universal.apk
└── manifest.json
```

`manifest.json` is the machine-readable record for the run: app metadata,
the resolved plan (including each file's URL, expected size, sha1 and, for
splits, the bundle entry name/offset/CRC), and per-file results with sizes,
sha1/sha256/md5/crc32, `attempts` and `resumed_from`. `--json` prints the same
document to stdout (human output then moves to stderr), which is what the
workflow consumes.

Partial transfers live next to their target as `<name>.part`; `--resume`
continues them, and a `.part` is never renamed to the final name until size and
hashes check out.

## GitHub Actions

`.github/workflows/download-apk.yml` (manual `workflow_dispatch`, plus the test
workflow) takes a package, versionCode, architecture and variant, prints the
resolved plan into the run summary, downloads (with resume caching of `.part`
files), verifies, and uploads the files as an artifact.

```yaml
- run: python fetch_apk.py --arch armeabi-v7a --with-base --mode download --verify --json
```

Choosing `arch: all` fans out over a matrix (`universal`, `arm64-v8a`,
`armeabi-v7a`) so each ABI lands in its own artifact.

## Verified behaviour and limitations

Facts confirmed against the live service while building this (they are the
reason a couple of design choices look unusual):

* **The metadata API is protobuf with no published schema.**
  `api.pureapk.com/m/v3/cms/app_version` returns ~1.1 MB of protobuf; it is
  decoded generically (`apkpure/pbwire.py`) and matched by field number.
  `--lang/--country/--api-abi` are just headers, and the returned bundle is the
  same for every advertised ABI.
* **The download descriptor carries a signed, expiring URL.** Field 24 of the
  version entry holds `{sha1, size, kind: XAPK, url}` where the URL is signed
  with an `at=` expiry a couple of days out, so the URL must be re-resolved on
  every run (the tool always does; `--verify` checks that sha1 against the
  bytes).
* **The signed bundle and the stable CDN bundle are not the same file.** For
  Blood Strike 169 the descriptor served a 666,673,555 B archive with 23
  entries while `d.apkpure.com/b/XAPK/...` served 665,214,022 B with 7. The
  descriptor URL is preferred (more splits, and its sha1 is verifiable), the
  CDN URL is the fallback.
* **Split-only releases exist.** When there is no standalone APK, the
  `/b/APK/` endpoint redirects to an HTML page on `apkpure.com`; the tool
  detects the non-zip content type and reports which ABIs the bundle *does*
  offer (e.g. `com.xapi.polydev`) instead of failing with a bare HTTP error.
* **Zip64 archives are rejected** with an explicit message (none of the apps
  tested use them); deflated bundle entries, if any, are inflated in memory and
  capped at 320 MB.
* **Be a good citizen:** the tool makes one request per plan, retries with
  jittered backoff, and resumes instead of restarting. Keep CI runs infrequent
  and use the artifacts rather than re-downloading. Download and use these
  packages in line with APKPure's terms and the app's own licence.

## Tests

```bash
python -m unittest discover -s tests -v
```

69 tests, fully offline: hand-built protobuf payloads, header parsing, archive
name sanitising, architecture normalisation/detection, build selection
(`--build`, several builds per versionCode), ABI reporting from archive entry
names, and a remote-zip reader driven by an injected local reader (including
CRC-mismatch and zip64 error paths).

Byte-level correctness of the interesting part — ranged extraction — can be
re-checked against a real download:

```bash
python fetch_apk.py --package com.xapi.polydev --arch arm64-v8a --with-base --mode download
python - <<'PY'
import zipfile, hashlib, pathlib
root = pathlib.Path("downloads/com.xapi.polydev/1.0.0")
with zipfile.ZipFile(root / "all" / "com.xapi.polydev_1.0.0.xapk") as zf:
    for name in ("com.xapi.polydev.apk", "config.arm64_v8a.apk"):
        ours = hashlib.sha1((root / "arm64-v8a" / name).read_bytes()).hexdigest()
        print(name, ours == hashlib.sha1(zf.read(name)).hexdigest())
PY
```

## Layout

```
fetch_apk.py             entry point (python fetch_apk.py --help)
apkpure/pbwire.py        protobuf wire reader
apkpure/transport.py     redirects, ranged reads, probes, header parsing
apkpure/api.py           metadata endpoint + version/descriptor parsing
apkpure/zipindex.py      remote zip index + single-entry ranged extraction
apkpure/downloader.py    resumable downloads, hashing, progress
apkpure/variants.py      architecture normalisation + plan builders
apkpure/cli.py           argument parsing, modes, manifest, reporting
apkpure/errors.py        exception hierarchy and exit-code mapping
tests/test_apkpure.py    offline test suite
```
