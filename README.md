# micro-dec

Dependency-free Python 3.9+ CLI that resolves and downloads APKs from APKCombo
and verifies the architectures actually present in the archive. Built for
GitHub Actions; only `workflow_dispatch` runs full downloads.

## Quick start

```bash
# Probe only (headers + remote zip index, no payload)
python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake --mode probe --detect-abis

# Full download + ABI gate (this is what CI runs)
python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake \
    --mode download --require-abi arm64-v8a,armeabi-v7a
```

## How it works

APKCombo publishes a download page per app. The tool:

1. Parses the app page and the "download APK" form, then exchanges the form
   token for the real CDN URL (HTTP 303).
2. Reads the remote zip central directory with HTTP range requests (a few KiB)
   to list `lib/<abi>/*.so` and `config.<abi>.apk` members — that is the
   authoritative source of which ABIs the file carries.
3. Streams the file straight to disk while hashing it (sha256/sha1/md5), then
   gates on `--require-abi` (exit code 3 on mismatch).

`--detect-abis` prints the ABI report; `--use-page-sha256` also checks the
file against the SHA-256 published on the APKCombo page.

## GitHub Actions

`.github/workflows/fetch-apk.yml` is a `workflow_dispatch` job. Defaults pull
the universal Blood Strike APK and fail unless `arm64-v8a` and `armeabi-v7a`
are both present in the archive. It uploads the APK (plus SHA256SUMS.txt and the
log) as an artifact.

Locally, run `--mode probe` or `--mode sample` only; full `--mode download`
belongs to CI.
