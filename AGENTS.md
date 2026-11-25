# Project notes for future sessions

## What this is
Dependency-free Python CLI (`fetch_apk.py` + `apkpure/` package) that resolves and
downloads APKs / per-architecture split APKs from APKPure. Built for GitHub Actions.

## bs-dec/ (separate repo, not part of the apkpure tool)
- `bs-dec/` is its **own git repo**, already pushed to `github.com/prexhgaming/bs-dec`
  (public). It is not tracked by this project; do not `git add` it here.
- It fetches the Blood Strike XAPK out of the owner's Telegram chat, unpacks it and
  verifies both ABIs (arm64-v8a + armeabi-v7a). Tests: `cd bs-dec && python -m unittest
  discover -s tests -v` (offline, no network).
- Telegram facts learned the hard way: the cloud Bot API refuses `getFile` for files
  over ~20 MB ("400: Bad Request: file is too big"), so CI starts a self-hosted
  `aiogram/telegram-bot-api` container with `TELEGRAM_LOCAL=1` (needs
  `TELEGRAM_API_ID`/`TELEGRAM_API_HASH` secrets from my.telegram.org).
- **`getUpdates` consumes the updates it returns.** Never rely on a bare scan: a
  second scan (or a local probe) finds nothing. Resolve the `file_id` with
  `forwardMessage` on an explicit message id instead, and delete the forwarded copy.
- Existing secrets in that repo: `TELEGRAM_BOT_TOKEN`. Owner chat id 9117250551.

## How to run / test
- Tests (offline, no network): `python -m unittest discover -s tests -v` (69 tests).
- Resolve without downloading: `python fetch_apk.py --package <pkg> --arch universal`.
- Local rule of thumb: locally run `--mode probe` or `--mode sample` only; full
  `--mode download` is for CI (repo owner asked for this explicitly).
- Python 3.9+ (dev sandbox is 3.12). No requirements.txt by design — stdlib only.

## Pitfalls already hit (don't relearn these)
- **The metadata API knows nothing about ABIs.** A 1.1 MB Blood Strike payload contains
  the strings `arm64`, `armeabi`, `v7a`, `v8a` exactly zero times, and field 7 (sha1) is
  the *same* for every build of an app. One versionCode can have several builds (169 has
  2, 166 has 3) differing only in the descriptor's size/md5/kind, so `parse_versions`
  keeps them all, `--list-versions` lists builds, and `--build N` selects one.
- **Architecture truth = the archive's zip index**, never the metadata: `--detect-abis`
  reports `lib/<abi>/*.so` and `config.<abi>.apk` members over ranged reads.
  `--abi-scan` probes every build of a version *name*; `--require-abi` gates it (exit 3).
  Blood Strike 1.003.650026: codes 169/168 = `armeabi-v7a` only, code **166 build 1 =
  arm64-v8a** (base 50.2 MiB + `config.arm64_v8a.apk` 156.8 MiB ≈ 207 MiB to extract).
- APKMirror is Cloudflare-protected against datacenter IPs: `apkmirror-downloader`
  v2.0.11 (Node, cheerio) got the "cannot be loaded without JavaScript and cookies"
  interstitial from this sandbox, so it cannot run in CI without a proxy.
- `d.apkpure.com` only returns a direct CDN link when the request uses a *mobile*
  browser User-Agent; desktop UA gets an HTML page. See `transport.BROWSER_UA`.
- The metadata API answers in protobuf with no published schema and returns ~1.1 MB.
  Field numbers are mapped in `apkpure/api.py`; checked against live responses.
- A desktop-style `curl` without the API headers gets `INVALID_COMMAND` protobuf.
- `arch=` / `abi=` query params are ignored by the CDN — architecture lives inside
  the `.xapk` bundle as `config.<abi>.apk` entries, read via HTTP range requests.
- When a version has no standalone APK, `/b/APK/` redirects to an Apache/HTML page
  on apkpure.com; detect by content-type, not by status code.
- Signed descriptor URLs expire (~2 days), so never cache them across runs.
- Sandbox policy: shell heredocs are blocked; write helper scripts with write_file.
- The sandbox is memory-tight: probe scripts that touch big payloads get killed.
