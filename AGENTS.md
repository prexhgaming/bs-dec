# Project notes for future sessions

## What this is
Dependency-free Python 3.9+ CLI (`fetch_apk.py` + `apkcombo/` package) that
resolves and downloads APKs from APKCombo and verifies the architectures actually
present in the archive. Built for GitHub Actions. No third-party dependencies.

## How to run
- Probe only (no payload): `python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake --mode probe --detect-abis`
- Full download + ABI gate (CI): `python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake --mode download --require-abi arm64-v8a,armeabi-v7a`
- Python 3.9+ (sandbox is 3.12). No requirements.txt by design — stdlib only.
- Local rule: run `--mode probe` or `--mode sample` locally; full `--mode download` is for CI.

## Architecture truth
APKCombo's page claims ABIs, but the authoritative source is the archive's zip
index (`lib/<abi>/*.so` and `config.<abi>.apk`), read via HTTP range requests.
`--detect-abis` reports it; `--require-abi` gates on it (exit 3 on mismatch).
The universal Blood Strike APK contains both `arm64-v8a` and `armeabi-v7a`.

## Pitfalls
- Shell heredocs are blocked in this sandbox; write helper scripts with write_file.
- The sandbox is memory-tight; probes that touch big payloads get killed.
- Do not run full downloads locally.
