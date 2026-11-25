# Project notes for future sessions

## What this is
Dependency-free Python 3.9+ CLI (`fetch_apk.py` + `apkcombo/` package) that
resolves and downloads APKs from APKCombo and verifies the architectures actually
present in the archive. Built for GitHub Actions. Runtime deps: stdlib only;
`analysis/scan_pyrun.py` optionally uses capstone for disassembly (CI installs it).

## How to run
- Probe only (no payload): `python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake --mode probe --detect-abis`
- Full download + ABI gate: `python fetch_apk.py -p com.netease.newspike --slug blood-strike-x-dj-snake --variant apk --mode download --require-abi arm64-v8a,armeabi-v7a`
- Version gate (mirror must serve this build): add `--expect-version 169`
- Native lib scan (CI `scan-libs.yml`): `python analysis/scan_pyrun.py downloads/<file>.apk --abi arm64-v8a --json reports/out.json`
- Cross-build function match: `python analysis/scan_pyrun.py app.apk --abi armeabi-v7a --match-lib local-libGame.so`
- Local rule: big downloads belong to CI, not the sandbox.

## Scanner evidence (analysis/scan_pyrun.py)
Prints/records: pyrun symbols and imports, all dynamic imports, `DT_NEEDED`, every
section with entropy, a marker table (`PyRun_`, `PyObject_`, `libpython`, `il2cpp`...),
function candidates, and matches between two libraries (sha256 over the first 96
bytes of each function, so a local build can be compared with the mirror's).
Entropy >= 7.85 warns packed/encrypted; 7.5 is normal for dense ARM code.

## Architecture truth
APKCombo's page claims ABIs, but the authoritative source is the archive's zip
index (`lib/<abi>/*.so`, `config.<abi>.apk`). `--detect-abis` reports it,
`--require-abi` gates on it (exit 3). The universal Blood Strike APK carries both
`arm64-v8a` and `armeabi-v7a`; the `.xapk` variant of the same page is 32-bit only.

## APKCombo download flow
App page -> `.../download/apk` page -> hidden `soqplay_download_file` token per
variant -> POST that token (same page) -> 303 to an `apkcombo-transfer*.workers.dev`
URL -> file. Tokens/URLs are short lived: resolve fresh every run, never cache.

## Pitfalls
- The APKCombo "Blood Strike x DJ SNAKE" page serves **versionCode 17** (665.78 MB),
  not the 1.003.650026/169 build installed on the device; its `libGame.so` is
  72 MB (v7a) vs 84 MB on the device. Use `--expect-version` to refuse a build the
  mirror has not published instead of silently comparing mismatched files.
- `apkcombo/__init__.py` must not re-export a name that collides with a submodule
  (`download` was exported as a function and shadowed `apkcombo.download`, which
  broke `download.Progress`). It is exported as `download_file` now.
- Ranged reads are fine for the zip index, never for judging a payload: CI
  downloads the whole APK and reads members with `zipfile` (CRC-checked).
- The APKCombo build can differ from the one installed on a device, so lib
  comparisons must report a mismatch instead of failing the job.
- Shell heredocs are blocked in this sandbox; use write_file for scripts.
