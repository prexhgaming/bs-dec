"""Offline unit tests for the APKPure tooling.

Everything here runs without network access: the protobuf payload is built by
hand, the zip index is served from a local temp file through the injectable
reader, and the HTTP-only code paths are exercised through their pure helpers.
Run with ``python -m unittest discover -s tests -v`` or ``python -m pytest``.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apkpure import abidetect, api, cli, pbwire, transport, variants  # noqa: E402
from apkpure.downloader import hash_bytes, hash_file  # noqa: E402
from apkpure.errors import (  # noqa: E402
    VariantError,
    VerificationError,
    ZipIndexError,
)
from apkpure.pbwire import ProtobufError  # noqa: E402
from apkpure.zipindex import RemoteZip, local_file_reader  # noqa: E402

PACKAGE = "com.netease.newspike"


# ---------------------------------------------------------------------------
# helpers to encode protobuf by hand (the API has no published schema)
# ---------------------------------------------------------------------------


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_field(number: int, value) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return encode_varint((number << 3) | 2) + encode_varint(len(value)) + value
    return encode_varint(number << 3) + encode_varint(value)


def encode_entry(overrides=None, *, size: int = 665214022) -> bytes:
    """Build a version entry shaped like the real API response."""
    defaults = {
        api.F_NAME: "Blood Strike",
        api.F_DISPLAY_NAME: "Blood Strike",
        api.F_PACKAGE: PACKAGE,
        api.F_VERSION_CODE: "169",
        api.F_VERSION_NAME: "1.003.650026",
        api.F_SHA1: "0a09599f51d2136f2f30f2ddf740e73f38f0f730",
        api.F_DEVELOPER: "NetEase Games",
        api.F_CATEGORY: "Action",
        api.F_UPDATED: "2026-11-11T04:16:53+00:00",
        api.F_MD5: "7c75d464b8c9f25df15d4c22b6b6d87f",
    }
    fields = dict(defaults)
    if overrides:
        fields.update(overrides)
    descriptor = (
        encode_field(api.D_LABEL, "Blood Strike")
        + encode_field(api.D_SHA1, "a5e14dbe594c340c7dd24150e81ff453ea02be36")
        + encode_field(api.D_SIZE, size)
        + encode_field(api.D_KIND, "XAPK")
        + encode_field(api.D_URL, "https://download.pureapk.com/b/XAPK/bundle?token=abc")
    )
    fields[api.F_DOWNLOAD] = descriptor
    payload = b"".join(encode_field(number, value) for number, value in fields.items())
    return payload


def wrap_entry(entry: bytes) -> bytes:
    """Nest the entry the way the API does: 1 -> 7 -> repeated 2 -> 3 -> 2."""
    inner = encode_field(3, entry)
    repeated = encode_field(2, inner)
    return encode_field(1, encode_field(7, repeated))


# ---------------------------------------------------------------------------
# pbwire
# ---------------------------------------------------------------------------


class VarintTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        for value in (0, 1, 127, 128, 300, 2**31, 665214022):
            encoded = encode_varint(value)
            decoded, pos = pbwire.read_varint(encoded, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(pos, len(encoded))

    def test_truncated_varint_raises(self) -> None:
        with self.assertRaises(ProtobufError):
            pbwire.read_varint(b"\x80\x80", 0)

    def test_overlong_varint_raises(self) -> None:
        with self.assertRaises(ProtobufError):
            pbwire.read_varint(b"\xff" * 12, 0)


class ParseTests(unittest.TestCase):
    def test_parse_and_accessors(self) -> None:
        payload = encode_field(1, "hello") + encode_field(2, 42)
        fixed64 = encode_varint((3 << 3) | 1) + struct.pack("<d", 3.5)
        payload += fixed64
        fields = pbwire.parse(payload)
        self.assertEqual(pbwire.get_text(payload, 1), "hello")
        self.assertEqual(pbwire.get_int(payload, 2), 42)
        double = [f for f in fields if f.number == 3][0]
        self.assertAlmostEqual(double.double(), 3.5)

    def test_missing_field_returns_default(self) -> None:
        self.assertIsNone(pbwire.get_text(b"", 9))
        self.assertEqual(pbwire.get_int(b"", 9, 7), 7)

    def test_truncated_length_field_raises(self) -> None:
        with self.assertRaises(ProtobufError):
            pbwire.parse(encode_varint((1 << 3) | 2) + encode_varint(10) + b"abc")

    def test_invalid_wire_type_raises(self) -> None:
        with self.assertRaises(ProtobufError):
            pbwire.parse(encode_varint((1 << 3) | 3))

    def test_messages_walks_nested_levels(self) -> None:
        nested = encode_field(1, encode_field(2, encode_field(3, b"deep")))
        found = [m for m in pbwire.messages(nested)]
        self.assertTrue(any(b"deep" in item for item in found))

    def test_messages_ignores_garbage(self) -> None:
        self.assertLessEqual(len(list(pbwire.messages(b"\xff\xff\xff"))), 1)


# ---------------------------------------------------------------------------
# transport helpers
# ---------------------------------------------------------------------------


class ContentRangeTests(unittest.TestCase):
    def test_full_span(self) -> None:
        self.assertEqual(transport.parse_content_range("bytes 0-1023/52770316"), (0, 1023, 52770316))

    def test_offset_span(self) -> None:
        self.assertEqual(transport.parse_content_range("bytes 500-999/1000"), (500, 999, 1000))

    def test_unknown_total(self) -> None:
        self.assertEqual(transport.parse_content_range("bytes 0-99/*"), (0, 99, -1))

    def test_garbage(self) -> None:
        for value in (None, "", "items 0-1/2", "bytes abc"):
            self.assertIsNone(transport.parse_content_range(value))


class ContentDispositionTests(unittest.TestCase):
    def test_quoted_plus_encoded(self) -> None:
        value = 'attachment; filename="Blood+Strike+x+DJ+SNAKE_1.003.650026_APKPure.apk"'
        self.assertEqual(
            transport.parse_content_disposition(value),
            "Blood Strike x DJ SNAKE_1.003.650026_APKPure.apk",
        )

    def test_rfc5987(self) -> None:
        value = "attachment; filename*=UTF-8''PolyDev%20AI%20Coding%20Agent.xapk"
        self.assertEqual(transport.parse_content_disposition(value), "PolyDev AI Coding Agent.xapk")

    def test_unquoted(self) -> None:
        self.assertEqual(transport.parse_content_disposition("filename=app.apk"), "app.apk")

    def test_absent(self) -> None:
        self.assertIsNone(transport.parse_content_disposition(None))
        self.assertIsNone(transport.parse_content_disposition("attachment"))


class SanitizeTests(unittest.TestCase):
    def test_strips_path_traversal(self) -> None:
        self.assertEqual(transport.sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(transport.sanitize_filename("C:\\windows\\evil.apk"), "evil.apk")
        self.assertEqual(transport.sanitize_filename("/a/b/../c.apk"), "c.apk")

    def test_rejects_empty_results(self) -> None:
        self.assertIsNone(transport.sanitize_filename("..."))
        self.assertIsNone(transport.sanitize_filename(""))

    def test_truncates_long_names_keeping_suffix(self) -> None:
        name = "x" * 400 + ".apk"
        cleaned = transport.sanitize_filename(name)
        self.assertIsNotNone(cleaned)
        self.assertLessEqual(len(cleaned or ""), transport.MAX_FILENAME_LENGTH)
        self.assertTrue((cleaned or "").endswith(".apk"))


class HumanFormatTests(unittest.TestCase):
    def test_sizes(self) -> None:
        self.assertEqual(transport.human_size(512), "512 B")
        self.assertEqual(transport.human_size(1024), "1.0 KiB")
        self.assertEqual(transport.human_size(52770316), "50.3 MiB")
        self.assertEqual(transport.human_size(None), "unknown")

    def test_durations(self) -> None:
        self.assertEqual(transport.human_duration(3.25), "3.2s")
        self.assertEqual(transport.human_duration(64), "1m 04s")


class RequestHeaderTests(unittest.TestCase):
    def test_defaults_and_overrides(self) -> None:
        headers = transport.request_headers({"Range": "bytes=0-1"})
        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["Range"], "bytes=0-1")

    def test_none_removes_header(self) -> None:
        headers = transport.request_headers({"Accept": None})
        self.assertNotIn("Accept", headers)


# ---------------------------------------------------------------------------
# api
# ---------------------------------------------------------------------------


class MetadataTests(unittest.TestCase):
    def test_parse_single_entry(self) -> None:
        payload = wrap_entry(encode_entry())
        versions = api.parse_versions(payload, PACKAGE)
        self.assertEqual(len(versions), 1)
        version = versions[0]
        self.assertEqual(version.version_code, 169)
        self.assertEqual(version.version_name, "1.003.650026")
        self.assertEqual(version.app_name, "Blood Strike")
        self.assertEqual(version.apk_sha1, "0a09599f51d2136f2f30f2ddf740e73f38f0f730")
        self.assertEqual(version.apk_md5, "7c75d464b8c9f25df15d4c22b6b6d87f")
        self.assertEqual(version.developer, "NetEase Games")

    def test_descriptor_is_decoded(self) -> None:
        payload = wrap_entry(encode_entry())
        descriptor = api.parse_versions(payload, PACKAGE)[0].descriptor
        self.assertIsNotNone(descriptor)
        assert descriptor is not None
        self.assertEqual(descriptor.kind, "XAPK")
        self.assertEqual(descriptor.size, 665214022)
        self.assertEqual(descriptor.sha1, "a5e14dbe594c340c7dd24150e81ff453ea02be36")
        self.assertTrue(descriptor.url.startswith("https://download.pureapk.com/"))

    def test_other_packages_are_ignored(self) -> None:
        payload = wrap_entry(encode_entry({api.F_PACKAGE: "com.example.other"}))
        with self.assertRaises(api.MetadataError):
            api.parse_versions(payload, PACKAGE)

    def test_invalid_hashes_are_dropped(self) -> None:
        payload = wrap_entry(encode_entry({api.F_SHA1: "not-a-hash", api.F_MD5: "12345"}))
        version = api.parse_versions(payload, PACKAGE)[0]
        self.assertIsNone(version.apk_sha1)
        self.assertIsNone(version.apk_md5)

    def test_select_version_by_code_and_name(self) -> None:
        versions = api.parse_versions(
            wrap_entry(encode_entry())
            + wrap_entry(encode_entry({api.F_VERSION_CODE: "170", api.F_VERSION_NAME: "1.003.650027"})),
            PACKAGE,
        )
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0].version_code, 170, "newest first")
        self.assertEqual(api.select_version(versions).version_code, 170)
        self.assertEqual(api.select_version(versions, version_code=169).version_code, 169)
        self.assertEqual(api.select_version(versions, version_name="1.003.650026").version_code, 169)

    def test_select_version_errors(self) -> None:
        versions = api.parse_versions(wrap_entry(encode_entry()), PACKAGE)
        with self.assertRaises(api.VersionNotFound):
            api.select_version(versions, version_code=999)
        with self.assertRaises(api.VersionNotFound):
            api.select_version(versions, version_name="nope")

    def test_urls(self) -> None:
        self.assertIn("package_name=com.netease.newspike", api.metadata_url(PACKAGE))
        self.assertEqual(
            api.cdn_url(PACKAGE, "APK", 169),
            "https://d.apkpure.com/b/APK/com.netease.newspike?versionCode=169",
        )
        self.assertEqual(
            api.cdn_url(PACKAGE, "xapk"),
            "https://d.apkpure.com/b/XAPK/com.netease.newspike",
        )

    def test_invalid_package_is_rejected(self) -> None:
        with self.assertRaises(api.MetadataError):
            api.fetch_metadata("not a package", timeout=0.1, retries=1)


# ---------------------------------------------------------------------------
# variants
# ---------------------------------------------------------------------------


class ArchNormalizationTests(unittest.TestCase):
    def test_aliases(self) -> None:
        expected = {
            "arm64": "arm64-v8a",
            "ARM64-V8A": "arm64-v8a",
            "aarch64": "arm64-v8a",
            "64": "arm64-v8a",
            "32": "armeabi-v7a",
            "armv7": "armeabi-v7a",
            "armeabi_v7a": "armeabi-v7a",
            "x64": "x86_64",
            "amd64": "x86_64",
            "i686": "x86",
            "universal": "universal",
            "all": "all",
        }
        for raw, canonical in expected.items():
            self.assertEqual(variants.normalize_arch(raw), canonical, raw)

    def test_unknown_arch_explains_choices(self) -> None:
        with self.assertRaises(VariantError) as ctx:
            variants.normalize_arch("mips")
        self.assertIn("arm64-v8a", str(ctx.exception))


class AbiDetectionTests(unittest.TestCase):
    def test_config_split_names(self) -> None:
        cases = {
            "config.arm64_v8a.apk": "arm64-v8a",
            "config.armeabi_v7a.apk": "armeabi-v7a",
            "config.x86.apk": "x86",
            "config.x86_64.apk": "x86_64",
        }
        for name, expected in cases.items():
            self.assertEqual(variants.detect_abi(name), expected, name)

    def test_arm64_wins_over_arm(self) -> None:
        self.assertEqual(variants.detect_abi("config.arm64_v8a.apk"), "arm64-v8a")
        self.assertEqual(variants.detect_abi("config.armeabi_v7a.apk"), "armeabi-v7a")

    def test_x86_64_wins_over_x86(self) -> None:
        self.assertEqual(variants.detect_abi("split_config.x86_64.apk"), "x86_64")
        self.assertEqual(variants.detect_abi("split_config.x86.apk"), "x86")

    def test_non_abi_entries(self) -> None:
        for name in (
            "com.netease.newspike.apk",
            "config.en.apk",
            "config.mdpi.apk",
            "base_mpk.apk",
            "icon.png",
            "manifest.json",
        ):
            self.assertIsNone(variants.detect_abi(name), name)

    def test_split_classification(self) -> None:
        self.assertTrue(variants.is_config_split("config.arm64_v8a.apk"))
        self.assertFalse(variants.is_config_split("base_mpk.apk"))
        self.assertTrue(variants.is_asset_split("base_mpk.apk"))
        self.assertFalse(variants.is_asset_split("config.en.apk"))


class NamingTests(unittest.TestCase):
    def test_default_names_include_version(self) -> None:
        version = api.parse_versions(wrap_entry(encode_entry()), PACKAGE)[0]
        self.assertEqual(
            variants.default_universal_name(PACKAGE, version),
            f"{PACKAGE}_1.003.650026_universal.apk",
        )
        self.assertEqual(
            variants.default_bundle_name(PACKAGE, version),
            f"{PACKAGE}_1.003.650026.xapk",
        )

    def test_names_without_metadata(self) -> None:
        self.assertEqual(variants.default_universal_name(PACKAGE, None), f"{PACKAGE}_universal.apk")


class BuildSelectionTests(unittest.TestCase):
    """One versionCode has several builds: the parser keeps them, --build picks."""

    def _build(self, code: int, size: int, md5: str):
        return api.AppVersion(
            package=PACKAGE,
            app_name="Blood Strike",
            version_code=code,
            version_name="1.003.650026",
            apk_md5=md5,
            descriptor=api.DownloadDescriptor(
                url=f"https://download.pureapk.com/b/XAPK/{code}?size={size}",
                kind="XAPK",
                size=size,
            ),
        )

    def test_two_builds_of_one_version_are_kept(self) -> None:
        payload = wrap_entry(encode_entry(size=666673555)) + wrap_entry(
            encode_entry({api.F_MD5: "a" * 32}, size=665214022)
        )
        builds = api.parse_versions(payload, PACKAGE)
        self.assertEqual(len(builds), 2, "both builds of versionCode 169 survive")
        self.assertEqual([item.build_size for item in builds], [666673555, 665214022])
        self.assertEqual(len(api.builds_for(builds, 169)), 2)

    def test_identical_duplicate_entries_are_collapsed(self) -> None:
        payload = wrap_entry(encode_entry()) + wrap_entry(encode_entry())
        self.assertEqual(len(api.parse_versions(payload, PACKAGE)), 1)

    def test_builds_for_a_missing_version_is_empty(self) -> None:
        builds = api.parse_versions(wrap_entry(encode_entry()), PACKAGE)
        self.assertEqual(api.builds_for(builds, 999), [])

    def test_pick_build_defaults_to_the_first(self) -> None:
        builds = [self._build(169, 666673555, "b" * 32), self._build(169, 665214022, "c" * 32)]
        chosen = cli.pick_build(builds, builds[0], argparse.Namespace(build=1))
        self.assertEqual(chosen.build_size, 666673555)

    def test_pick_build_can_reach_the_smaller_build(self) -> None:
        builds = [self._build(169, 666673555, "b" * 32), self._build(169, 665214022, "c" * 32)]
        chosen = cli.pick_build(builds, builds[0], argparse.Namespace(build=2))
        self.assertEqual(chosen.build_size, 665214022)

    def test_pick_build_out_of_range_explains_itself(self) -> None:
        builds = [self._build(169, 666673555, "b" * 32)]
        with self.assertRaises(api.VersionNotFound) as ctx:
            cli.pick_build(builds, builds[0], argparse.Namespace(build=2))
        self.assertIn("--list-versions", str(ctx.exception))


class VersionNameLookupTests(unittest.TestCase):
    """A version *number* maps to several versionCodes."""

    def _payload(self) -> bytes:
        return (
            wrap_entry(encode_entry(size=666673555))
            + wrap_entry(encode_entry({api.F_VERSION_CODE: "168"}, size=652850885))
            + wrap_entry(
                encode_entry({api.F_VERSION_CODE: "166"}, size=697009040)
            )
            + wrap_entry(
                encode_entry(
                    {api.F_VERSION_CODE: "164", api.F_VERSION_NAME: "1.003.650025"},
                    size=699581328,
                )
            )
        )

    def test_every_code_of_one_name_is_returned(self) -> None:
        versions = api.parse_versions(self._payload(), PACKAGE)
        found = api.versions_by_name(versions, "1.003.650026")
        self.assertEqual([item.version_code for item in found], [169, 168, 166])
        self.assertEqual(found[0].build_size, 666673555, "newest code first")
        self.assertEqual(api.versions_by_name(versions, "1.003.650025")[0].version_code, 164)
        self.assertEqual(api.versions_by_name(versions, "nope"), [])

    def test_scan_reports_abis_per_code_and_gates_on_required(self) -> None:
        versions = api.parse_versions(self._payload(), PACKAGE)
        args = cli.build_parser().parse_args(
            ["--package", PACKAGE, "--version-name", "1.003.650026", "--abi-scan",
             "--require-abi", "arm64-v8a,armeabi-v7a"]
        )
        reporter = cli.Reporter(quiet=True, verbose=False, json_mode=False)

        def fake_probe(url, **kwargs):
            # The 64-bit build only exists for versionCode 166, which is exactly
            # the situation a version-name-wide search is meant to uncover.
            sizes = {
                666673555: ["lib/armeabi-v7a/libUE4.so"],
                652850885: ["lib/armeabi-v7a/libUE4.so"],
                697009040: ["lib/arm64-v8a/libUE4.so", "lib/armeabi-v7a/libUE4.so"],
                699581328: ["config.armeabi_v7a.apk"],
            }
            names = sizes.get(kwargs.get("size"), [])
            return abidetect.analyse_names(url, 1, names)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                cli.scan_version_abis(PACKAGE, versions, args, reporter, probe=fake_probe), 0
            )

            strict = cli.build_parser().parse_args(
                ["--package", PACKAGE, "--version-name", "1.003.650025", "--abi-scan",
                 "--require-abi", "arm64-v8a"]
            )
            with self.assertRaises(VerificationError) as ctx:
                cli.scan_version_abis(PACKAGE, versions, strict, reporter, probe=fake_probe)
        self.assertIn("arm64-v8a", str(ctx.exception))

    def test_scan_without_metadata_is_refused(self) -> None:
        code = cli.main(["--package", PACKAGE, "--abi-scan", "--no-api", "--version-code", "169", "--quiet"])
        self.assertEqual(code, cli.EXIT_FAILURE)


class BundleAbiReportTests(unittest.TestCase):
    """The ABI answer comes from the archive index, never from the metadata."""

    def test_lib_directories_are_detected(self) -> None:
        report = abidetect.analyse_names(
            "https://example.invalid/x.xapk",
            1000,
            [
                "com.example.apk",
                "lib/arm64-v8a/libc++_shared.so",
                "lib/arm64-v8a/libUE4.so",
                "lib/armeabi-v7a/libc++_shared.so",
                "assets/whatever.bin",
            ],
        )
        self.assertEqual(report.abi_names, ["arm64-v8a", "armeabi-v7a"])
        self.assertEqual(report.abis["arm64-v8a"].so_files, 2)
        self.assertEqual(report.abis["arm64-v8a"].bitness, 64)
        self.assertEqual(report.abis["armeabi-v7a"].bitness, 32)
        self.assertTrue(report.has("arm64"), "aliases are accepted")
        self.assertEqual(report.missing(["arm64-v8a", "x86_64"]), ["x86_64"])

    def test_split_names_are_detected(self) -> None:
        report = abidetect.analyse_names(
            "https://example.invalid/x.xapk",
            1000,
            [
                "com.example.apk",
                "config.arm64_v8a.apk",
                "config.armeabi_v7a.apk",
                "config.en.apk",
                "config.mdpi.apk",
                "icon.png",
            ],
        )
        self.assertEqual(report.abi_names, ["arm64-v8a", "armeabi-v7a"])
        self.assertEqual(len(report.abis["arm64-v8a"].splits), 1)
        self.assertEqual(report.unlabelled_apks, ("com.example.apk",))

    def test_unknown_lib_directory_is_reported_not_guessed(self) -> None:
        report = abidetect.analyse_names(
            "https://example.invalid/x.apk",
            10,
            ["lib/mips64/libx.so", "lib/arm64-v8a/liby.so"],
        )
        self.assertEqual(report.unknown_arches, ("mips64",))
        self.assertEqual(report.abi_names, ["arm64-v8a"])

    def test_apk_without_native_libraries(self) -> None:
        report = abidetect.analyse_names(
            "https://example.invalid/x.apk", 10, ["com.example.apk", "manifest.json"]
        )
        self.assertEqual(report.abi_names, [])
        self.assertEqual(report.unlabelled_apks, ("com.example.apk",))
        self.assertTrue(report.notes)

    def test_probe_reads_the_index_through_the_injected_reader(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "bundle.xapk"
        build_zip(path)
        reader, size = local_file_reader(path)
        report = abidetect.probe_bundle_abis(
            "https://example.invalid/bundle.xapk", size=size, reader=reader
        )
        self.assertEqual(report.abi_names, ["arm64-v8a", "armeabi-v7a", "x86_64"])
        self.assertEqual(report.entry_count, 5)
        self.assertEqual(report.size, size)
        self.assertIn("abis", report.as_dict())


# ---------------------------------------------------------------------------
# zip index (served from a local file through the injected reader)
# ---------------------------------------------------------------------------


def build_zip(path: Path, *, with_comment: bool = False) -> dict:
    payloads = {
        "com.example.apk": b"M" * 5000,
        "config.arm64_v8a.apk": bytes(range(256)) * 40,
        "config.armeabi_v7a.apk": os.urandom(2048),
        "config.x86_64.apk": os.urandom(1024),
        "manifest.json": b'{"package_name":"com.example"}',
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in payloads.items():
            archive.writestr(name, data)
        archive.comment = b"x" * 100 if with_comment else b""
    return payloads


class RemoteZipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "bundle.xapk"
        self.payloads = build_zip(self.path)
        reader, size = local_file_reader(self.path)
        self.zip = RemoteZip("https://example.invalid/bundle.xapk", size=size, reader=reader)

    def test_entries_are_listed(self) -> None:
        names = set(self.zip.names())
        self.assertEqual(names, set(self.payloads))
        self.assertEqual(len(self.zip), len(self.payloads))

    def test_find_and_match(self) -> None:
        entry = self.zip.find("config.arm64_v8a.apk")
        self.assertIsNotNone(entry)
        splits = self.zip.match(lambda item: variants.is_config_split(item.name))
        self.assertEqual(len(splits), 3)
        self.assertIsNone(self.zip.find("nope.apk"))

    def test_uncompressed_sizes_match(self) -> None:
        for name, data in self.payloads.items():
            entry = self.zip.find(name)
            assert entry is not None
            self.assertEqual(entry.uncompressed_size, len(data), name)

    def test_read_deflated_entry(self) -> None:
        entry = self.zip.find("config.arm64_v8a.apk")
        assert entry is not None
        self.assertTrue(entry.is_deflated)
        self.assertEqual(self.zip.read(entry), self.payloads["config.arm64_v8a.apk"])

    def test_data_offset_points_past_local_header(self) -> None:
        entry = self.zip.find("com.example.apk")
        assert entry is not None
        with open(self.path, "rb") as handle:
            handle.seek(self.zip.data_offset(entry))
            raw = handle.read(entry.compressed_size)
        # The entry is deflated, so the offset must point at a valid zlib stream
        # that inflates back to the original payload.
        inflated = zlib.decompressobj(-15).decompress(raw, entry.uncompressed_size)
        self.assertEqual(inflated, self.payloads["com.example.apk"])

    def test_extract_verifies_crc(self) -> None:
        entry = self.zip.find("com.example.apk")
        assert entry is not None
        target = Path(self.tmp.name) / "out" / "base.apk"
        result = self.zip.extract(entry, target)
        self.assertEqual(target.read_bytes(), self.payloads["com.example.apk"])
        self.assertEqual(int(result.hashes.crc32, 16), entry.crc32)

    def test_extract_detects_corruption(self) -> None:
        entry = self.zip.find("com.example.apk")
        assert entry is not None
        # Corrupt the entry's stored CRC so verification must fail.
        bad = variants.ZipEntry(
            name=entry.name,
            method=entry.method,
            crc32=0xDEADBEEF,
            compressed_size=entry.compressed_size,
            uncompressed_size=entry.uncompressed_size,
            local_header_offset=entry.local_header_offset,
        )
        with self.assertRaises(VerificationError):
            self.zip.extract(bad, Path(self.tmp.name) / "bad.apk")

    def test_missing_index_raises(self) -> None:
        broken = RemoteZip("https://example.invalid/x", size=64, reader=lambda start, end: b"\x00" * (end - start + 1))
        with self.assertRaises(ZipIndexError):
            broken.entries

    def test_zip_with_comment_is_parsed(self) -> None:
        path = Path(self.tmp.name) / "commented.xapk"
        build_zip(path, with_comment=True)
        reader, size = local_file_reader(path)
        archive = RemoteZip("https://example.invalid/c.xapk", size=size, reader=reader)
        self.assertEqual(len(archive.entries), 5)

    def test_zip64_is_reported_clearly(self) -> None:
        # A central directory marker of 0xFFFFFFFF means zip64.
        fake = io.BytesIO()
        fake.write(b"\x00" * 10)
        start = fake.tell()
        fake.write(struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0))
        blob = fake.getvalue()
        archive = RemoteZip(
            "https://example.invalid/z64",
            size=len(blob),
            reader=lambda s, e: blob[s:e + 1],
        )
        with self.assertRaises(ZipIndexError) as ctx:
            archive.entries
        self.assertIn("zip64", str(ctx.exception).lower())
        self.assertGreaterEqual(start, 0)


# ---------------------------------------------------------------------------
# downloader hashing
# ---------------------------------------------------------------------------


class HashTests(unittest.TestCase):
    def test_known_digests(self) -> None:
        hashes = hash_bytes(b"hello")
        self.assertEqual(hashes.size, 5)
        self.assertEqual(hashes.sha1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        self.assertEqual(hashes.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(hashes.md5, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(hashes.crc32, "3610a686")

    def test_hash_file_matches_hash_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.bin"
            data = os.urandom(3 * 1024 * 1024 + 7)
            path.write_bytes(data)
            self.assertEqual(hash_file(path).sha1, hash_bytes(data).sha1)
            self.assertEqual(hash_file(path).size, len(data))

    def test_as_dict_shape(self) -> None:
        self.assertEqual(
            set(hash_bytes(b"x").as_dict()),
            {"size", "sha256", "sha1", "md5", "crc32"},
        )


class ZipCrcSanityTests(unittest.TestCase):
    def test_crc_matches_zlib(self) -> None:
        data = b"the quick brown fox" * 100
        self.assertEqual(int(hash_bytes(data).crc32, 16), zlib.crc32(data) & 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main(verbosity=2)
