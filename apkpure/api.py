"""APKPure metadata API client.

The v3 endpoint answers in protobuf without a published schema, so the response
is decoded with :mod:`apkpure.pbwire` and matched by field number. Everything we
read here was verified against live responses (package, version code/name,
hashes, plus the signed XAPK download descriptor).
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import pbwire, transport
from .errors import MetadataError, VersionNotFound
from .pbwire import ProtobufError

METADATA_ENDPOINT = "https://api.pureapk.com/m/v3/cms/app_version"
DOWNLOAD_ENDPOINT = "https://d.apkpure.com/b/{kind}/{package}"

API_USER_AGENT = transport.API_UA
PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$")

# Field numbers of the version entry (verified empirically against live data).
F_NAME = 1
F_DISPLAY_NAME = 2
F_PACKAGE = 4
F_VERSION_CODE = 5
F_VERSION_NAME = 6
F_SHA1 = 7
F_DESCRIPTION = 10
F_DEVELOPER = 13
F_CATEGORY = 31
F_UPDATED = 36
F_RELEASED = 37
F_MD5 = 72
F_DOWNLOAD = 24

# Sub-fields of the download descriptor (field 24).
D_GENERATED = 1
D_LABEL = 2
D_SHA1 = 3
D_SIZE = 4
D_KIND = 8
D_URL = 9


def build_api_headers(
    *,
    lang: str = "en-US",
    country: str = "US",
    abi: str = "arm64-v8a",
    sdk: str = "33",
) -> Dict[str, str]:
    """Headers that make the API answer with the client-shaped payload."""
    project = {
        "lang": lang,
        "aid": 3,
        "os_ver": "13",
        "device_os_v": "13",
        "sys_ver": sdk,
        "country": country,
        "abi": abi,
    }
    return transport.request_headers(
        {
            "Accept": "*/*",
            "Ual-Access-Businessid": "projecta",
            "Ual-Access-ProjectA": json.dumps(project, separators=(",", ":")),
            "X-Cv": "2019000000",
            "X-Sv": "30",
            "X-Abis": "0",
            "X-Device-Id": "1234567890",
        },
        user_agent=API_USER_AGENT,
    )


def metadata_url(package: str, *, lang: str = "en-US") -> str:
    """URL of the metadata endpoint for ``package``."""
    query = urllib.parse.urlencode({"hl": lang, "package_name": package})
    return f"{METADATA_ENDPOINT}?{query}"


def cdn_url(package: str, kind: str = "APK", version_code: Optional[int] = None) -> str:
    """Build the stable APKPure download URL for an APK or XAPK."""
    base = DOWNLOAD_ENDPOINT.format(kind=kind.upper(), package=package)
    if version_code is None:
        return base
    return f"{base}?{urllib.parse.urlencode({'versionCode': str(version_code)})}"


@dataclass(frozen=True)
class DownloadDescriptor:
    """A signed download URL found in the metadata (XAPK bundles)."""

    url: str
    kind: str
    size: Optional[int] = None
    sha1: Optional[str] = None
    label: Optional[str] = None
    generated: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "kind": self.kind,
            "size": self.size,
            "sha1": self.sha1,
            "label": self.label,
            "generated": self.generated,
        }


@dataclass(frozen=True)
class AppVersion:
    """One release of an app as described by the metadata API."""

    package: str
    app_name: str
    version_code: int
    version_name: str
    apk_sha1: Optional[str] = None
    apk_md5: Optional[str] = None
    developer: Optional[str] = None
    category: Optional[str] = None
    updated: Optional[str] = None
    released: Optional[str] = None
    description: Optional[str] = None
    descriptor: Optional[DownloadDescriptor] = None

    @property
    def label(self) -> str:
        return f"{self.version_name} (versionCode {self.version_code})"

    @property
    def build_size(self) -> int:
        """Size of this build's payload, or -1 when the metadata omits it."""
        if self.descriptor and self.descriptor.size:
            return self.descriptor.size
        return -1

    @property
    def build_key(self) -> Tuple[int, int, str, str]:
        """Identity of one concrete build of a versionCode.

        APKPure lists several builds under the same versionCode — typically the
        32-bit and the 64-bit bundle, sometimes plus a rebuild. They share the
        versionCode and the app-level sha1 (field 7), so a build can only be told
        apart by its download descriptor: size, md5 and kind.
        """
        descriptor = self.descriptor
        return (
            self.version_code,
            self.build_size,
            (self.apk_md5 or ""),
            descriptor.kind if descriptor else "",
        )

    def as_dict(self) -> Dict[str, object]:
        return {
            "package": self.package,
            "app_name": self.app_name,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "apk_sha1": self.apk_sha1,
            "apk_md5": self.apk_md5,
            "developer": self.developer,
            "category": self.category,
            "updated": self.updated,
            "released": self.released,
            "download_descriptor": self.descriptor.as_dict() if self.descriptor else None,
        }


def fetch_metadata(
    package: str,
    *,
    lang: str = "en-US",
    country: str = "US",
    abi: str = "arm64-v8a",
    timeout: float = transport.DEFAULT_TIMEOUT,
    retries: int = 4,
) -> bytes:
    """Fetch the raw protobuf payload for ``package``."""
    if not PACKAGE_PATTERN.match(package):
        raise MetadataError(f"{package!r} does not look like an Android package name")
    url = metadata_url(package, lang=lang)
    headers = build_api_headers(lang=lang, country=country, abi=abi)

    def attempt() -> bytes:
        _meta, body = transport.fetch_bytes(url, headers=headers, timeout=timeout)
        return body

    def on_error(count: int, exc: BaseException) -> None:
        pass

    payload = transport.retry_call(
        attempt, attempts=retries, retry_on=(transport.NetworkError, transport.HttpError), on_error=on_error
    )
    if not payload:
        raise MetadataError(f"metadata API returned an empty response for {package}")
    return payload


def parse_versions(payload: bytes, package: str) -> List[AppVersion]:
    """Decode every build in a metadata payload, newest version first.

    All builds are kept: APKPure publishes several per versionCode (the 32-bit
    and the 64-bit bundle), and collapsing them by versionCode used to hide the
    architecture a caller was looking for. Builds of the same version are
    ordered largest first, which is the 64-bit bundle in practice.
    """
    builds: Dict[Tuple[int, int, str, str], AppVersion] = {}
    for message in pbwire.messages(payload):
        entry = _parse_entry(message, package)
        if entry is not None:
            builds.setdefault(entry.build_key, entry)
    if not builds:
        raise MetadataError(
            f"no version of {package} found in the metadata response "
            f"({len(payload)} bytes) — the app may not be hosted on APKPure"
        )
    return sorted(builds.values(), key=lambda item: (item.version_code, item.build_size), reverse=True)


def builds_for(versions: List[AppVersion], version_code: int) -> List[AppVersion]:
    """Every known build of ``version_code``, largest (usually 64-bit) first."""
    return [item for item in versions if item.version_code == version_code]


def versions_by_name(versions: List[AppVersion], version_name: str) -> List[AppVersion]:
    """Every build whose version *name* matches, newest versionCode first.

    The version name is not unique: Blood Strike 1.003.650026 is published as
    versionCode 169, 168 and 166, and one of those codes may carry the 64-bit
    bundle while the others are 32-bit. Searching by name is therefore the way to
    find an architecture that is missing from the newest build.
    """
    wanted = version_name.strip().lower()
    matches = [item for item in versions if item.version_name.strip().lower() == wanted]
    return sorted(matches, key=lambda item: (item.version_code, item.build_size), reverse=True)


def fetch_versions(package: str, **kwargs) -> List[AppVersion]:
    """Convenience wrapper: fetch and decode in one step."""
    payload = fetch_metadata(package, **kwargs)
    return parse_versions(payload, package)


def select_version(
    versions: List[AppVersion],
    *,
    version_code: Optional[int] = None,
    version_name: Optional[str] = None,
) -> AppVersion:
    """Pick a version by code or name, defaulting to the newest one."""
    if not versions:
        raise VersionNotFound("no versions were provided to select from")
    if version_code is not None:
        for version in versions:
            if version.version_code == version_code:
                return version
        available = ", ".join(str(item.version_code) for item in versions[:8])
        raise VersionNotFound(
            f"versionCode {version_code} is not on APKPure (newest codes: {available})"
        )
    if version_name is not None:
        wanted = version_name.strip().lower()
        for version in versions:
            if version.version_name.lower() == wanted:
                return version
        raise VersionNotFound(f"version {version_name} is not on APKPure")
    return versions[0]


def _parse_entry(message: bytes, package: str) -> Optional[AppVersion]:
    try:
        parsed = pbwire.parse(message)
    except ProtobufError:
        return None

    fields: Dict[int, List[pbwire.Field]] = {}
    for field in parsed:
        fields.setdefault(field.number, []).append(field)

    if _text(fields, F_PACKAGE) != package:
        return None
    code_text = _text(fields, F_VERSION_CODE)
    version_name = _text(fields, F_VERSION_NAME)
    if not code_text or not code_text.isdigit() or not version_name:
        return None

    sha1 = _text(fields, F_SHA1)
    md5 = _text(fields, F_MD5)
    return AppVersion(
        package=package,
        app_name=_text(fields, F_DISPLAY_NAME) or _text(fields, F_NAME) or package,
        version_code=int(code_text),
        version_name=version_name,
        apk_sha1=sha1.lower() if sha1 and SHA1_PATTERN.match(sha1.lower()) else None,
        apk_md5=md5.lower() if md5 and MD5_PATTERN.match(md5.lower()) else None,
        developer=_text(fields, F_DEVELOPER),
        category=_text(fields, F_CATEGORY),
        updated=_text(fields, F_UPDATED),
        released=_text(fields, F_RELEASED),
        description=_text(fields, F_DESCRIPTION),
        descriptor=_parse_descriptor(fields),
    )


def _parse_descriptor(fields: Dict[int, List[pbwire.Field]]) -> Optional[DownloadDescriptor]:
    for field in fields.get(F_DOWNLOAD, []):
        if field.wire_type != pbwire.LEN or not isinstance(field.value, bytes):
            continue
        try:
            sub = pbwire.parse(field.value)
        except ProtobufError:
            continue
        subfields: Dict[int, List[pbwire.Field]] = {}
        for item in sub:
            subfields.setdefault(item.number, []).append(item)

        url = _text(subfields, D_URL)
        if not url or not url.startswith("http"):
            continue
        kind = (_text(subfields, D_KIND) or "").upper()
        if not kind:
            kind = "XAPK" if ".xapk" in url.lower() else "APK"
        size = pbwire.get_int(field.value, D_SIZE)
        sha1 = (_text(subfields, D_SHA1) or "").lower() or None
        return DownloadDescriptor(
            url=url,
            kind=kind,
            size=size,
            sha1=sha1 if sha1 and SHA1_PATTERN.match(sha1) else None,
            label=_text(subfields, D_LABEL),
            generated=_text(subfields, D_GENERATED),
        )
    return None


def _text(fields: Dict[int, List[pbwire.Field]], number: int) -> Optional[str]:
    for field in fields.get(number, []):
        text = field.text()
        if text:
            return text
    return None
