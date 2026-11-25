"""Read APKCombo's HTML: app details, and the download variants plus their tokens.

APKCombo is a WordPress site, so the interesting data is server-rendered. Two
pages matter:

``/<slug>/<package>/``
    app details — version, size, publisher, declared architectures and the
    published SHA-256;
``/<slug>/<package>/download/apk``
    one ``<form>`` per variant. Each form carries a hidden/button field
    ``soqplay_download_file=<token>``; POSTing that token is what
    :mod:`apkcombo.api` turns into a file URL.

Only :mod:`re` is used: the markup is stable, and pulling in an HTML parser for
five fields would not be worth the dependency.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import http
from .errors import AppNotFound, ScrapeError, VariantNotFound

SITE = "https://apkcombo.com"
APP_URL = SITE + "/{slug}/{package}/"
DOWNLOAD_URL = SITE + "/{slug}/{package}/download/apk"
SEARCH_URL = SITE + "/search/{query}"
WP_SEARCH_URL = SITE + "/wp-json/wp/v2/search?search={query}&per_page=20"

#: APKCombo writes sizes in binary units ("665.78 MB" is a 698,120,404 byte file).
SIZE_UNITS = {"b": 1, "kb": 1 << 10, "mb": 1 << 20, "gb": 1 << 30, "tb": 1 << 40}
SIZE_RE = re.compile(r"([\d.]+)\s*(B|KB|MB|GB|TB)\b", re.I)
TOKEN_RE = re.compile(r"soqplay_download_file[^>]{0,80}?value=\"([0-9a-fA-F]{32,})\"", re.I)
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.S | re.I)
BADGE_RE = re.compile(r"ak-badge[^>]*>\s*([A-Za-z]+)\s*<", re.I)
ARCH_RE = re.compile(r"ak-var__arch[^>]*>\s*([^<]+?)\s*<", re.I)
META_RE = re.compile(r"ak-var__m[^>]*>\s*([^<]+?)\s*<", re.I)
ARIA_RE = re.compile(r'aria-label="Download ([^"]+)"', re.I)
SHA_RE = re.compile(r"SHA-256[^0-9a-fA-F]{0,40}([0-9a-fA-F]{64})")
PACKAGE_RE = re.compile(r'data-copy-package="([^"]+)"')
PLAY_ID_RE = re.compile(r"play\.google\.com/store/apps/details\?id=([A-Za-z0-9_.]+)")
TITLE_RE = re.compile(r"<title>([^<]+)</title>", re.I)
META_DESC_RE = re.compile(r'<meta name="description" content="([^"]+)"', re.I)
VERSION_RE = re.compile(r"latest version ([0-9][\w.\-]*)", re.I)
LINK_RE = re.compile(r'href="(https://apkcombo\.com/([^"/]+)/([^"/]+)/)"')


def parse_size_text(text: str) -> Optional[int]:
    """``"665.78 MB"`` -> ``698120404``-ish byte count (approximate by design)."""
    match = SIZE_RE.search(text or "")
    if not match:
        return None
    value = float(match.group(1))
    unit = SIZE_UNITS.get(match.group(2).lower())
    if unit is None:
        return None
    return int(value * unit)


def human_size(text: str) -> str:
    match = SIZE_RE.search(text or "")
    if not match:
        return (text or "").strip()
    return f"{match.group(1)} {match.group(2).upper()}"


def _dt_dd(html: str, label: str, *, inner: str = r"([^<]+)") -> Optional[str]:
    """Read ``<dt>Label</dt><dd>…<bdi|a|time>value</…></dd>`` tolerantly."""
    pattern = (
        r"<dt[^>]*>\s*" + re.escape(label) + r"\s*</dt>\s*<dd[^>]*>\s*"
        r"(?:<a[^>]*>|<bdi[^>]*>|<time[^>]*>)?\s*" + inner
    )
    match = re.search(pattern, html, re.I)
    return match.group(1).strip() if match else None


def _split_archs(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,/|]", text) if part.strip()]


@dataclass(frozen=True)
class Variant:
    """One downloadable file offered on the download page."""

    kind: str  # "APK" or "XAPK"
    token: str
    size_text: str = ""
    size_bytes: Optional[int] = None
    android: str = ""
    archs: Tuple[str, ...] = ()
    primary: bool = False

    @property
    def label(self) -> str:
        bits = [self.kind]
        if self.size_text:
            bits.append(self.size_text)
        return " ".join(bits)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "token": self.token,
            "size_text": self.size_text,
            "size_bytes": self.size_bytes,
            "android": self.android,
            "archs": list(self.archs),
            "primary": self.primary,
        }


@dataclass(frozen=True)
class AppInfo:
    """Everything the app page advertises."""

    package: str
    slug: str
    url: str
    name: str = ""
    version: str = ""
    size_text: str = ""
    size_bytes: Optional[int] = None
    updated: str = ""
    publisher: str = ""
    android: str = ""
    archs: Tuple[str, ...] = ()
    sha256: str = ""
    description: str = ""

    @property
    def download_url(self) -> str:
        return DOWNLOAD_URL.format(slug=self.slug, package=self.package)

    def as_dict(self) -> Dict[str, object]:
        return {
            "package": self.package,
            "slug": self.slug,
            "url": self.url,
            "name": self.name,
            "version": self.version,
            "size_text": self.size_text,
            "size_bytes": self.size_bytes,
            "updated": self.updated,
            "publisher": self.publisher,
            "android": self.android,
            "archs": list(self.archs),
            "sha256": self.sha256,
        }


def parse_app_page(html: str, url: str, *, package: str = "") -> AppInfo:
    """Turn an app page into :class:`AppInfo`."""
    parts = urllib.parse.urlsplit(url)
    segments = [segment for segment in parts.path.split("/") if segment]
    slug = segments[0] if segments else ""
    found_package = package or (PACKAGE_RE.search(html).group(1) if PACKAGE_RE.search(html) else "")
    if not found_package:
        play = PLAY_ID_RE.search(html)
        found_package = play.group(1) if play else ""
    if not found_package:
        raise ScrapeError(f"no package id on {url}")

    name = ""
    title = TITLE_RE.search(html)
    if title:
        name = re.sub(r"\s*[–-]\s*(Free Download|Latest Version).*$", "", title.group(1)).strip()
        name = re.sub(r"\s+APK$", "", name).strip()
    size_text = human_size(_dt_dd(html, "Size") or "")
    updated = _dt_dd(html, "Updated on", inner=r'([^"]+)') or ""
    version = _dt_dd(html, "Version") or ""
    if not version:
        desc = META_DESC_RE.search(html)
        match = VERSION_RE.search(desc.group(1)) if desc else None
        version = match.group(1) if match else ""
    sha = SHA_RE.search(html)

    return AppInfo(
        package=found_package,
        slug=slug,
        url=url,
        name=name,
        version=version,
        size_text=size_text,
        size_bytes=parse_size_text(size_text),
        updated=updated,
        publisher=_dt_dd(html, "Publisher") or "",
        android=_dt_dd(html, "Android") or "",
        archs=tuple(_split_archs(_dt_dd(html, "Architecture"))),
        sha256=sha.group(1).lower() if sha else "",
        description=re.sub(r"\s+", " ", _meta_description(html)).strip(),
    )


def _meta_description(html: str) -> str:
    match = META_DESC_RE.search(html)
    if not match:
        return ""
    return match.group(1)


def parse_variants(html: str, *, app: Optional[AppInfo] = None) -> List[Variant]:
    """Collect every download variant offered by a download page."""
    variants: List[Variant] = []
    seen: Dict[str, int] = {}
    for block in FORM_RE.findall(html):
        match = TOKEN_RE.search(block)
        if not match:
            continue
        token = match.group(1).lower()
        if token in seen:
            continue

        badge = BADGE_RE.search(block)
        aria = ARIA_RE.search(block)
        meta = META_RE.search(block)
        arch = ARCH_RE.search(block)
        primary = 'id="nu-download-request"' in block or "nu-download-button" in block

        kind = ""
        if badge:
            kind = badge.group(1).upper()
        elif aria and "apk" in aria.group(1).lower():
            kind = "APK"
        if not kind:
            kind = "APK" if primary else "XAPK"

        size_text = ""
        if aria:
            size_text = human_size(aria.group(1))
        elif meta:
            size_text = human_size(meta.group(1).split("·")[0])

        android = ""
        if meta and "·" in meta.group(1):
            android = meta.group(1).split("·", 1)[1].strip()

        archs = tuple(_split_archs(arch.group(1) if arch else None))
        if not archs and app is not None:
            archs = tuple(app.archs)

        seen[token] = len(variants)
        variants.append(
            Variant(
                kind=kind,
                token=token,
                size_text=size_text,
                size_bytes=parse_size_text(size_text),
                android=android,
                archs=archs,
                primary=primary,
            )
        )
    if not variants:
        raise ScrapeError("no download forms found on the page (APKCombo markup changed?)")
    return variants


def pick_variant(variants: Sequence[Variant], wanted: str = "auto") -> Variant:
    """Choose a variant: ``apk``, ``xapk``, or ``auto`` = smallest total download.

    ``auto`` prefers the XAPK bundle because a bundle is what carries the
    per-architecture splits, and falls back to the plain APK when no bundle is
    offered.
    """
    wanted = (wanted or "auto").lower()
    if wanted not in ("auto", "apk", "xapk"):
        raise VariantNotFound(f"unknown variant '{wanted}'; use apk, xapk or auto")

    def by_kind(kind: str) -> List[Variant]:
        return [item for item in variants if item.kind.lower() == kind]

    if wanted == "apk":
        found = by_kind("apk")
    elif wanted == "xapk":
        found = by_kind("xapk")
    else:
        found = by_kind("xapk") or by_kind("apk") or list(variants)
    if not found:
        kinds = ", ".join(sorted({item.kind for item in variants})) or "none"
        raise VariantNotFound(f"no '{wanted}' variant offered (available: {kinds})")
    if wanted == "auto" and len(found) > 1:
        # Same kind twice: take the one with the smallest advertised size.
        found = sorted(found, key=lambda item: item.size_bytes or 1 << 62)
    return found[0]


def app_url(slug: str, package: str) -> str:
    return APP_URL.format(slug=slug, package=package)


def slug_from_url(url: str) -> str:
    segments = [segment for segment in urllib.parse.urlsplit(url).path.split("/") if segment]
    return segments[0] if segments else ""


def resolve_slug(
    package: str,
    *,
    slug: Optional[str] = None,
    timeout: float = http.DEFAULT_TIMEOUT,
    log=None,
) -> Tuple[str, str]:
    """Find the ``/<slug>/<package>/`` URL for a package id.

    Tries the WordPress search endpoint first (it is JSON and cheap), then the
    site search page. Returns ``(slug, url)``.
    """
    logger = log or (lambda _message: None)
    if slug:
        url = app_url(slug, package)
        logger(f"using the given slug: {url}")
        return slug, url

    query = urllib.parse.quote(package)
    try:
        text, _headers = http.fetch_text(WP_SEARCH_URL.format(query=query), timeout=timeout, log=log)
        for item in json.loads(text):
            candidate = str(item.get("url", ""))
            if candidate.rstrip("/").endswith("/" + package):
                found = slug_from_url(candidate)
                if found:
                    logger(f"resolved {package} via the search API: {found}")
                    return found, candidate
    except Exception as exc:  # noqa: BLE001 - fall back to the HTML search
        logger(f"search API unavailable ({type(exc).__name__}), trying the search page")

    text, _headers = http.fetch_text(SEARCH_URL.format(query=query), timeout=timeout, log=log)
    for match in LINK_RE.finditer(text):
        url, found_slug, found_package = match.groups()
        if found_package == package and found_slug not in ("search", "category", "tag", "developer"):
            logger(f"resolved {package} via the search page: {found_slug}")
            return found_slug, url
    raise AppNotFound(
        f"APKCombo has no page for '{package}' (tried the search API and the search page); "
        "pass --slug to point at an app URL directly"
    )


def fetch_app_info(
    package: str,
    *,
    slug: Optional[str] = None,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    log=None,
) -> AppInfo:
    found_slug, url = resolve_slug(package, slug=slug, timeout=timeout, log=log)
    html, _headers = http.fetch_text(url, timeout=timeout, retries=retries, log=log)
    return parse_app_page(html, url, package=package)


def fetch_variants(
    app: AppInfo,
    *,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    log=None,
) -> Tuple[str, List[Variant]]:
    """Fetch the download page and return ``(url, variants)``."""
    url = app.download_url
    html, _headers = http.fetch_text(url, timeout=timeout, retries=retries, log=log)
    return url, parse_variants(html, app=app)
