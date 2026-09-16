"""ipa-diagnose: evidence-grounded diagnostic and correlation engine for FreeIPA / Red Hat IdM."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ipa-diagnose")
except PackageNotFoundError:  # pragma: no cover - only hit for an unpackaged checkout
    __version__ = "0.0.0+unknown"
