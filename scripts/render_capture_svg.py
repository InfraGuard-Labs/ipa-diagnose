"""Render a REAL captured terminal output (a text file) as an SVG "screenshot".

Standard library only. It does not run ipa-diagnose and does not alter the
captured text (beyond stripping ANSI colour codes and trimming to a maximum
number of lines, which is stated in the image footer): the text in the image is
exactly what the tool printed in the recorded run. Every image carries a
provenance banner ("REAL LIVE CAPTURE", "REAL CONTAINER CAPTURE", ...) so a
capture from a real FreeIPA lab is never confused with fixture output.

Usage:
    python scripts/render_capture_svg.py IN.txt OUT.svg "Title" "PROVENANCE" [max_lines] [start_line]
"""

from __future__ import annotations

import html
import re
import sys

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_TS = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ")  # GitHub Actions log timestamps


def render(text: str, title: str, provenance: str, max_lines: int = 60, start: int = 0) -> str:
    lines = [_TS.sub("", _ANSI.sub("", ln)).rstrip("\r") for ln in text.splitlines()]
    total = len(lines)
    shown = lines[start : start + max_lines]
    footer = f"lines {start + 1}-{start + len(shown)} of {total} of the captured output" if total > len(shown) else f"{total} lines, complete"
    char_w, line_h, pad = 8.4, 17, 18
    width = int(max([len(x) for x in shown] + [len(provenance) + 4, len(title) + 4, 60]) * char_w + pad * 2)
    width = min(max(width, 720), 1400)
    height = int((len(shown) + 5) * line_h + pad * 2 + 40)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="Consolas, Menlo, \'DejaVu Sans Mono\', monospace" font-size="13.5">',
        f'<rect width="{width}" height="{height}" rx="8" fill="#0d1117"/>',
        f'<rect width="{width}" height="34" rx="8" fill="#161b22"/>',
        '<circle cx="18" cy="17" r="5" fill="#ff5f56"/><circle cx="36" cy="17" r="5" fill="#ffbd2e"/><circle cx="54" cy="17" r="5" fill="#27c93f"/>',
        f'<text x="76" y="22" fill="#8b949e">{html.escape(title)}</text>',
        f'<rect x="{pad}" y="44" width="{width - 2 * pad}" height="22" rx="4" fill="#12261e"/>',
        f'<text x="{pad + 8}" y="60" fill="#3fb950" font-weight="bold">{html.escape(provenance)}</text>',
    ]
    y = 44 + 22 + line_h + 6
    for ln in shown:
        colour = "#c9d1d9"
        low = ln.lower()
        if "critical" in low or "not running" in low or "overall: unknown" in low:
            colour = "#ff7b72"
        elif "degraded" in low or "not verified" in low or "not_fully_verified" in low or "partial" in low:
            colour = "#d29922"
        elif "overall: healthy" in low or "resolved" in low or ln.startswith("PASS"):
            colour = "#3fb950"
        elif ln.startswith("FAIL"):
            colour = "#ff7b72"
        out.append(f'<text x="{pad}" y="{y}" fill="{colour}" xml:space="preserve">{html.escape(ln)}</text>')
        y += line_h
    out.append(f'<text x="{pad}" y="{height - 10}" fill="#6e7681" font-size="11">{html.escape(footer)}</text>')
    out.append("</svg>")
    return "\n".join(out)


def main(argv: list) -> int:
    if len(argv) < 5:
        print(__doc__)
        return 2
    src, dst, title, prov = argv[1:5]
    max_lines = int(argv[5]) if len(argv) > 5 else 60
    start = int(argv[6]) if len(argv) > 6 else 0
    with open(src, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(text, title, prov, max_lines, start))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
