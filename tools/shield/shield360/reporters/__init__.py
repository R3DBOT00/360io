"""Report renderers: plain text and JSON."""
from __future__ import annotations

import json

from ..model import Finding, exit_code_for, summarize

SCHEMA_VERSION = 1


def build_report(findings: list[Finding], meta: dict) -> dict:
    return {
        "tool": "360io-shield",
        "schema": SCHEMA_VERSION,
        **meta,
        "summary": summarize(findings),
        "exit_code": exit_code_for(findings),
        "findings": [f.to_dict() for f in findings],
    }


def render_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps(build_report(findings, meta), indent=2, sort_keys=False) + "\n"


def render_text(findings: list[Finding], meta: dict) -> str:
    lines = [f"360io Shield {meta.get('version', '')} - read-only host audit"]
    if meta.get("host"):
        host = meta["host"]
        lines.append(f"kernel {host.get('kernel', '?')}  uid {host.get('uid', '?')}")
    lines.append("")
    category = None
    for f in findings:
        if f.category != category:
            category = f.category
            lines.append(f"== {category}")
        lines.append(f"[{f.status.value:<7}] {f.id}: {f.evidence}")
        if f.note:
            lines.append(f"          note: {f.note}")
    counts = summarize(findings)
    lines.append("")
    lines.append("summary: " + "  ".join(f"{k}={v}" for k, v in counts.items())
                 + f"  exit={exit_code_for(findings)}")
    return "\n".join(lines) + "\n"


RENDERERS = {"text": render_text, "json": render_json}
