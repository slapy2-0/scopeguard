from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(report: dict) -> str:
    tpl = _env().get_template("report.html.j2")
    return tpl.render(r=report)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render(report: dict, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "html":
        return render_html(report)
    if fmt == "json":
        return render_json(report)
    raise ValueError(f"Unsupported format: {fmt!r} (use html or json)")
