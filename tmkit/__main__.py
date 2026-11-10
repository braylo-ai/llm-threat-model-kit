"""CLI: python -m tmkit <system.yaml> [-o OUTDIR] [--fail-on High]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import report, to_markdown
from .model import ModelError, load

ORDER = ["Low", "Medium", "High", "Critical"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="tmkit", description="LLM/agent threat-model generator"
    )
    ap.add_argument("system", help="system description YAML")
    ap.add_argument("-o", "--out", help="write <name>.md and <name>.json here")
    ap.add_argument(
        "--fail-on",
        choices=ORDER,
        help="exit 1 if any RESIDUAL risk is at or above this rating",
    )
    a = ap.parse_args(argv)
    try:
        r = report(load(a.system))
    except (ModelError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    md = to_markdown(r)
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        stem = Path(a.system).stem
        (out / f"{stem}.md").write_text(md)
        (out / f"{stem}.json").write_text(json.dumps(r, indent=2) + "\n")
    else:
        print(md)
    if a.fail_on:
        floor = ORDER.index(a.fail_on)
        if any(ORDER.index(f["residual_rating"]) >= floor for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
