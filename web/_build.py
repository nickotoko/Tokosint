#!/usr/bin/env python3
"""Build the source list from BBoT module metadata plus quotas from web/quotas.json.

Used by bin/web. Scan data is not read here.
"""

import json
from pathlib import Path

from bbot.core.modules import MODULE_LOADER

WEB_DIR = Path(__file__).resolve().parent


def build_sources():
    preloaded = MODULE_LOADER.preloaded()
    quotas = json.loads((WEB_DIR / "quotas.json").read_text())

    sources = []
    for name, meta in sorted(preloaded.items()):
        if meta.get("type") != "scan":
            continue
        flags = meta.get("flags", [])
        # sources = passive modules plus http (kept as the one deliberate exception)
        if "passive" not in flags and name != "http":
            continue
        m = meta.get("meta", {})
        mandatory = meta.get("options_mandatory", []) or []
        sources.append(
            {
                "name": name,
                "description": m.get("description", ""),
                "author": m.get("author", ""),
                "created_date": m.get("created_date", ""),
                "watched_events": meta.get("watched_events", []),
                "produced_events": meta.get("produced_events", []),
                "flags": flags,
                "auth_required": bool(m.get("auth_required")) or any("api_key" in o for o in mandatory),
                "freshness": m.get("freshness", ""),
                "quota": quotas.get(name, ""),
            }
        )
    return sources


def main():
    sources = build_sources()
    out = WEB_DIR / "sources.json"
    out.write_text(json.dumps(sources, ensure_ascii=False, indent=2))
    print(f"web/sources.json: {len(sources)} sources")


if __name__ == "__main__":
    main()
