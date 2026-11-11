#!/usr/bin/env python3
"""Build the source list from BBoT module metadata plus quotas from web/quotas.json.

Used by bin/web. Scan data is not read here.
"""

import json
from pathlib import Path

from bbot.core.modules import MODULE_LOADER

WEB_DIR = Path(__file__).resolve().parent


# http - live checks of URLs; gowitness - screenshots of the target's pages (both visit the target)
ACTIVE_SOURCES = ("http", "gowitness")


def build_sources():
    preloaded = MODULE_LOADER.preloaded()
    quotas = json.loads((WEB_DIR / "quotas.json").read_text())

    sources = []
    for name, meta in sorted(preloaded.items()):
        if meta.get("type") != "scan":
            continue
        flags = meta.get("flags", [])
        # sources = passive modules plus the deliberate active exceptions (they are only run when chosen explicitly:
        # an empty module list runs the passive set)
        if "passive" not in flags and name not in ACTIVE_SOURCES:
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


def build_chord(preloaded=None):
    """Modules <-> event types for the chord graph of the "How it works" tab.

    The same dataset as BBoT's documentation (bbot/scripts/docs.py: gen_chord_data), built from the modules of this
    fork: scan and internal modules with their watched (consumes) and produced event types. The tree has a root,
    a "module" branch and an "event_type" branch; rels go event type -> module (produces) and module -> event type
    (consumes)."""
    preloaded = MODULE_LOADER.preloaded() if preloaded is None else preloaded
    lookup, entities, rels = {}, {}, []

    def add(name, parent):
        if name not in lookup:
            e_id = len(entities) + 1
            lookup[name] = e_id
            entities[e_id] = {"id": e_id, "name": name, "parent": parent, "consumes": [], "produces": []}
        return lookup[name]

    mods = []
    for module, meta in sorted(preloaded.items()):
        if meta.get("type") not in ("scan", "internal"):
            continue
        watched = [e for e in meta.get("watched_events", []) if e != "*"]
        produced = [e for e in meta.get("produced_events", []) if e != "*"]
        if not (watched or produced):
            continue
        mods.append((module, watched, produced))
        m_id = add(module, 99999999)
        for event_type in watched:
            e_id = add(event_type, 88888888)
            entities[m_id]["consumes"].append(e_id)
            entities[e_id]["consumes"].append(m_id)
        for event_type in produced:
            e_id = add(event_type, 88888888)
            entities[m_id]["produces"].append(e_id)
            entities[e_id]["produces"].append(m_id)
    for module, watched, produced in mods:
        for event_type in watched:
            rels.append({"source": lookup[module], "target": lookup[event_type], "type": "consumes"})
        for event_type in produced:
            rels.append({"source": lookup[event_type], "target": lookup[module], "type": "produces"})
    tree = [
        {"id": 77777777, "name": "root"},
        {"id": 99999999, "name": "module", "parent": 77777777},
        {"id": 88888888, "name": "event_type", "parent": 77777777},
    ]
    return {"entities": tree + sorted(entities.values(), key=lambda x: x["name"]), "rels": rels,
            "modules": len(mods), "event_types": sum(1 for e in entities.values() if e["parent"] == 88888888)}  # fmt: skip
