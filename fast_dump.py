#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from zpo.checker import iter_mods
from zpo.config import load_config
from zpo.heuristics import analyze_heuristics
from zpo.jar_parser import parse_jar
from zpo.logging_setup import setup_logging
from zpo.obfuscation import analyze_obfuscation
from zpo.report import format_comment, merge_verdict, save_report
from zpo.llm import LlmResult

log = logging.getLogger("fast_dump")

def dump_one(path: Path, reports_dir: Path) -> dict:
    jar = parse_jar(path)
    heur = analyze_heuristics(jar)
    obf = analyze_obfuscation(jar)
    llm = LlmResult(enabled=False, ok=False, error="fast_dump")
    verdict = merge_verdict(jar, heur, obf, llm)
    save_report(verdict, reports_dir)
    return {
        "file": path.name,
        "mod_id": jar.mod_id,
        "mod_name": jar.mod_name,
        "size": jar.size,
        "classes": len(jar.classes),
        "obfuscated": obf.is_obfuscated,
        "zpo": verdict.zpo,
        "percent": verdict.percent,
        "guide_points": verdict.guide_points,
        "comment": format_comment(verdict),
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Быстрый дамп пула модов (без нейросети)")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--json-out", default="reports/fast_dump.json")
    args = parser.parse_args()

    cfg = load_config()
    setup_logging(cfg.logs_dir, "fast_dump")
    targets = [Path(p).resolve() for p in args.paths] if args.paths else iter_mods(cfg.mods_dir)
    if not targets:
        print("mods/ пуст", file=sys.stderr)
        return 2

    rows = []
    zpo_yes = 0
    for p in targets:
        try:
            row = dump_one(p, cfg.reports_dir)
            rows.append(row)
            zpo_yes += int(row["zpo"])
            print(row["comment"])
            print("-" * 48)
        except Exception:
            log.exception("fail %s", p)

    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"итого: {len(rows)} модов, ЗПО да: {zpo_yes}, нет: {len(rows) - zpo_yes}")
    print(f"json: {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
