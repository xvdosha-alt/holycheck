#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from zpo.checker import check_mod, iter_mods
from zpo.config import load_config
from zpo.logging_setup import setup_logging
from zpo.report import format_comment

log = logging.getLogger("check_zpo")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка пула модов на ЗПО")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Конкретные .jar (по умолчанию весь mods/)",
    )
    parser.add_argument("--no-llm", action="store_true", help="Только эвристики, без нейросети")
    parser.add_argument("--mods-dir", default=None, help="Папка пула модов")
    args = parser.parse_args(argv)

    cfg = load_config()
    if args.mods_dir:
        cfg = type(cfg)(
            **{
                **cfg.__dict__,
                "mods_dir": Path(args.mods_dir).resolve(),
            }
        )
    if args.no_llm:
        cfg = type(cfg)(**{**cfg.__dict__, "llm_enabled": False})

    log_path = setup_logging(cfg.logs_dir)
    log.info("holycheck ZPO | mods_dir=%s llm=%s model=%s", cfg.mods_dir, cfg.llm_enabled, cfg.llm_model)
    log.info("full log: %s", log_path)

    if args.paths:
        targets = [Path(p).resolve() for p in args.paths]
    else:
        targets = iter_mods(cfg.mods_dir)

    if not targets:
        print("Пул модов пуст. Клади .jar в mods/", file=sys.stderr)
        return 2

    verdicts = []
    for path in targets:
        if not path.exists():
            log.error("не найден: %s", path)
            continue
        try:
            v = check_mod(path, cfg)
            v.log_path = str(log_path)
            verdicts.append(v)
        except Exception:
            log.exception("ошибка на %s", path)

    print()
    print("=" * 48)
    for v in verdicts:
        print(format_comment(v))
        print("-" * 48)
    print(f"Лог: {log_path}")
    print(f"Репорты: {cfg.reports_dir}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
