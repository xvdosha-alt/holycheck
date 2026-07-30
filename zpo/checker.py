from __future__ import annotations

import logging
from pathlib import Path

from .config import Config
from .heuristics import analyze_heuristics
from .jar_parser import parse_jar, is_mc_below_116
from .llm import LlmResult, analyze_jar_with_llm
from .obfuscation import analyze_obfuscation
from .report import Verdict, merge_verdict, save_report

log = logging.getLogger(__name__)

def check_mod(path: Path, cfg: Config) -> Verdict:
    log.info("======== START %s ========", path.name)
    jar = parse_jar(path)
    heur = analyze_heuristics(jar)
    obf = analyze_obfuscation(jar)
    if obf.is_obfuscated:
        log.warning("УВЕДОМЛЕНИЕ: мод похож на обфусцированный (%s)", path.name)

    mc_old = is_mc_below_116(jar.mc_version) is True
    if mc_old:
        log.info("MC < 1.16 (%s) — пропуск ML", jar.mc_version or "?")
        llm = LlmResult(
            enabled=False,
            ok=False,
            error="legacy_mc",
            summary=f"Minecraft < 1.16 ({jar.mc_version or '?'}) — только fast-скан",
        )
    else:
        llm = analyze_jar_with_llm(
            cfg,
            jar,
            heuristic_points=[f"{h.point.category}: {h.point.title}" for h in heur.hits],
            obfuscated=obf.is_obfuscated,
            malware_notes=heur.malware_notes,
        )

    verdict = merge_verdict(jar, heur, obf, llm)
    save_report(verdict, cfg.reports_dir)
    log.info("======== DONE %s zpo=%s percent=%.1f ========", path.name, verdict.zpo, verdict.percent)
    return verdict

def iter_mods(mods_dir: Path) -> list[Path]:
    if not mods_dir.exists():
        return []
    return sorted(
        p for p in mods_dir.iterdir() if p.is_file() and p.suffix.lower() in {".jar", ".zip"}
    )
