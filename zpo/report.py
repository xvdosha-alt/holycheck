from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .heuristics import HeuristicResult
from .jar_parser import JarInfo
from .llm import LlmResult
from .obfuscation import ObfuscationReport

log = logging.getLogger(__name__)

@dataclass
class Verdict:
    file: str
    zpo: bool
    percent: float
    guide_points: list[str] = field(default_factory=list)
    obfuscated: bool = False
    obfuscation_percent: float = 0.0
    obfuscation_notes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    malware_notes: list[str] = field(default_factory=list)
    summary: str = ""
    log_path: str = ""
    report_path: str = ""

def merge_verdict(
    jar: JarInfo,
    heur: HeuristicResult,
    obf: ObfuscationReport,
    llm: LlmResult,
) -> Verdict:
    points: list[str] = []
    for h in heur.hits:
        label = f"{h.point.category}: {h.point.title}"
        if label not in points:
            points.append(label)
    if llm.ok and llm.is_zpo:
        for p in llm.guide_points:
            p = str(p).strip()
            if not p or len(p) > 140:
                continue
            if p not in points:
                points.append(p)

    percent = heur.percent
    if llm.ok and llm.is_zpo is True:
        percent = max(percent, min(100.0, llm.confidence))
        if llm.confidence >= 60:
            percent = max(percent, 50.0)
    if llm.ok and llm.is_zpo is False and not heur.hits:
        percent = min(percent, 10.0)

    is_zpo = heur.is_zpo
    if llm.ok and llm.is_zpo is True and llm.confidence >= 55:
        is_zpo = True
    if llm.ok and llm.is_zpo is False and not heur.hits and llm.confidence >= 60:
        is_zpo = False

    if is_zpo and percent < 25:
        percent = 25.0
    if not is_zpo:
        percent = min(percent, 15.0)

    evidence: list[str] = []
    for h in heur.hits:
        evidence.extend(h.evidence[:2])
    evidence.extend(llm.evidence)
    evidence = list(dict.fromkeys(evidence))[:20]

    malware = list(dict.fromkeys(heur.malware_notes + llm.malware_notes))
    obf_notes = list(obf.reasons)
    if llm.obfuscated_classes:
        obf_notes.append("LLM classes: " + ", ".join(llm.obfuscated_classes))
    obfuscated = obf.is_obfuscated or bool(llm.obfuscated_classes)
    obf_percent = float(obf.percent or 0)
    if llm.obfuscated_classes:
        obf_percent = max(obf_percent, min(100.0, 40.0 + 10.0 * len(llm.obfuscated_classes)))
    if obfuscated and obf_percent < 25:
        obf_percent = 25.0

    summary = llm.summary or (
        f"Локально: hits={len(heur.hits)}, маскировка={ 'да' if heur.brand_spoof else 'нет' }"
    )

    return Verdict(
        file=jar.path.name,
        zpo=is_zpo,
        percent=round(percent, 1),
        guide_points=points,
        obfuscated=obfuscated,
        obfuscation_percent=round(obf_percent, 1),
        obfuscation_notes=obf_notes,
        evidence=evidence,
        malware_notes=malware,
        summary=summary,
    )

def format_comment(v: Verdict) -> str:
    lines = [
        f"Файл: {v.file}",
        f"ЗПО: {'да' if v.zpo else 'нет'}",
        f"Насколько ЗПО: {v.percent:.1f}%",
        f"Обфускация: {'ДА ⚠️' if v.obfuscated else 'нет'} ({v.obfuscation_percent:.1f}%)",
        "Пункты гайда:",
    ]
    if v.guide_points:
        for p in v.guide_points:
            lines.append(f"  - {p}")
    else:
        lines.append("  - (нет)")
    if v.obfuscated and v.obfuscation_notes:
        for n in v.obfuscation_notes:
            lines.append(f"  - обф: {n}")
    if v.malware_notes:
        lines.append("Прочее (не ЗПО):")
        for n in v.malware_notes:
            lines.append(f"  - {n}")
    if v.summary:
        lines.append(f"Комментарий: {v.summary}")
    return "\n".join(lines)

def save_report(v: Verdict, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / f"{Path(v.file).stem}.zpo.json"
    payload = asdict(v)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    txt = reports_dir / f"{Path(v.file).stem}.zpo.txt"
    txt.write_text(format_comment(v) + "\n", encoding="utf-8")
    v.report_path = str(out)
    log.info("report saved: %s / %s", out, txt)
    return out
