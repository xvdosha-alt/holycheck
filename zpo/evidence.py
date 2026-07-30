from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .guide import GUIDE, GuidePoint
from .heuristics import STRONG_PATTERNS, HeuristicResult
from .jar_parser import JarInfo, parse_constant_pool

@dataclass
class StringHit:
    class_path: str
    string: str
    pattern: str

@dataclass
class PointEvidence:
    point_id: str
    category: str
    title: str
    strings: list[StringHit] = field(default_factory=list)

def _match_patterns(text: str, patterns: tuple[str, ...]) -> list[tuple[str, str]]:
    out = []
    for pat in patterns:
        try:
            m = re.search(pat, text, re.I)
        except re.error:
            continue
        if m:
            out.append((pat, m.group(0)))
    return out

def _utf8s_from_class(data: bytes) -> list[str]:
    cp, _ = parse_constant_pool(data)
    return [x[1] for x in cp if x and x[0] == "Utf8"]

def _scan_zip(
    z: zipfile.ZipFile,
    patterns: tuple[str, ...],
    found: list[StringHit],
    seen: set[tuple[str, str]],
    limit: int,
    prefix: str = "",
) -> bool:
    for name in z.namelist():
        label = f"{prefix}{name}" if prefix else name
        if name.endswith((".json", ".toml", ".txt", ".properties", ".lang")):
            try:
                text = z.read(name).decode("utf-8", "replace")
            except Exception:
                continue
            for pat, matched in _match_patterns(text, patterns):
                key = (label, matched)
                if key in seen:
                    continue
                seen.add(key)
                snippet = text
                if len(snippet) > 200:
                    m = re.search(re.escape(matched), text, re.I)
                    if m:
                        a, b = max(0, m.start() - 40), min(len(text), m.end() + 40)
                        snippet = text[a:b]
                found.append(StringHit(label, snippet.strip(), matched))
                if len(found) >= limit:
                    return True

        if name.startswith("META-INF/jars/") and name.lower().endswith(".jar"):
            try:
                import io

                with zipfile.ZipFile(io.BytesIO(z.read(name))) as nz:
                    if _scan_zip(nz, patterns, found, seen, limit, prefix=f"{name}!"):
                        return True
            except Exception:
                pass
            continue

        if not name.endswith(".class"):
            continue
        for pat, matched in _match_patterns(label, patterns):
            key = (label, label)
            if key not in seen:
                seen.add(key)
                found.append(StringHit(label, label, matched))
                if len(found) >= limit:
                    return True
        try:
            data = z.read(name)
        except Exception:
            continue
        for s in _utf8s_from_class(data):
            for pat, matched in _match_patterns(s, patterns):
                key = (label, s)
                if key in seen:
                    continue
                seen.add(key)
                found.append(StringHit(label, s, matched))
                if len(found) >= limit:
                    return True
    return False

def locate_in_jar_file(path: Path, patterns: tuple[str, ...], limit: int = 60) -> list[StringHit]:
    if not patterns:
        return []
    found: list[StringHit] = []
    seen: set[tuple[str, str]] = set()
    try:
        with zipfile.ZipFile(path) as z:
            _scan_zip(z, patterns, found, seen, limit)
    except Exception:
        return found
    return found

def locate_point_evidence(jar: JarInfo, point: GuidePoint, limit: int = 60) -> list[StringHit]:
    found = locate_in_jar_file(jar.path, point.patterns, limit=limit)
    if found:
        return found
    seen: set[tuple[str, str]] = set()
    out: list[StringHit] = []
    for cls in jar.classes:
        for s in cls.strings:
            for pat, matched in _match_patterns(s, point.patterns):
                key = (cls.path, s)
                if key in seen:
                    continue
                seen.add(key)
                out.append(StringHit(cls.path, s, matched))
                if len(out) >= limit:
                    return out
    return out

def locate_strong_evidence(jar: JarInfo, limit: int = 60) -> list[StringHit]:
    return locate_in_jar_file(jar.path, STRONG_PATTERNS, limit=limit)

def build_evidence_report(jar: JarInfo, heur: HeuristicResult) -> list[PointEvidence]:
    report: list[PointEvidence] = []
    for hit in heur.hits:
        if hit.point.id == "bypass.brand_spoof":
            report.append(
                PointEvidence(
                    point_id=hit.point.id,
                    category=hit.point.category,
                    title=hit.point.title,
                    strings=[
                        StringHit(
                            class_path="fabric.mod.json / entrypoints",
                            string=note,
                            pattern="brand_spoof",
                        )
                        for note in hit.evidence
                    ],
                )
            )
            continue
        if hit.point.id == "strong.signal":
            report.append(
                PointEvidence(
                    point_id=hit.point.id,
                    category=hit.point.category,
                    title=hit.point.title,
                    strings=locate_strong_evidence(jar),
                )
            )
            continue

        guide_point = next((g for g in GUIDE if g.id == hit.point.id), hit.point)
        pe = PointEvidence(
            point_id=hit.point.id,
            category=hit.point.category,
            title=hit.point.title,
            strings=locate_point_evidence(jar, guide_point),
        )
        if not pe.strings and hit.evidence:
            pe.strings = [StringHit("?", ev, "evidence") for ev in hit.evidence[:10]]
        report.append(pe)
    return report

def evidence_to_dict(items: list[PointEvidence]) -> list[dict]:
    return [
        {
            "point_id": pe.point_id,
            "category": pe.category,
            "title": pe.title,
            "strings": [
                {
                    "class_path": s.class_path,
                    "string": s.string,
                    "pattern": s.pattern,
                }
                for s in pe.strings
            ],
        }
        for pe in items
    ]
