from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .guide import KNOWN_BUNDLED_LIB_PREFIXES
from .jar_parser import ClassInfo, JarInfo

log = logging.getLogger(__name__)

SHORT_NAME = re.compile(r"^[a-z]{1,2}$")
PROGUARDISH = re.compile(r"^[a-z]{1,3}(/[a-z]{1,3}){1,6}/[a-zA-Z0-9]{1,3}\.class$")
INTERMEDIARY = re.compile(r"class_\d+|method_\d+|field_\d+")

ILLI_NAME = re.compile(r"^[Il1O0]{4,}$")
ILLI_PATH = re.compile(r"(?:^|/)[Il1O0]{4,}(?:\.class)?$")
CJK_CHARS = re.compile(r"[\u3400-\u9FFF\uF900-\uFAFF]")
DECRYPT_HINT = re.compile(
    r"(?i)(decrypt|decode|deobf|unscrambl|CooldownInfo\.d|StringPool|\.d\(\")",
)

@dataclass
class ObfuscationReport:
    is_obfuscated: bool
    confidence: float
    percent: float
    reasons: list[str]
    short_name_ratio: float
    proguard_path_ratio: float

def _illi_ratio(name: str) -> float:
    if not name:
        return 0.0
    illi = sum(1 for c in name if c in "Il1O0")
    return illi / len(name)

def analyze_obfuscation(jar: JarInfo) -> ObfuscationReport:
    classes = [c for c in jar.classes if "/mixin/" not in c.path.lower()]
    if not classes:
        classes = jar.classes
    if not classes:
        return ObfuscationReport(False, 0.0, 0.0, ["нет .class"], 0.0, 0.0)

    short = 0
    proguard_paths = 0
    illi_names = 0
    weird_strings = 0
    cjk_string_hits = 0
    decrypt_hits = 0
    total_names = 0
    total_strings_checked = 0

    for cls in classes:
        simple = cls.path.rsplit("/", 1)[-1].removesuffix(".class")
        total_names += 1
        if SHORT_NAME.fullmatch(simple) or re.fullmatch(r"[a-z]{1,2}\d*", simple):
            short += 1
        if PROGUARDISH.fullmatch(cls.path):
            proguard_paths += 1
        if ILLI_NAME.fullmatch(simple) or (_illi_ratio(simple) >= 0.85 and len(simple) >= 4):
            illi_names += 1
        elif ILLI_PATH.search(cls.path):
            illi_names += 1

        named = [
            s
            for s in cls.strings
            if re.fullmatch(r"[A-Za-z_$][\w$]*", s)
            and 1 <= len(s) <= 2
            and s.lower() not in {"id", "to", "of", "in", "on", "is", "or"}
            and s.upper() not in {"Z", "I", "J", "D", "F", "V", "B", "C", "S"}
        ]
        if len(named) >= 8:
            shortish = sum(1 for s in named if SHORT_NAME.fullmatch(s))
            if shortish / max(len(named), 1) > 0.7:
                weird_strings += 1

        for s in cls.strings[:80]:
            total_strings_checked += 1
            if len(s) >= 4 and CJK_CHARS.search(s):
                cjk_ratio = len(CJK_CHARS.findall(s)) / max(len(s), 1)
                if cjk_ratio >= 0.4:
                    cjk_string_hits += 1
            if DECRYPT_HINT.search(s):
                decrypt_hits += 1

    short_ratio = short / total_names
    pg_ratio = proguard_paths / total_names
    weird_ratio = weird_strings / total_names
    illi_ratio = illi_names / total_names
    cjk_ratio = cjk_string_hits / max(total_names, 1)

    reasons: list[str] = []
    score = 0.0
    if short_ratio >= 0.35:
        score += 0.45
        reasons.append(f"короткие имена классов: {short_ratio:.0%}")
    if pg_ratio >= 0.25:
        score += 0.35
        reasons.append(f"proguard-подобные пути: {pg_ratio:.0%}")
    if weird_ratio >= 0.45:
        score += 0.25
        reasons.append(f"обфусцированные members: {weird_ratio:.0%}")
    if illi_ratio >= 0.2:
        score += 0.55
        reasons.append(f"IlIlI/I1l1 имена классов: {illi_ratio:.0%}")
    elif illi_ratio >= 0.08:
        score += 0.3
        reasons.append(f"IlIlI/I1l1 имена классов: {illi_ratio:.0%}")
    if cjk_ratio >= 0.15 or cjk_string_hits >= 8:
        score += 0.5
        reasons.append(f"зашифрованные CJK-строки: {cjk_string_hits} шт.")
    elif cjk_string_hits >= 3:
        score += 0.25
        reasons.append(f"зашифрованные CJK-строки: {cjk_string_hits} шт.")
    if decrypt_hits >= 2 and (cjk_string_hits >= 2 or illi_ratio >= 0.08):
        score += 0.2
        reasons.append("decrypt/string-pool методы рядом с обфускацией")

    readable = 0
    for cls in classes:
        if any(len(s) >= 8 and re.search(r"[a-z]{4,}", s, re.I) for s in cls.strings[:30]):
            readable += 1
    readable_ratio = readable / total_names
    if readable_ratio < 0.25 and total_names >= 5:
        score += 0.2
        reasons.append(f"мало читаемых строк в классах: {readable_ratio:.0%}")

    fname = (jar.path.name or "").lower()
    if re.search(r"[-_]obf(?:uscated)?(?:[-_.]|$)", fname) and score < 0.45:
        score = max(score, 0.4)
        reasons.append("имя файла содержит -obf")

    raw_pct = min(100.0, round(score * 100, 1))
    is_obf = score >= 0.4
    conf = min(1.0, score)
    percent = raw_pct
    if is_obf and percent < 25:
        percent = 25.0
    note_reasons = reasons if is_obf else (reasons if raw_pct >= 15 else [])
    report = ObfuscationReport(is_obf, conf, percent, note_reasons, short_ratio, pg_ratio)
    if is_obf:
        log.warning(
            "ОБФУСКАЦИЯ: percent=%.0f%% confidence=%.0f%% reasons=%s",
            percent,
            conf * 100,
            "; ".join(reasons) or "heuristic",
        )
    else:
        log.info("обфускация не подтверждена (percent=%.1f score=%.2f)", percent, score)
    return report

_LLM_KEYWORDS = (
    "attack",
    "esp",
    "glow",
    "aim",
    "trigger",
    "crystal",
    "freecam",
    "xray",
    "hitbox",
    "elytra",
    "outline",
    "critical",
    "sword",
    "module",
    "hack",
    "cheat",
    "aura",
    "tracer",
    "playeresp",
    "killaura",
    "autoclick",
    "reach",
    "velocity",
    "antiknockback",
    "indicator",
    "health",
    "target",
    "render",
    "client",
    "bot",
    "panic",
    "baritone",
    "cooldown",
    "swap",
    "crystal",
    "webhook",
    "steal",
    "rat",
)


def _entrypoint_class_paths(jar: JarInfo) -> set[str]:
    paths: set[str] = set()
    for entries in jar.entrypoints.values():
        for ep in entries:
            ep = str(ep).strip()
            if not ep:
                continue
            paths.add(ep.replace(".", "/") + ".class")
    return paths


def _score_class_for_llm(cls: ClassInfo, entrypoints: set[str]) -> float:
    blob = " ".join(cls.strings).lower()
    path_low = cls.path.lower()
    simple = cls.path.rsplit("/", 1)[-1].removesuffix(".class")

    score = sum(3.0 for k in _LLM_KEYWORDS if k in blob)
    if cls.path in entrypoints:
        score += 8.0
    if "client" in path_low or "Client" in simple:
        score += 2.0
    if SHORT_NAME.fullmatch(simple):
        score += 4.0
    if ILLI_NAME.fullmatch(simple) or _illi_ratio(simple) >= 0.85:
        score += 5.0
    if any(CJK_CHARS.search(s) for s in cls.strings[:20]):
        score += 3.0
    if "/module/" in path_low or "modules/" in path_low:
        score += 3.0
    if "mixin" in path_low:
        score += 1.0
    if simple.endswith("Mixin") and cls.size < 1200:
        score -= 2.0
    if score <= 0:
        score = 0.5 + (cls.size / 10000.0)
    return score


def _entrypoint_package_prefixes(jar: JarInfo) -> list[str]:
    prefixes: set[str] = set()
    for entries in jar.entrypoints.values():
        for ep in entries:
            ep = str(ep).strip()
            if not ep or "." not in ep:
                continue
            prefixes.add(ep.rsplit(".", 1)[0].replace(".", "/"))
    return sorted(prefixes)


def _is_nested_jar_class(path: str) -> bool:
    return path.startswith("META-INF/jars/") or ".jar!" in path


def _is_known_lib_class(path: str) -> bool:
    plain = path.split(".jar!", 1)[-1]
    return any(plain.startswith(p) for p in KNOWN_BUNDLED_LIB_PREFIXES)


def _is_mod_own_class(cls: ClassInfo, jar: JarInfo) -> bool:
    if _is_nested_jar_class(cls.path):
        return False
    plain = cls.path
    for prefix in _entrypoint_package_prefixes(jar):
        if plain.startswith(prefix + "/") or plain.startswith(prefix + ".class"):
            return True
    if _is_known_lib_class(cls.path):
        return False
    mod_token = (jar.mod_id or "").lower().replace("-", "")
    if mod_token and mod_token in plain.lower().replace("-", ""):
        return True
    return not _is_known_lib_class(cls.path) and not plain.startswith("net/minecraft/")


def split_mod_and_lib_classes(jar: JarInfo) -> tuple[list[ClassInfo], list[ClassInfo]]:
    if not jar.classes:
        return [], []
    entrypoints = _entrypoint_class_paths(jar)
    mod_own: list[tuple[float, ClassInfo]] = []
    libs: list[tuple[float, ClassInfo]] = []
    for cls in jar.classes:
        score = _score_class_for_llm(cls, entrypoints)
        if _is_mod_own_class(cls, jar):
            score += 25.0
            mod_own.append((score, cls))
        else:
            if _is_nested_jar_class(cls.path):
                score -= 20.0
            elif _is_known_lib_class(cls.path):
                score -= 12.0
            libs.append((score, cls))
    mod_own.sort(key=lambda x: (-x[0], -x[1].size, x[1].path))
    libs.sort(key=lambda x: (-x[0], -x[1].size, x[1].path))
    return [c for _, c in mod_own], [c for _, c in libs]


def rank_classes_for_llm(jar: JarInfo) -> list[ClassInfo]:
    mod_own, libs = split_mod_and_lib_classes(jar)
    if mod_own:
        return mod_own + libs
    entrypoints = _entrypoint_class_paths(jar)
    scored = [(_score_class_for_llm(cls, entrypoints), cls) for cls in jar.classes]
    scored.sort(key=lambda x: (-x[0], -x[1].size, x[1].path))
    return [cls for _, cls in scored]


def pick_classes_for_llm(jar: JarInfo, max_classes: int) -> list[ClassInfo]:
    ranked = rank_classes_for_llm(jar)
    limit = max(1, max_classes)
    picked = ranked[:limit]
    log.info(
        "LLM кандидаты (%d/%d): %s",
        len(picked),
        len(jar.classes),
        [c.path for c in picked],
    )
    return picked
