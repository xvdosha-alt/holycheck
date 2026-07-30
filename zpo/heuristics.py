from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .guide import (
    BANNED_KNOWN_MODS,
    GUIDE,
    LEGIT_BRAND_IDS,
    NON_ZPO_ALLOWED_VISUAL_PATTERNS,
    NON_ZPO_MALWARE_PATTERNS,
    TRNTR_REPACK_PATTERNS,
    GuidePoint,
)
from .jar_parser import JarInfo

log = logging.getLogger(__name__)

STRONG_PATTERNS = (
    r"killaura",
    r"kill.?aura",
    r"triggerbot",
    r"trigger.?bot",
    r"(?<![A-Za-z])aimbot(?![A-Za-z])",
    r"AimbotModule",
    r"playeresp",
    r"PlayerESP",
    r"storage.?esp",
    r"chest.?esp",
    r"HitboxESP",
    r"(?<![A-Za-z])hitbox.?esp(?![A-Za-z])",
    r"entity.?silhouette",
    r"player.?silhouette",
    r"HealthBarESP",
    r"hitbox.?health",
    r"(?i)(?<![A-Za-z0-9_])xray(?:module|hack|esp)(?![A-Za-z0-9_])",
    r"XrayModule",
    r"XRayModule",
    r"/xray/",
    r"oreEsp",
    r"OreESP",
    r"ore.?finder",
    r"ore[_-]esp",
    r"freecam",
    r"free.?cam",
    r"FORCED_GLOW",
    r"onIsGlowing",
    r"onIsInvisible",
    r"shouldUnload",
    r"t\.me/ghostbitbox",
    r"ghostbitbox\.t\.me",
    r"ATTACK_DELAY_MS",
    r"criticalsOnly",
    r"canPerformCritical",
    r"baritone",
    r"BaritoneAPI",
    r"selfdestruct",
    r"crystal.?aura",
    r"auto.?crystal",
    r"AutoCrystal",
    r"autocrystal",
    r"auto.?swap",
    r"AutoSwap",
    r"autoswap",
    r"elytra.?swap",
    r"ElytraSwap",
    r"elytraswap",
    r"shift.?tap",
    r"ShiftTap",
    r"shifttap",
    r"auto.?eat",
    r"AutoEat",
    r"autoeat",
    r"AutoSellModule",
    r"AutoBuyModule",
    r"stash.?stealer",
    r"targetbot",
    r"target.?bot",
    r"TargetBot",
    r"killaura",
    r"kill.?aura",
    r"KillAura",
    r"reach.?hack",
    r"hitbox.?expander",
    r"increaseHitbox",
    r"decreaseHitbox",
    r"applyHitboxScale",
    r"enlargedHitbox",
    r"updateHitboxes",
    r"restoreAllHitboxes",
    r"hitboxScale",
    r"hitboxSize",
    r"key\.hitboxmod",
    r"panicModeBinding",
    r"increaseHitboxKey",
    r"decreaseHitboxKey",
    r"resetHitboxKey",
    r"increaseHitboxBinding",
    r"decreaseHitboxBinding",
    r"expandServerPlayersHitboxes",
    r"hitboxExpansionSize",
    r"getHitboxScale",
    r"customhitboxes",
    r"CustomHitboxes",
    r"renderDebugBoundingBox",
    r"renderBoundingBox",
    r"oldHitbox",
    r"TargetESP",
    r"TapeMouse",
    r"tapemouse",
    r"topkasize",
    r"TopkaSIZE",
    r"autoinvise",
    r"autoleave",
    r"invisibleKey",
    r"invisibleMode",
    r"wallhack",
    r"true.?sight",
    r"elytra.?hack",
    r"NoFallHack",
    r"FlyHack",
    r"SpeedHack",
    r"world.?download",
    r"chunk.?download",
    r"seed.?crack",
    r"antidump",
    r"cloak.?mod",
    r"mod.?hider",
    r"NESTED_SUSPICIOUS:",
)

@dataclass
class Hit:
    point: GuidePoint
    evidence: list[str] = field(default_factory=list)
    score: float = 0.0
    strong: bool = False

@dataclass
class HeuristicResult:
    hits: list[Hit]
    brand_spoof: bool
    brand_notes: list[str]
    malware_notes: list[str]
    percent: float
    is_zpo: bool

def _blob(jar: JarInfo) -> str:
    parts = [
        jar.mod_id or "",
        jar.mod_name or "",
        " ".join(jar.packages),
        " ".join(str(v) for v in (jar.entrypoints or {}).values()),
    ]
    for cls in jar.classes:
        parts.append(cls.path)
        parts.extend(cls.methods)
        parts.extend(cls.fields)
    parts.extend(jar.all_strings)
    return "\n".join(parts)

def _class_body(cls) -> str:
    return " ".join([cls.path, *cls.strings, *cls.methods, *cls.fields])

def check_structural_hitbox_signals(jar: JarInfo) -> list[str]:
    notes: list[str] = []
    for cls in jar.classes:
        path = cls.path
        path_low = path.lower()
        body = _class_body(cls)
        body_low = body.lower()

        if re.search(r"expandServerPlayersHitboxes|hitboxExpansionSize", body):
            notes.append(f"{path}: expandServerPlayersHitboxes / hitboxExpansionSize")
            continue

        if re.search(r"customhitboxes|renderdebugboundingbox", body_low) and re.search(
            r"renderboundingbox|oldhitbox", body_low
        ):
            notes.append(f"{path}: кастомный ESP/рендер хитбоксов")
            continue

        if re.search(r"(?:^|/)modules/hitbox\.class$", path_low):
            if re.search(r"RenderPlayerEvent|AxisAlignedBB|getBoundingBox|func_174813_aQ", body, re.I):
                notes.append(f"{path}: combat-модуль Hitbox меняет bounding box игрока")
                continue

        if path_low.endswith("/hitbox.class") and "customhitbox" not in path_low:
            if re.search(r"RenderPlayerEvent|AxisAlignedBB|getBoundingBox|func_174813_aQ", body, re.I):
                notes.append(f"{path}: класс Hitbox с RenderPlayerEvent/AxisAlignedBB")
                continue

        if re.search(r"alpine/minimap/", path_low) and re.search(
            r"expandServerPlayersHitboxes|hitboxExpansionSize", body
        ):
            notes.append(f"{path}: fake minimap с расширением хитбоксов")
    if notes:
        log.warning("структурные hitbox-сигналы: %s", notes[:4])
    return notes

def _find_evidence(blob: str, patterns: tuple[str, ...], limit: int = 6) -> list[str]:
    found: list[str] = []
    for pat in patterns:
        try:
            rx = re.compile(pat, re.I)
        except re.error:
            continue
        for m in rx.finditer(blob):
            start = max(0, m.start() - 40)
            end = min(len(blob), m.end() + 40)
            snippet = re.sub(r"\s+", " ", blob[start:end]).strip()
            if len(snippet) > 160:
                snippet = snippet[:160] + "…"
            hit_text = m.group(0)
            if len(hit_text) <= 3 and not re.search(r"[_\.-]", hit_text):
                continue
            if snippet and snippet not in found:
                found.append(f"{hit_text} :: {snippet}")
            if len(found) >= limit:
                return found
    return found

def _has_strong(blob: str) -> list[str]:
    found = []
    for pat in STRONG_PATTERNS:
        m = re.search(pat, blob, re.I)
        if m:
            found.append(m.group(0))
    return found

def check_brand_spoof(jar: JarInfo) -> tuple[bool, list[str]]:
    notes: list[str] = []
    mod_id = (jar.mod_id or "").lower()
    if not mod_id or mod_id not in LEGIT_BRAND_IDS:
        return False, notes
    expected = LEGIT_BRAND_IDS[mod_id]
    entry_blob = " ".join(
        x if isinstance(x, str) else ".".join(x) if isinstance(x, (list, tuple)) else str(x)
        for vals in (jar.entrypoints or {}).values()
        for x in (vals if isinstance(vals, list) else [vals])
    )
    pkg_blob = " ".join(jar.packages).replace("/", ".")
    combined = f"{entry_blob} {pkg_blob}".lower()
    if not combined.strip():
        return False, notes
    if not any(exp.lower() in combined for exp in expected):
        notes.append(
            f"id={mod_id} заявлен как известный мод, но пакеты/entrypoints чужие "
            f"(ожидались префиксы: {', '.join(expected)}; есть: {pkg_blob[:200]})"
        )
        log.warning("маскировка бренда: %s", notes[-1])
        return True, notes
    return False, notes

def check_non_zpo_malware(blob: str) -> list[str]:
    notes: list[str] = []
    for pat in NON_ZPO_MALWARE_PATTERNS:
        if re.search(pat, blob, re.I):
            notes.append(f"не-ЗПО сигнал (рат/стиллер и т.п.): /{pat}/")
    
    if (
        re.search(r"Blowfish|DESede|javax/crypto/Cipher", blob, re.I)
        and re.search(r"java/net/URL|openStream", blob)
        and re.search(r"java/lang/Runtime|\.exec\(", blob)
    ):
        notes.append(
            "не-ЗПО сигнал: obfuscated dropper (crypto + URL.openStream + Runtime.exec)"
        )
    if notes:
        log.info("обнаружены не-ЗПО malware-сигналы (в процент ЗПО не входят): %s", notes)
    return notes

def check_allowed_visuals(blob: str) -> list[str]:
    notes: list[str] = []
    for pat in NON_ZPO_ALLOWED_VISUAL_PATTERNS:
        if re.search(pat, blob, re.I):
            notes.append(
                f"разрешённый визуал (не бан): /{pat}/ — HP без наведения / партиклы / круги"
            )
    if notes:
        log.info("разрешённые визуалы (не ЗПО): %s", notes[:4])
    return notes


def check_trntr_repack(jar: JarInfo) -> list[str]:
    notes: list[str] = []
    blob = _blob(jar)
    fname = jar.path.name.lower() if jar.path else ""
    if re.search(r"[-_]trntr\b", fname):
        notes.append("репак сервера: суффикс -trntr в имени файла")
    for pat in TRNTR_REPACK_PATTERNS:
        if re.search(pat, blob, re.I):
            notes.append(
                f"репак сервера trntr: /{pat}/ — custom channel + verifier (не ЗПО, серверная метка)"
            )
            break
    if notes:
        log.info("trntr repack: %s", notes)
    return notes

def _norm_mod_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

def check_banned_known_mods(jar: JarInfo) -> list[str]:
    raw_fields = [
        ("mod_id", jar.mod_id or ""),
        ("mod_name", jar.mod_name or ""),
        ("file", jar.path.stem if jar.path else ""),
    ]
    fields = [(k, v, _norm_mod_token(v)) for k, v in raw_fields if v]
    if not fields:
        return []

    found: list[str] = []
    for banned in BANNED_KNOWN_MODS:
        bn = _norm_mod_token(banned)
        if len(bn) < 3:
            continue
        for key, raw, compact in fields:
            if not compact:
                continue
            
            if len(bn) <= 5:
                hit = compact == bn
            elif len(bn) <= 10:
                hit = compact == bn or compact.startswith(bn + "client") or compact.endswith(bn)
            else:
                hit = compact == bn or compact.startswith(bn) or compact.endswith(bn) or bn in compact
            if hit and bn == "doomsday" and "translation" in compact:
                hit = False
            if hit:
                found.append(f"чёрный список: «{banned}» ↔ {key}={raw}")
                break
    if found:
        log.warning("известный запрещённый мод: %s", found)
    return found

def analyze_heuristics(jar: JarInfo) -> HeuristicResult:
    blob = _blob(jar)
    spoof, brand_notes = check_brand_spoof(jar)
    structural_hits = check_structural_hitbox_signals(jar)
    malware_notes = check_non_zpo_malware(blob) + check_allowed_visuals(blob) + check_trntr_repack(jar)
    banned_hits = check_banned_known_mods(jar)
    strong_hits = _has_strong(blob)
    nested_bad = [n for n in jar.nested_jars if n.suspicious]

    if not strong_hits and not spoof and not nested_bad and not banned_hits and not structural_hits:
        log.info("heuristic: is_zpo=False percent=0.0 (нет strong-сигнала)")
        return HeuristicResult(
            hits=[],
            brand_spoof=False,
            brand_notes=brand_notes,
            malware_notes=malware_notes,
            percent=0.0,
            is_zpo=False,
        )

    hits: list[Hit] = []
    for point in GUIDE:
        if point.id == "known.banned_client":
            continue
        evidence = _find_evidence(blob, point.patterns)
        if not evidence:
            continue
        point_strong = bool(_has_strong(" ".join(evidence))) or any(
            re.search(p, "\n".join(point.patterns), re.I) and re.search(p, blob, re.I)
            for p in STRONG_PATTERNS
        )
        if not point_strong and point.id != "bypass.jar_in_jar":
            continue
        if point.id == "bypass.jar_in_jar" and not nested_bad and "NESTED_SUSPICIOUS:" not in blob:
            continue
        hit = Hit(point=point, evidence=evidence, score=point.weight, strong=True)
        hits.append(hit)
        log.info("hit STRONG [%s] %s | evidence=%s", point.category, point.title, evidence[:2])

    if banned_hits:
        hits.append(
            Hit(
                point=GuidePoint(
                    "known.banned_client",
                    "Известные читы",
                    "совпадение имени с чёрным списком (слабый сигнал)",
                    5,
                    (),
                ),
                evidence=banned_hits,
                score=5,
                strong=False,
            )
        )

    if spoof:
        fake_point = GuidePoint(
            "bypass.brand_spoof",
            "Обходы",
            "маскировка чита под названием легитимного мода",
            20,
            (),
        )
        hits.append(Hit(point=fake_point, evidence=brand_notes, score=20, strong=True))

    if nested_bad and not any(h.point.id == "bypass.jar_in_jar" for h in hits):
        notes = [f"{n.path}: {n.reason} (id={n.mod_id})" for n in nested_bad]
        hits.append(
            Hit(
                point=GuidePoint(
                    "bypass.jar_in_jar",
                    "Обходы",
                    "подложенный nested-jar / маскировка чита внутри легитимного мода",
                    22,
                    (),
                ),
                evidence=notes,
                score=22,
                strong=True,
            )
        )

    if structural_hits and not any(h.point.id == "combat.hitbox" for h in hits):
        hits.append(
            Hit(
                point=GuidePoint(
                    "combat.hitbox",
                    "Бой",
                    "увеличение или изменение хитбоксов",
                    18,
                    (),
                ),
                evidence=structural_hits[:6],
                score=18,
                strong=True,
            )
        )

    if not hits and strong_hits:
        hits.append(
            Hit(
                point=GuidePoint(
                    "strong.signal",
                    "ЗПО",
                    "сильный чит-сигнал в коде",
                    40,
                    (),
                ),
                evidence=strong_hits[:6],
                score=40,
                strong=True,
            )
        )

    raw = sum(h.score for h in hits)
    percent = min(100.0, round(raw, 1))
    name_only = bool(hits) and all(h.point.id == "known.banned_client" for h in hits)
    is_zpo = bool(hits) and not name_only
    if name_only:
        percent = min(percent, 8.0)
        malware_notes = list(malware_notes) + [
            f"слабый сигнал по имени (не ЗПО само по себе): {e}"
            for h in hits
            for e in h.evidence[:2]
        ]
        hits = []
    elif is_zpo and percent < 25:
        percent = 25.0

    log.info("heuristic: is_zpo=%s percent=%.1f hits=%d", is_zpo, percent, len(hits))
    return HeuristicResult(
        hits=hits,
        brand_spoof=spoof,
        brand_notes=brand_notes,
        malware_notes=malware_notes,
        percent=percent,
        is_zpo=is_zpo,
    )
