from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field

import requests

from .config import Config
from .jar_parser import ClassInfo, JarInfo, class_digest
from .obfuscation import rank_classes_for_llm, split_mod_and_lib_classes

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """Проверка Minecraft-модов на ЗПО. Ответ — только JSON без markdown.
ЯЗЫК: все текстовые поля (guide_points, evidence, malware_notes, summary) ТОЛЬКО на русском. Не используй английский.
ЗПО=читы: аура, триггербот, аим, автоклик, хитбоксы, xray, freecam, ESP/box/silhouette, glow, baritone, маскировка.
НЕ ЗПО: rat/stealer→malware_notes, UI/оптимизаторы, HP без прицела, частицы/круги, HP-плашки над мобами (Orderly/Neat).
trntr_pth/xtrs_pth/-trntr в имени — серверный репак с channel-verifier (не ЗПО, упомяни в malware_notes если есть).
META-INF/jars/, cloth-config, shedaniel — вложенные библиотеки; вердикт по КЛАССАМ САМОГО МОДА (entrypoint), не по dependency.
Не выдумывай назначение мода — опирайся на mod_id, mod_name, description и классы entrypoint-пакета.
БАН: силуэт хитбокса/игрока; HP-полоски размером с хитбокс.
Обфускация сама по себе ≠ ЗПО.
{"is_zpo":bool,"confidence":0-100,"guide_points":[],"obfuscated_classes":[],"evidence":[],"malware_notes":[],"summary":"1 предложение на русском"}"""

def _mini_class_digest(cls: ClassInfo) -> str:
    methods = sorted(set(cls.methods))[:10]
    fields = sorted(set(cls.fields))[:10]
    keys = (
        "attack", "esp", "glow", "aim", "trigger", "crystal", "freecam", "xray",
        "hitbox", "elytra", "aura", "kill", "critical", "swap", "bot", "cheat",
        "indicator", "health", "target", "render", "client", "module", "outline",
    )
    strings: list[str] = []
    for s in cls.strings:
        if len(s) < 4 or len(s) > 96:
            continue
        low = s.lower()
        if any(k in low for k in keys) or re.search(r"[A-Z][a-z]+[A-Z]", s):
            strings.append(s.replace("\n", " ")[:72])
        if len(strings) >= 10:
            break
    if not strings:
        strings = [s.replace("\n", " ")[:48] for s in cls.strings[:6] if 3 <= len(s) <= 96]
    body = (
        f"class={cls.path} size={cls.size}\n"
        f"methods={methods}\n"
        f"fields={fields}\n"
        f"strings={strings[:10]}"
    )
    return body[:520]


def _compact_classes_snippet(classes: list[ClassInfo], max_chars: int = 2800) -> str:
    parts = [_mini_class_digest(c) for c in classes]
    text = "\n---\n".join(parts)
    if len(text) > max_chars:
        text = text[: max_chars - 3] + "..."
    return text


def _compact_class_snippet(classes: list[ClassInfo], max_chars: int = 340) -> str:
    if not classes:
        return "no classes"
    cls = classes[0]
    keys = (
        "attack", "esp", "glow", "aim", "trigger", "crystal", "freecam", "xray",
        "hitbox", "elytra", "aura", "kill", "critical", "swap", "bot", "cheat",
        "invis", "outline", "baritone", "panic", "cooldown",
    )
    picks: list[str] = []
    for s in cls.strings:
        if len(s) < 4 or len(s) > 100:
            continue
        low = s.lower()
        if any(k in low for k in keys) or re.search(r"[A-Z][a-z]+[A-Z]", s):
            picks.append(s.replace("\n", " ")[:72])
        if len(picks) >= 8:
            break
    text = f"{cls.path}: " + " | ".join(picks or cls.strings[:4])
    return text[:max_chars]

def _mod_context(jar: JarInfo) -> str:
    meta = jar.metadata_raw if isinstance(jar.metadata_raw, dict) else {}
    desc = str(meta.get("description") or "").strip()
    nested = ", ".join(n.path.rsplit("/", 1)[-1] for n in jar.nested_jars[:4])
    bits = [f"mod_id={jar.mod_id}", f"mod_name={jar.mod_name}"]
    if desc:
        bits.append(f"description={desc[:200]}")
    if nested:
        bits.append(f"nested_deps={nested}")
    return " ".join(bits)


def _build_user_prompt(
    jar: JarInfo,
    classes: list[ClassInfo],
    heuristic_points: list[str],
    obfuscated: bool,
    compact: bool,
    batch_note: str = "",
    malware_notes: list[str] | None = None,
) -> str:
    hits = heuristic_points[:6]
    mnotes = (malware_notes or [])[:4]
    header = (
        f"file={jar.path.name} {_mod_context(jar)} mc={jar.mc_version} loader={jar.loader}\n"
        f"heuristic_hits={hits} fast_notes={mnotes} obf={obfuscated} classes_in_batch={len(classes)}"
    )
    if batch_note:
        header += f" {batch_note}"
    if compact and len(classes) == 1:
        snippet = _compact_class_snippet(classes, max_chars=280)
        return (f"{header}\n{snippet}\nОтвет на русском.")[:420]
    if len(classes) <= 6:
        digests = _compact_classes_snippet(classes, max_chars=3200)
    else:
        digests = "\n\n".join(class_digest(c, limit=16) for c in classes)
        if len(digests) > 4200:
            digests = digests[:4197] + "..."
    return f"{header}\n\nclasses:\n{digests}\nОтвет на русском."

@dataclass
class LlmResult:
    enabled: bool
    ok: bool
    is_zpo: bool | None = None
    confidence: float = 0.0
    guide_points: list[str] = field(default_factory=list)
    obfuscated_classes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    malware_notes: list[str] = field(default_factory=list)
    summary: str = ""
    raw: str = ""
    error: str | None = None
    classes_scanned: int = 0
    batches: int = 0

def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m.group(0))

def _merge_llm_results(results: list[LlmResult]) -> LlmResult:
    ok = [r for r in results if r.ok]
    if not ok:
        last = results[-1] if results else LlmResult(enabled=True, ok=False, error="llm failed")
        return last

    zpo_hits = [r for r in ok if r.is_zpo]
    if zpo_hits:
        best = max(zpo_hits, key=lambda r: r.confidence)
        guide_points: list[str] = []
        evidence: list[str] = []
        malware_notes: list[str] = []
        obfuscated_classes: list[str] = []
        for r in zpo_hits:
            for p in r.guide_points:
                p = str(p).strip()
                if p and p not in guide_points:
                    guide_points.append(p)
            for p in r.evidence:
                p = str(p).strip()
                if p and p not in evidence:
                    evidence.append(p)
            for p in r.malware_notes:
                p = str(p).strip()
                if p and p not in malware_notes:
                    malware_notes.append(p)
            for p in r.obfuscated_classes:
                p = str(p).strip()
                if p and p not in obfuscated_classes:
                    obfuscated_classes.append(p)
        summary = best.summary or next((r.summary for r in zpo_hits if r.summary), "")
        return LlmResult(
            enabled=True,
            ok=True,
            is_zpo=True,
            confidence=max(r.confidence for r in zpo_hits),
            guide_points=guide_points[:8],
            obfuscated_classes=obfuscated_classes[:8],
            evidence=evidence[:12],
            malware_notes=malware_notes[:8],
            summary=summary,
            classes_scanned=sum(r.classes_scanned for r in ok),
            batches=len(ok),
        )

    best = max(ok, key=lambda r: r.confidence)
    guide_points = []
    evidence = []
    malware_notes = []
    obfuscated_classes = []
    for r in ok:
        for p in r.guide_points:
            p = str(p).strip()
            if p and p not in guide_points:
                guide_points.append(p)
        for p in r.evidence:
            p = str(p).strip()
            if p and p not in evidence:
                evidence.append(p)
        for p in r.malware_notes:
            p = str(p).strip()
            if p and p not in malware_notes:
                malware_notes.append(p)
        for p in r.obfuscated_classes:
            p = str(p).strip()
            if p and p not in obfuscated_classes:
                obfuscated_classes.append(p)
    return LlmResult(
        enabled=True,
        ok=True,
        is_zpo=False,
        confidence=best.confidence,
        guide_points=guide_points[:8],
        obfuscated_classes=obfuscated_classes[:8],
        evidence=evidence[:12],
        malware_notes=malware_notes[:8],
        summary=best.summary,
        classes_scanned=sum(r.classes_scanned for r in ok),
        batches=len(ok),
    )


def _llm_request(cfg: Config, user: str) -> LlmResult:
    url = f"{cfg.llm_base_url}/chat/completions"
    payload = {
        "model": cfg.llm_model,
        "temperature": 0.1,
        "max_tokens": cfg.llm_max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
    }
    headers = {
        "Authorization": f"Bearer {cfg.llm_api_key}",
        "Content-Type": "application/json",
    }

    last_err: Exception | None = None
    for attempt in range(5):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=120)
            log.debug("LLM status=%s body=%s", resp.status_code, resp.text[:4000])
            if resp.status_code == 429:
                wait = min(30.0, 1.5 * (2**attempt))
                log.warning("LLM 429, retry in %.1fs (attempt %d/5)", wait, attempt + 1)
                time.sleep(wait)
                last_err = requests.HTTPError(f"429 Client Error: {url}", response=resp)
                continue
            if resp.status_code in {401, 402, 403}:
                detail = resp.text[:300]
                if attempt < 4:
                    wait = min(8.0, 0.8 * (2**attempt))
                    log.warning("LLM %s attempt %d/5, retry in %.1fs", resp.status_code, attempt + 1, wait)
                    time.sleep(wait)
                    last_err = requests.HTTPError(f"{resp.status_code}: {detail}", response=resp)
                    continue
                log.error("LLM auth/billing error %s: %s", resp.status_code, detail)
                return LlmResult(enabled=True, ok=False, error=f"{resp.status_code}: {detail}")
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = _extract_json(content)
            result = LlmResult(
                enabled=True,
                ok=True,
                is_zpo=bool(parsed.get("is_zpo")),
                confidence=float(parsed.get("confidence") or 0),
                guide_points=[str(x) for x in (parsed.get("guide_points") or [])],
                obfuscated_classes=[str(x) for x in (parsed.get("obfuscated_classes") or [])],
                evidence=[str(x) for x in (parsed.get("evidence") or [])],
                malware_notes=[str(x) for x in (parsed.get("malware_notes") or [])],
                summary=str(parsed.get("summary") or ""),
                raw=content,
            )
            log.info(
                "LLM result is_zpo=%s confidence=%.1f points=%s",
                result.is_zpo,
                result.confidence,
                result.guide_points,
            )
            if result.obfuscated_classes:
                log.warning("LLM: обфусцированные классы: %s", result.obfuscated_classes)
            return result
        except Exception as exc:
            last_err = exc
            wait = min(20.0, 1.2 * (2**attempt))
            log.warning("LLM ошибка attempt %d/5: %s; sleep %.1fs", attempt + 1, exc, wait)
            time.sleep(wait)

    log.exception("LLM ошибка: %s", last_err)
    return LlmResult(enabled=True, ok=False, error=str(last_err or "llm failed"))


def analyze_classes_with_llm(
    cfg: Config,
    jar: JarInfo,
    classes: list[ClassInfo],
    heuristic_points: list[str],
    obfuscated: bool,
    *,
    compact: bool | None = None,
    batch_note: str = "",
    malware_notes: list[str] | None = None,
) -> LlmResult:
    if not cfg.llm_enabled:
        log.info("LLM отключён (LLM_ENABLED=0)")
        return LlmResult(enabled=False, ok=False, error="disabled")
    if not cfg.llm_api_key:
        log.warning("LLM: нет API ключа (LLM_API_KEY / CLODEX_API_KEY)")
        return LlmResult(enabled=True, ok=False, error="no_api_key")

    classes = classes[: max(1, min(len(classes), cfg.llm_max_classes))]
    use_compact = len(classes) == 1 if compact is None else compact
    user = _build_user_prompt(
        jar, classes, heuristic_points, obfuscated, use_compact,
        batch_note=batch_note, malware_notes=malware_notes,
    )

    log.info(
        "LLM request model=%s classes=%d prompt_chars=%d url=%s",
        cfg.llm_model,
        len(classes),
        len(user) + len(SYSTEM_PROMPT),
        f"{cfg.llm_base_url}/chat/completions",
    )
    log.debug("LLM user prompt:\n%s", user[:8000])

    result = _llm_request(cfg, user)
    if result.ok:
        result.classes_scanned = len(classes)
        result.batches = 1
    return result


ML_GAP_SEC = 0.35


def analyze_jar_with_llm(
    cfg: Config,
    jar: JarInfo,
    heuristic_points: list[str],
    obfuscated: bool,
    *,
    malware_notes: list[str] | None = None,
) -> LlmResult:
    if not cfg.llm_enabled:
        return LlmResult(enabled=False, ok=False, error="disabled")
    if not cfg.llm_api_key:
        return LlmResult(enabled=True, ok=False, error="no_api_key")

    mod_own, libs = split_mod_and_lib_classes(jar)
    total_cap = max(cfg.llm_max_classes, cfg.llm_max_total_classes)

    if mod_own:
        if len(mod_own) <= total_cap:
            to_scan = mod_own
        else:
            to_scan = mod_own[:total_cap]
    else:
        ranked = rank_classes_for_llm(jar)
        if not ranked:
            return LlmResult(enabled=True, ok=False, error="no classes")
        if len(jar.classes) <= cfg.llm_max_classes * 2:
            to_scan = ranked
        else:
            to_scan = ranked[:total_cap]

    if not to_scan:
        return LlmResult(enabled=True, ok=False, error="no classes")

    batch_size = max(1, cfg.llm_max_classes)
    batches: list[list[ClassInfo]] = [
        to_scan[i : i + batch_size] for i in range(0, len(to_scan), batch_size)
    ]
    log.info(
        "LLM scan %s: %d classes total, mod_own=%d, scanning %d in %d batch(es)",
        jar.path.name,
        len(jar.classes),
        len(mod_own),
        len(to_scan),
        len(batches),
    )

    results: list[LlmResult] = []
    for idx, batch in enumerate(batches, start=1):
        note = f"batch={idx}/{len(batches)} mod_own={len(mod_own)} jar_classes={len(jar.classes)}"
        result = analyze_classes_with_llm(
            cfg,
            jar,
            batch,
            heuristic_points,
            obfuscated,
            compact=False,
            batch_note=note,
            malware_notes=malware_notes,
        )
        results.append(result)
        if result.ok and result.is_zpo and result.confidence >= 70:
            log.info("LLM early stop: ZPO conf=%.1f batch=%d/%d", result.confidence, idx, len(batches))
            break
        if not result.ok and idx == 1:
            return result
        if not result.ok:
            log.warning("LLM batch %d/%d failed: %s", idx, len(batches), result.error)
        if idx < len(batches):
            time.sleep(ML_GAP_SEC)

    merged = _merge_llm_results(results)
    if merged.ok and not merged.summary:
        for r in reversed(results):
            if r.summary:
                merged.summary = r.summary
                break
    return merged

