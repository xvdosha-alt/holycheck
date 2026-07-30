from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from zpo.config import load_config
from zpo.evidence import build_evidence_report, evidence_to_dict
from zpo.heuristics import analyze_heuristics
from zpo.jar_parser import is_mc_below_116, parse_jar
from zpo.llm import LlmResult, analyze_jar_with_llm
from zpo.obfuscation import analyze_obfuscation
from zpo.report import merge_verdict

log = logging.getLogger("web")

ROOT = Path(__file__).resolve().parent.parent
UPLOADS = ROOT / "uploads"
HISTORY_PATH = UPLOADS / "history.json"
WEB_DIR = Path(__file__).resolve().parent

FAST_WORKERS = 8
ML_WORKERS = 1
ML_GAP_SEC = 0.8

app = FastAPI(title="HolyCheck ZPO")
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

_lock = threading.Lock()
JOBS: dict[str, dict] = {}
CANCEL: dict[str, threading.Event] = {}
GLOBAL_STOP = threading.Event()
_subscribers: dict[str, list[asyncio.Queue]] = {}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _job_dir(job_id: str) -> Path:
    return UPLOADS / job_id

def _meta_path(job_id: str) -> Path:
    return _job_dir(job_id) / "meta.json"

def _result_path(job_id: str, filename: str) -> Path:
    safe = filename.replace("/", "_")
    return _job_dir(job_id) / "results" / f"{safe}.json"

def _save_meta(job: dict) -> None:
    job_id = job["id"]
    path = _meta_path(job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {k: v for k, v in job.items() if k not in {"_task"}}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    _touch_history(job)

def _save_result(job_id: str, result: dict) -> None:
    path = _result_path(job_id, result["file"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

def _load_history_all() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    try:
        return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

def _load_history() -> list[dict]:
    return [x for x in _load_history_all() if not x.get("hidden")]

def _save_history_all(items: list[dict]) -> None:
    UPLOADS.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(items[:200], ensure_ascii=False, indent=2), encoding="utf-8")

def _touch_history(job: dict) -> None:
    items = [x for x in _load_history_all() if x.get("id") != job["id"]]
    items.insert(
        0,
        {
            "id": job["id"],
            "created_at": job.get("created_at"),
            "updated_at": job.get("updated_at") or _now(),
            "files": len(job.get("files") or []),
            "phase": job.get("phase"),
            "status": job.get("status"),
            "use_ml": job.get("use_ml"),
            "fast_done": job.get("fast_done", 0),
            "ml_done": job.get("ml_done", 0),
            "zpo_count": sum(1 for r in (job.get("results") or {}).values() if r.get("zpo")),
            "hidden": False,
        },
    )
    _save_history_all(items)

def _is_job_hidden(job_id: str) -> bool:
    for item in _load_history_all():
        if item.get("id") == job_id:
            return bool(item.get("hidden"))
    return False

def _load_job_from_disk(job_id: str) -> dict | None:
    meta = _meta_path(job_id)
    if not meta.exists():
        return None
    try:
        job = json.loads(meta.read_text(encoding="utf-8"))
    except Exception:
        return None
    results_dir = _job_dir(job_id) / "results"
    results = {}
    if results_dir.exists():
        for p in results_dir.glob("*.json"):
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
                results[r.get("file") or p.stem] = r
            except Exception:
                pass
    job["results"] = results
    job["dir"] = str(_job_dir(job_id))
    return job

def _get_job(job_id: str) -> dict | None:
    with _lock:
        if job_id in JOBS:
            return JOBS[job_id]
    job = _load_job_from_disk(job_id)
    if job:
        with _lock:
            JOBS[job_id] = job
            CANCEL.setdefault(job_id, threading.Event())
    return job

async def _publish(job_id: str, event: dict) -> None:
    event["ts"] = time.time()
    data = f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
    queues = list(_subscribers.get(job_id, []))
    for q in queues:
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            pass

def _file_hashes(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _scan_fast(path: Path) -> dict:
    jar = parse_jar(path)
    heur = analyze_heuristics(jar)
    obf = analyze_obfuscation(jar)
    llm = LlmResult(enabled=False, ok=False, error="fast_phase")
    verdict = merge_verdict(jar, heur, obf, llm)
    evidence = evidence_to_dict(build_evidence_report(jar, heur)) if heur.is_zpo else []
    classes_preview = [
        {"path": c.path, "size": c.size, "strings_sample": c.strings[:30]}
        for c in sorted(jar.classes, key=lambda x: -x.size)[:40]
    ]
    nested = [
        {
            "path": n.path,
            "mod_id": n.mod_id,
            "suspicious": n.suspicious,
            "reason": n.reason,
            "entrypoints": n.entrypoints,
        }
        for n in jar.nested_jars
    ]
    md5, sha256 = _file_hashes(path)
    mc_below_116 = is_mc_below_116(jar.mc_version) is True
    summary = verdict.summary
    if mc_below_116:
        note = f"Minecraft < 1.16 ({jar.mc_version or '?'}) — только fast-скан"
        summary = f"{summary} {note}".strip() if summary else note
    return {
        "file": path.name,
        "md5": md5,
        "sha256": sha256,
        "mod_id": jar.mod_id,
        "mod_name": jar.mod_name,
        "mod_version": jar.mod_version,
        "mc_version": jar.mc_version,
        "mc_below_116": mc_below_116,
        "skip_ml": mc_below_116,
        "loader": jar.loader,
        "size": jar.size,
        "packages": jar.packages[:50],
        "entrypoints": jar.entrypoints,
        "nested_jars": nested,
        "phase": "fast",
        "zpo_fast": verdict.zpo,
        "percent_fast": verdict.percent,
        "zpo_ml": None,
        "percent_ml": None,
        "ml_confidence": None,
        "factors": {"fast": bool(verdict.zpo), "ml": None},
        "zpo": verdict.zpo,
        "percent": verdict.percent,
        "guide_points": verdict.guide_points,
        "obfuscated": verdict.obfuscated,
        "obfuscation_percent": verdict.obfuscation_percent,
        "obfuscation_notes": verdict.obfuscation_notes,
        "malware_notes": verdict.malware_notes,
        "summary": summary,
        "evidence": evidence,
        "classes": classes_preview,
        "ml_summary": "Minecraft < 1.16 — только fast-скан" if mc_below_116 else None,
        "factor_status": "legacy_mc" if mc_below_116 else None,
    }

def _two_factor(fast: dict, ml: LlmResult) -> dict:
    out = dict(fast)
    out["phase"] = "ml"
    out["zpo_ml"] = bool(ml.is_zpo) if ml.ok else None
    out["percent_ml"] = float(ml.confidence) if ml.ok else None
    out["ml_confidence"] = float(ml.confidence) if ml.ok else None
    out["ml_summary"] = ml.summary or None
    out["ml_classes_scanned"] = int(ml.classes_scanned) if ml.ok and ml.classes_scanned else None
    out["ml_batches"] = int(ml.batches) if ml.ok and ml.batches else None
    out["factors"] = {
        "fast": bool(fast.get("zpo_fast")),
        "ml": bool(ml.is_zpo) if ml.ok else None,
    }

    if ml.ok and ml.guide_points:
        points = list(fast.get("guide_points") or [])
        for p in ml.guide_points:
            p = str(p).strip()
            if p and len(p) <= 140 and p not in points:
                points.append(p)
        out["guide_points"] = points

    if ml.ok and ml.evidence:
        out["summary"] = ml.summary or fast.get("summary")

    
    
    f = bool(fast.get("zpo_fast"))
    m = bool(ml.is_zpo) if ml.ok else False
    conf = float(ml.confidence or 0) if ml.ok else 0

    
    points = " ".join(str(p) for p in (fast.get("guide_points") or [])).lower()
    evidence_blob = " ".join(
        str(s.get("string") or s.get("pattern") or "")
        for ev in (fast.get("evidence") or [])
        for s in (ev.get("strings") or [])
    ).lower()
    hard_fast = any(
        x in points
        for x in (
            "хитбокс",
            "hitbox",
            "killaura",
            "triggerbot",
            "aimbot",
            "freecam",
            "playeresp",
            "маскировка",
            "combat.",
        )
    ) or any(
        x in evidence_blob
        for x in (
            "killaura",
            "triggerbot",
            "aimbot",
            "freecam",
            "playeresp",
            "hitbox",
            "brand_spoof",
        )
    )
    soft_only = f and not hard_fast and any(
        "инвентарь" in p or "поиск" in p or "визуал" in p
        for p in (str(x).lower() for x in (fast.get("guide_points") or []))
    ) and not any(
        x in points
        for x in ("хитбокс", "hitbox", "killaura", "triggerbot", "aimbot", "freecam", "combat.", "маскировка")
    )

    if f and m:
        out["zpo"] = True
        out["percent"] = min(100.0, max(float(fast.get("percent_fast") or 0), conf, 55.0))
        out["factor_status"] = "2/2"
    elif f and ml.ok and not m and (conf >= 70 or (soft_only and conf >= 20)) and not hard_fast:
        out["zpo"] = False
        out["percent"] = min(15.0, float(fast.get("percent_fast") or 0) * 0.2)
        out["factor_status"] = "ml_override_clean"
    elif f and ml.ok and not m and hard_fast:
        out["zpo"] = True
        out["percent"] = min(100.0, max(45.0, float(fast.get("percent_fast") or 0) * 0.85))
        out["factor_status"] = "1/2_fast_hard"
    elif f:
        out["zpo"] = True
        out["percent"] = min(100.0, max(35.0, float(fast.get("percent_fast") or 0) * 0.75))
        out["factor_status"] = "1/2_fast"
    elif m and conf >= 60:
        out["zpo"] = True
        out["percent"] = min(100.0, max(40.0, conf * 0.85))
        out["factor_status"] = "1/2_ml"
    else:
        out["zpo"] = False
        out["percent"] = 0.0
        out["factor_status"] = "0/2"

    if out["zpo"] and out["percent"] < 25:
        out["percent"] = 25.0
    return out

def _scan_ml(path: Path, fast: dict) -> dict:
    jar = parse_jar(path)
    heur = analyze_heuristics(jar)
    obf = analyze_obfuscation(jar)
    cfg = load_config()
    llm = analyze_jar_with_llm(
        cfg,
        jar,
        [f"{h.point.category}: {h.point.title}" for h in heur.hits],
        obf.is_obfuscated,
        malware_notes=heur.malware_notes,
    )
    if not llm.ok:
        out = dict(fast)
        out["phase"] = "ml"
        out["factor_status"] = "ml_error"
        out["ml_summary"] = llm.error or "ml failed"
        out["factors"] = {"fast": bool(fast.get("zpo_fast")), "ml": None}
        return out
    return _two_factor(fast, llm)

def _is_cancelled(job_id: str) -> bool:
    if GLOBAL_STOP.is_set():
        return True
    ev = CANCEL.get(job_id)
    return bool(ev and ev.is_set())

async def _run_job(job_id: str) -> None:
    job = _get_job(job_id)
    if not job:
        return
    job_dir = Path(job["dir"])
    files = list(job["files"])
    total = len(files)
    await _publish(job_id, {"type": "start", "phase": "fast", "total": total, "files": files})

    job["status"] = "fast"
    job["phase"] = "fast"
    job["updated_at"] = _now()
    _save_meta(job)

    fast_done = 0
    loop = asyncio.get_running_loop()

    def fast_one(name: str) -> tuple[str, dict | None, str | None]:
        if _is_cancelled(job_id):
            return name, None, "stopped"
        path = job_dir / name
        try:
            return name, _scan_fast(path), None
        except Exception as exc:
            log.exception("fast fail %s", name)
            return name, None, str(exc)

    with ThreadPoolExecutor(max_workers=FAST_WORKERS) as pool:
        futs = [loop.run_in_executor(pool, fast_one, name) for name in files]
        for fut in asyncio.as_completed(futs):
            if _is_cancelled(job_id):
                break
            name, result, err = await fut
            fast_done += 1
            if result is None:
                result = {
                    "file": name,
                    "zpo": False,
                    "percent": 0,
                    "error": err or "fail",
                    "phase": "fast",
                    "zpo_fast": False,
                    "percent_fast": 0,
                    "guide_points": [],
                    "evidence": [],
                    "factors": {"fast": False, "ml": None},
                }
            with _lock:
                job["results"][name] = result
                job["fast_done"] = fast_done
                job["updated_at"] = _now()
            _save_result(job_id, result)
            _save_meta(job)
            await _publish(
                job_id,
                {
                    "type": "result",
                    "phase": "fast",
                    "index": fast_done,
                    "total": total,
                    "result": result,
                },
            )

    if _is_cancelled(job_id):
        job["status"] = "stopped"
        job["phase"] = "stopped"
        job["updated_at"] = _now()
        _save_meta(job)
        await _publish(job_id, {"type": "stopped", "phase": "fast", "total": total, "done": fast_done})
        return

    await _publish(job_id, {"type": "phase_done", "phase": "fast", "total": total})

    if not job.get("use_ml"):
        job["status"] = "done"
        job["phase"] = "done"
        job["updated_at"] = _now()
        _save_meta(job)
        await _publish(job_id, {"type": "done", "phase": "fast", "total": total})
        return

    job["status"] = "ml"
    job["phase"] = "ml"
    job["updated_at"] = _now()
    _save_meta(job)
    await _publish(job_id, {"type": "start", "phase": "ml", "total": total, "workers": ML_WORKERS})

    ml_done = 0

    def ml_one(name: str) -> tuple[str, dict | None, str | None]:
        if _is_cancelled(job_id):
            return name, None, "stopped"
        if ML_GAP_SEC > 0:
            time.sleep(ML_GAP_SEC)
        path = job_dir / name
        fast = job["results"].get(name) or {}
        if fast.get("skip_ml") or fast.get("mc_below_116"):
            out = dict(fast)
            out["phase"] = "ml"
            out["factor_status"] = "legacy_mc"
            out["ml_summary"] = out.get("ml_summary") or "Minecraft < 1.16 — только fast-скан"
            out["factors"] = {"fast": bool(fast.get("zpo_fast")), "ml": None}
            return name, out, None
        try:
            return name, _scan_ml(path, fast), None
        except Exception as exc:
            log.exception("ml fail %s", name)
            return name, None, str(exc)

    with ThreadPoolExecutor(max_workers=ML_WORKERS) as pool:
        futs = [loop.run_in_executor(pool, ml_one, name) for name in files]
        for fut in asyncio.as_completed(futs):
            if _is_cancelled(job_id):
                break
            name, result, err = await fut
            ml_done += 1
            if result is None:
                result = dict(job["results"].get(name) or {"file": name})
                result["phase"] = "ml"
                result["error"] = err or "ml fail"
                result["factor_status"] = "ml_error"
            with _lock:
                job["results"][name] = result
                job["ml_done"] = ml_done
                job["updated_at"] = _now()
            _save_result(job_id, result)
            _save_meta(job)
            await _publish(
                job_id,
                {
                    "type": "result",
                    "phase": "ml",
                    "index": ml_done,
                    "total": total,
                    "result": result,
                },
            )

    if _is_cancelled(job_id):
        job["status"] = "stopped"
        job["phase"] = "stopped"
        job["updated_at"] = _now()
        _save_meta(job)
        await _publish(job_id, {"type": "stopped", "phase": "ml", "total": total, "done": ml_done})
        return

    job["status"] = "done"
    job["phase"] = "done"
    job["updated_at"] = _now()
    _save_meta(job)
    await _publish(job_id, {"type": "done", "phase": "ml", "total": total})

@app.get("/")
async def index():
    return FileResponse(WEB_DIR / "templates" / "index.html")

@app.post("/api/scan")
async def create_scan(
    files: list[UploadFile] = File(...),
    use_ml: bool = Query(False),
):
    GLOBAL_STOP.clear()
    job_id = uuid.uuid4().hex[:12]
    job_dir = _job_dir(job_id)
    (job_dir / "results").mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        name = Path(f.filename or "unknown.jar").name
        if not name.lower().endswith((".jar", ".zip")):
            continue
        dest = job_dir / name
        with dest.open("wb") as out:
            shutil.copyfileobj(f.file, out)
        saved.append(name)

    job = {
        "id": job_id,
        "dir": str(job_dir),
        "files": saved,
        "use_ml": bool(use_ml),
        "results": {},
        "status": "queued",
        "phase": "queued",
        "fast_done": 0,
        "ml_done": 0,
        "created_at": _now(),
        "updated_at": _now(),
    }
    with _lock:
        JOBS[job_id] = job
        CANCEL[job_id] = threading.Event()
    _save_meta(job)
    asyncio.create_task(_run_job(job_id))
    return {"job_id": job_id, "files": saved, "use_ml": bool(use_ml)}

@app.get("/api/scan/{job_id}")
async def get_job(job_id: str):
    if _is_job_hidden(job_id):
        return {"error": "job not found"}
    job = _get_job(job_id)
    if not job:
        return {"error": "job not found"}
    return {
        "id": job["id"],
        "files": job.get("files") or [],
        "status": job.get("status"),
        "phase": job.get("phase"),
        "use_ml": job.get("use_ml"),
        "fast_done": job.get("fast_done", 0),
        "ml_done": job.get("ml_done", 0),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "results": job.get("results") or {},
    }

@app.get("/api/scan/{job_id}/events")
async def scan_events(job_id: str):
    if _is_job_hidden(job_id):
        return StreamingResponse(
            iter([f"data: {json.dumps({'type': 'error', 'message': 'job not found'})}\n\n"]),
            media_type="text/event-stream",
        )
    job = _get_job(job_id)
    if not job:
        return StreamingResponse(
            iter([f"data: {json.dumps({'type': 'error', 'message': 'job not found'})}\n\n"]),
            media_type="text/event-stream",
        )

    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _subscribers.setdefault(job_id, []).append(queue)

    async def gen():
        try:
            snap = {
                "type": "snapshot",
                "job": {
                    "id": job["id"],
                    "files": job.get("files") or [],
                    "status": job.get("status"),
                    "phase": job.get("phase"),
                    "use_ml": job.get("use_ml"),
                    "fast_done": job.get("fast_done", 0),
                    "ml_done": job.get("ml_done", 0),
                },
                "results": list((job.get("results") or {}).values()),
            }
            yield f"data: {json.dumps(snap, ensure_ascii=False)}\n\n"
            if job.get("status") in {"done", "stopped"}:
                yield f"data: {json.dumps({'type': job['status'], 'phase': job.get('phase'), 'total': len(job.get('files') or [])}, ensure_ascii=False)}\n\n"
                return
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield data
                    if '"type": "done"' in data or '"type": "stopped"' in data:
                        break
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
                    job2 = _get_job(job_id)
                    if job2 and job2.get("status") in {"done", "stopped"}:
                        yield f"data: {json.dumps({'type': job2['status'], 'phase': job2.get('phase'), 'total': len(job2.get('files') or [])}, ensure_ascii=False)}\n\n"
                        break
        finally:
            subs = _subscribers.get(job_id, [])
            if queue in subs:
                subs.remove(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")

@app.post("/api/scan/{job_id}/stop")
async def stop_job(job_id: str):
    job = _get_job(job_id)
    if not job:
        return {"error": "job not found"}
    CANCEL.setdefault(job_id, threading.Event()).set()
    return {"ok": True, "job_id": job_id}

@app.post("/api/stop")
async def stop_all():
    GLOBAL_STOP.set()
    with _lock:
        for job_id, ev in CANCEL.items():
            ev.set()
        ids = list(JOBS.keys())
    return {"ok": True, "stopped": ids}

@app.get("/api/history")
async def history():
    return {"items": _load_history()}

@app.post("/api/history/clear-last")
async def clear_last_logs():
    items = _load_history_all()
    cleared_job = None
    visible = [x for x in items if not x.get("hidden")]
    if visible:
        cleared_job = visible[0].get("id")
        for item in items:
            if item.get("id") == cleared_job:
                item["hidden"] = True
                item["hidden_at"] = _now()
                break
        _save_history_all(items)

    return {
        "ok": True,
        "cleared_job": cleared_job,
        "cleared_logs": [],
        "history_left": len([x for x in items if not x.get("hidden")]),
        "kept_on_disk": True,
    }
