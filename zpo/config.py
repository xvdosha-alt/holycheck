from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)

_load_dotenv(ROOT / ".env")

def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

@dataclass(frozen=True)
class Config:
    mods_dir: Path
    logs_dir: Path
    reports_dir: Path
    llm_enabled: bool
    llm_api_key: str
    llm_base_url: str
    llm_model: str
    llm_max_classes: int
    llm_max_total_classes: int
    llm_max_tokens: int

def _normalize_model(model: str) -> str:
    model = (model or "").strip()
    if model.startswith("clodex/"):
        return model.split("/", 1)[1]
    return model

def load_config() -> Config:
    base = os.getenv("LLM_BASE_URL", "https://clodex.xyz/v1").rstrip("/")
    model = _normalize_model(os.getenv("LLM_MODEL", "claude-sonnet-5"))
    return Config(
        mods_dir=(ROOT / os.getenv("MODS_DIR", "mods")).resolve(),
        logs_dir=(ROOT / os.getenv("LOGS_DIR", "logs")).resolve(),
        reports_dir=(ROOT / os.getenv("REPORTS_DIR", "reports")).resolve(),
        llm_enabled=_bool("LLM_ENABLED", True),
        llm_api_key=os.getenv("LLM_API_KEY")
        or os.getenv("CLODEX_API_KEY")
        or os.getenv("OPENROUTER_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or "",
        llm_base_url=base,
        llm_model=model,
        llm_max_classes=int(os.getenv("LLM_MAX_CLASSES", "4")),
        llm_max_total_classes=int(os.getenv("LLM_MAX_TOTAL_CLASSES", "24")),
        llm_max_tokens=int(os.getenv("LLM_MAX_TOKENS", "220")),
    )
