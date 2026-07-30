from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

def setup_logging(logs_dir: Path, jar_name: str | None = None) -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = f"_{Path(jar_name).stem}" if jar_name else "_batch"
    log_path = logs_dir / f"zpo{suffix}_{stamp}.log"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    root.addHandler(fh)
    root.addHandler(sh)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger(__name__).debug("log file: %s", log_path)
    return log_path
