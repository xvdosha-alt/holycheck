EN | [RU](docs/README_RU.md)

# holycheck

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)


Minecraft mod scanner for **ZPO** (forbidden cheat features): fast heuristics + optional ML (two-factor).

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
./run_web.sh
```

UI: http://127.0.0.1:8787

## CLI

```bash
.venv/bin/python collect_mods.py
.venv/bin/python fast_dump.py
.venv/bin/python check_zpo.py --no-llm
.venv/bin/python check_zpo.py path/to/mod.jar
```

## Features

- Fast scan: ZPO patterns, structural hitbox, disguise as legit mods, blacklist
- ML (Clodex/OpenAI-compatible): batch scan of mod classes, entrypoint priority over nested libs
- Detect server repacks `trntr` / `trntr_pth` (not ZPO, flagged in report)
- MC < 1.16: fast only, ML skipped
- Forge `mods.toml`: Minecraft version from dependency, not from mod version
- Web UI: batch upload, progress, history, report

## UI metrics

- red - ZPO %
- purple - obfuscation %
- green - clean
- card shows Minecraft version (`MC 1.20.1`) when extracted from metadata

## Config

Copy `.env.example` -> `.env`. API key is not stored in the repository.

| Variable | Description |
|---|---|
| `LLM_MAX_CLASSES` | classes per ML request (batch) |
| `LLM_MAX_TOTAL_CLASSES` | max mod classes per scan |
| `LLM_MODEL` | Clodex model |
