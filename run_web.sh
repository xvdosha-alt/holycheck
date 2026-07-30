#!/usr/bin/env bash
cd "$(dirname "$0")"
exec .venv/bin/uvicorn web.app:app --host 127.0.0.1 --port 8787 --reload
