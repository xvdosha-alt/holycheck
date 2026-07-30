# holycheck

Сканер Minecraft-модов на **ЗПО** (запрещённые чит-функции): fast-эвристики + опционально ML (двухфакторно).

## Быстрый старт

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

## Возможности

- Fast-скан: паттерны ЗПО, structural hitbox, маскировка под легит-моды, чёрный список
- ML (Clodex/OpenAI-compatible): батч-скан классов мода, приоритет entrypoint над nested libs
- Детект серверных репаков `trntr` / `trntr_pth` (не ЗПО, пометка в отчёте)
- MC &lt; 1.16: только fast, ML пропускается
- Forge `mods.toml`: версия Minecraft из dependency, не из version мода
- Web UI: загрузка пачки, прогресс, история, отчёт

## Метрики UI

- красный — ЗПО %
- фиолетовый — обфускация %
- зелёный — чисто
- в карточке показывается версия Minecraft (`MC 1.20.1`), если удалось вытащить из метаданных

## Конфиг

Скопируй `.env.example` → `.env`. Ключ API в репозиторий не кладётся.

| Переменная | Описание |
|---|---|
| `LLM_MAX_CLASSES` | классов за один ML-запрос (батч) |
| `LLM_MAX_TOTAL_CLASSES` | максимум классов мода на скан |
| `LLM_MODEL` | модель Clodex |
