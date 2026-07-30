#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import logging
import shutil
import zipfile
from pathlib import Path

log = logging.getLogger("collect_mods")

SEARCH_ROOTS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / ".minecraft",
    Path.home() / "Library/Application Support/minecraft",
    Path.home() / "Library/Application Support/LabyMod",
    Path.home() / "Library/Application Support/LabyMod Launcher",
    Path.home() / "Library/Application Support/PrismLauncher",
    Path.home() / "Library/Application Support/MultiMC",
    Path.home() / "Library/Application Support/curseforge",
    Path.home() / "Library/Application Support/com.modrinth.theseus",
    Path.home() / "Library/Application Support/feather-launcher",
    Path.home() / "Library/Application Support/gdlauncher_next",
    Path.home() / "Library/Application Support/ATLauncher",
]

def is_minecraft_mod(path: Path) -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            low = {n.lower() for n in names}
            is_server_plugin = (
                "plugin.yml" in low
                or "bungee.yml" in low
                or "velocity-plugin.json" in low
                or "paper-plugin.yml" in low
            )
            has_fabric = "fabric.mod.json" in names
            has_quilt = "quilt.mod.json" in names
            has_forge = "META-INF/mods.toml" in names or "META-INF/neoforge.mods.toml" in names
            has_old = "mcmod.info" in names or "litemod.json" in names
            has_laby = "addon.json" in names or "labymod.json" in names
            has_mixins = any(n.endswith(".mixins.json") for n in names) and any(
                n.endswith(".class") for n in names
            )

            if is_server_plugin and not (has_fabric or has_quilt or has_forge):
                return False, "server_plugin"

            if is_server_plugin and has_fabric and not has_forge and not has_quilt:
                try:
                    import json as _json

                    meta = _json.loads(z.read("fabric.mod.json").decode("utf-8", "replace"))
                    mid = str((meta or {}).get("id") or "").lower()
                    env = str((meta or {}).get("environment") or "")
                    if env == "client" or mid in {"viaversion", "viabackwards", "viafabric"}:
                        return True, "fabric.mod.json"
                    return False, "server_plugin_hybrid"
                except Exception:
                    return False, "server_plugin_hybrid"

            if has_fabric:
                return True, "fabric.mod.json"
            if has_quilt:
                return True, "quilt.mod.json"
            if has_forge:
                return True, "META-INF/mods.toml"
            if has_old:
                return True, "mcmod.info"
            if has_laby:
                return True, "labymod"
            if has_mixins:
                return True, "mixins.json"
            if "META-INF/MANIFEST.MF" in names and sum(1 for n in names if n.endswith(".class")) > 0:
                try:
                    mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").lower()
                except Exception:
                    mf = ""
                if "fmlcoreplugin" in mf or "tweakclass" in mf or "mixinconfigs" in mf:
                    return True, "manifest_mod"
    except zipfile.BadZipFile:
        return False, "bad_zip"
    except Exception as exc:
        return False, f"error:{exc}"
    return False, "no_mod_meta"

def file_hashes(path: Path) -> tuple[str, str]:
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

def unique_dest(dest_dir: Path, src: Path, md5: str) -> Path:
    candidate = dest_dir / src.name
    if not candidate.exists():
        return candidate
    return dest_dir / f"{src.stem}__{md5[:12]}{src.suffix}"

def iter_jars(roots: list[Path], exclude_dirs: set[Path] | None = None) -> list[Path]:
    exclude_dirs = {p.resolve() for p in (exclude_dirs or set())}
    found: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        log.info("scan: %s", root)
        for path in root.rglob("*.jar"):
            if not path.is_file():
                continue
            try:
                resolved = path.resolve()
            except Exception:
                continue
            if any(resolved == d or d in resolved.parents for d in exclude_dirs):
                continue
            key = str(resolved).lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(path)
    return found

def purge_junk(dest: Path, dry_run: bool = False) -> dict:
    removed = 0
    kept = 0
    by_reason: dict[str, int] = {}
    seen_md5: set[str] = set()
    seen_sha256: set[str] = set()

    for path in sorted(dest.glob("*.jar")):
        ok, reason = is_minecraft_mod(path)
        if not ok:
            by_reason[reason] = by_reason.get(reason, 0) + 1
            removed += 1
            log.info("purge junk %s (%s)", path.name, reason)
            if not dry_run:
                path.unlink(missing_ok=True)
            continue

        md5, sha256 = file_hashes(path)
        if md5 in seen_md5 or sha256 in seen_sha256:
            by_reason["duplicate_hash"] = by_reason.get("duplicate_hash", 0) + 1
            removed += 1
            log.info("purge duplicate %s (md5=%s sha256=%s)", path.name, md5[:12], sha256[:12])
            if not dry_run:
                path.unlink(missing_ok=True)
            continue

        seen_md5.add(md5)
        seen_sha256.add(sha256)
        kept += 1

    return {"removed": removed, "kept": kept, "by_reason": by_reason}

def collect(dest: Path, roots: list[Path], dry_run: bool = False) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    jars = iter_jars(roots, exclude_dirs={dest})
    log.info("candidates: %d", len(jars))

    copied = 0
    skipped = 0
    by_reason: dict[str, int] = {}
    seen_md5: set[str] = set()
    seen_sha256: set[str] = set()
    results = []

    for path in dest.glob("*.jar"):
        ok, _ = is_minecraft_mod(path)
        if not ok:
            continue
        md5, sha256 = file_hashes(path)
        seen_md5.add(md5)
        seen_sha256.add(sha256)

    for path in jars:
        ok, reason = is_minecraft_mod(path)
        by_reason[reason] = by_reason.get(reason, 0) + 1
        if not ok:
            skipped += 1
            log.debug("skip %s (%s)", path, reason)
            continue

        md5, sha256 = file_hashes(path)
        if md5 in seen_md5 or sha256 in seen_sha256:
            skipped += 1
            by_reason["duplicate_hash"] = by_reason.get("duplicate_hash", 0) + 1
            log.debug("duplicate md5=%s sha256=%s %s", md5, sha256, path)
            continue

        seen_md5.add(md5)
        seen_sha256.add(sha256)
        target = unique_dest(dest, path, md5)
        results.append((path, target, reason, md5, sha256))
        if dry_run:
            log.info("DRY %s -> %s [%s] md5=%s sha256=%s", path, target.name, reason, md5, sha256)
            continue
        shutil.copy2(path, target)
        copied += 1
        log.info("copy %s -> %s [%s] md5=%s sha256=%s", path, target.name, reason, md5[:12], sha256[:12])

    purge_stats = purge_junk(dest, dry_run=dry_run)
    return {
        "candidates": len(jars),
        "copied": copied,
        "skipped": skipped,
        "by_reason": by_reason,
        "purge": purge_stats,
        "results": results,
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Собрать Minecraft-моды в mods/, шлак выкинуть")
    parser.add_argument("--dest", default="mods")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--purge-only", action="store_true", help="Только вычистить шлак из mods/")
    parser.add_argument("-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.v else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
    )

    root = Path(__file__).resolve().parent
    dest = (root / args.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    if args.purge_only:
        stats = purge_junk(dest, dry_run=args.dry_run)
        print()
        print(f"kept:    {stats['kept']}")
        print(f"removed: {stats['removed']}")
        print("reasons:")
        for k, v in sorted(stats["by_reason"].items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    stats = collect(dest, SEARCH_ROOTS, dry_run=args.dry_run)
    print()
    print(f"candidates: {stats['candidates']}")
    print(f"copied:     {stats['copied']}")
    print(f"skipped:    {stats['skipped']}")
    print(f"purge kept: {stats['purge']['kept']}")
    print(f"purge rm:   {stats['purge']['removed']}")
    print("reasons:")
    for k, v in sorted(stats["by_reason"].items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")
    if stats["purge"]["by_reason"]:
        print("purge reasons:")
        for k, v in sorted(stats["purge"]["by_reason"].items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
