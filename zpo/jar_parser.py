from __future__ import annotations

import io
import json
import logging
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

@dataclass
class ClassInfo:
    path: str
    size: int
    strings: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    super_name: str | None = None
    interfaces: list[str] = field(default_factory=list)

@dataclass
class NestedJarInfo:
    path: str
    mod_id: str | None = None
    entrypoints: dict = field(default_factory=dict)
    mixins: list[str] = field(default_factory=list)
    suspicious: bool = False
    reason: str = ""

@dataclass
class JarInfo:
    path: Path
    size: int
    entries: list[str]
    mod_id: str | None = None
    mod_name: str | None = None
    mod_version: str | None = None
    mc_version: str | None = None
    loader: str | None = None
    authors: list[str] = field(default_factory=list)
    entrypoints: dict = field(default_factory=dict)
    mixin_packages: list[str] = field(default_factory=list)
    metadata_raw: dict = field(default_factory=dict)
    classes: list[ClassInfo] = field(default_factory=list)
    all_strings: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    nested_jars: list[NestedJarInfo] = field(default_factory=list)

def parse_constant_pool(data: bytes) -> tuple[list, str | None]:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return [], "bad_magic"
    cp_count = struct.unpack(">H", data[8:10])[0]
    i = 10
    cp: list = [None]
    idx = 1
    while idx < cp_count and i < len(data):
        tag = data[i]
        i += 1
        try:
            if tag == 1:
                ln = struct.unpack(">H", data[i : i + 2])[0]
                i += 2
                s = data[i : i + ln].decode("utf-8", "replace")
                i += ln
                cp.append(("Utf8", s))
            elif tag in (7, 8, 16, 19, 20):
                cp.append((tag, struct.unpack(">H", data[i : i + 2])[0]))
                i += 2
            elif tag in (3, 4):
                cp.append((tag, data[i : i + 4]))
                i += 4
            elif tag in (5, 6):
                cp.append((tag, data[i : i + 8]))
                i += 8
                cp.append(None)
                idx += 1
            elif tag in (9, 10, 11, 12, 17, 18):
                cp.append((tag, struct.unpack(">HH", data[i : i + 4])))
                i += 4
            elif tag == 15:
                cp.append((tag, data[i], struct.unpack(">H", data[i + 1 : i + 3])[0]))
                i += 3
            else:
                return cp, f"unknown_tag_{tag}"
        except Exception as exc:
            return cp, f"parse_error:{exc}"
        idx += 1
    return cp, None

def _utf8s(cp: list) -> list[str]:
    return [x[1] for x in cp if x and x[0] == "Utf8"]

def summarize_class(path: str, data: bytes) -> ClassInfo:
    info = ClassInfo(path=path, size=len(data))
    cp, err = parse_constant_pool(data)
    if err:
        log.debug("class %s: %s", path, err)
    strings = _utf8s(cp)
    info.strings = strings
    for s in strings:
        if re.fullmatch(r"[A-Za-z_$][\w$]*", s) and len(s) >= 2:
            if s[:1].islower() and not s.endswith(("Exception", "Error")):
                info.methods.append(s)
            elif s[:1].isupper() or s.isupper():
                info.fields.append(s)
    for s in strings:
        if "/" in s and not s.endswith(".java") and not s.startswith("("):
            if info.super_name is None and s not in {path.replace(".class", "")}:
                pass
    return info

def _read_json(z: zipfile.ZipFile, name: str) -> dict | list | None:
    try:
        return json.loads(z.read(name).decode("utf-8", "replace"))
    except Exception:
        return None

def _extract_mc_version_fabric(meta: dict) -> str | None:
    depends = meta.get("depends") or {}
    if not isinstance(depends, dict):
        return None
    raw = depends.get("minecraft") or depends.get("Minecraft")
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = " || ".join(str(x) for x in raw)
    s = str(raw).strip()
    return s or None

def _extract_mc_version_forge(text: str) -> str | None:
    for block in re.findall(r"(?ms)\[\[dependencies[^\]]*\]\]\s*(.*?)(?=\n\[\[|\Z)", text):
        if not re.search(r'(?im)modId\s*=\s*"minecraft"', block):
            continue
        for key in ("versionRange", "version"):
            m = re.search(rf'(?im){key}\s*=\s*"([^"]+)"', block)
            if m:
                return m.group(1).strip()

    m = re.search(
        r'(?im)^\s*(?:minecraft|MinecraftVersion)\s*=\s*"([^"]+)"',
        text,
    )
    if m:
        return m.group(1).strip()
    return None

def _guess_mc_from_name(name: str) -> str | None:
    m = re.search(r"(?<![0-9])(1\.(?:7|8|9|1[0-9]|2[0-1])(?:\.[0-9]+)?)(?![0-9])", name)
    return m.group(1) if m else None

_MC_116 = (1, 16, 0)

def _ver_tuple(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"(?<![0-9])1\.(\d+)(?:\.(\d+))?(?![0-9])", text)
    if not m:
        return None
    return (1, int(m.group(1)), int(m.group(2) or 0))

def is_mc_below_116(mc_version: str | None) -> bool | None:
    """True if mod targets only Minecraft versions below 1.16."""
    if not mc_version or not str(mc_version).strip():
        return None
    raw = str(mc_version).strip()

    if re.search(r">=?\s*1\.16(?:\.\d+)?", raw) or re.search(r"\[\s*1\.16(?:\.\d+)?", raw):
        return False

    if re.search(r"<\s*1\.16(?:\.\d+)?", raw) or re.search(r"<=\s*1\.15(?:\.\d+)?", raw):
        return True
    if re.search(r",\s*1\.16(?:\.\d+)?\s*\)", raw):
        return True

    vers = [_ver_tuple(m.group(0)) for m in re.finditer(r"1\.\d+(?:\.\d+)?", raw)]
    vers = [v for v in vers if v]
    if not vers:
        return None

    if len(vers) == 1 and not re.search(r"[<>\[\]|~]", raw):
        return vers[0] < _MC_116

    if max(vers) < _MC_116:
        return True
    if min(vers) >= _MC_116:
        return False
    return False

def parse_jar(path: Path) -> JarInfo:
    log.info("parse jar: %s (%s bytes)", path.name, path.stat().st_size)
    with zipfile.ZipFile(path) as z:
        entries = z.namelist()
        jar = JarInfo(path=path, size=path.stat().st_size, entries=entries)

        meta = _read_json(z, "fabric.mod.json")
        if isinstance(meta, dict):
            jar.metadata_raw = meta
            jar.loader = "fabric"
            jar.mod_id = meta.get("id")
            jar.mod_name = meta.get("name")
            jar.mod_version = meta.get("version")
            jar.mc_version = _extract_mc_version_fabric(meta)
            authors = meta.get("authors") or []
            jar.authors = [a if isinstance(a, str) else str(a) for a in authors]
            jar.entrypoints = meta.get("entrypoints") or {}
            mixins = meta.get("mixins") or []
            for m in mixins:
                cfg_name = m if isinstance(m, str) else (m or {}).get("config")
                if not cfg_name:
                    continue
                cfg = _read_json(z, cfg_name)
                if isinstance(cfg, dict) and cfg.get("package"):
                    jar.mixin_packages.append(cfg["package"])

        if not jar.mod_id:
            quilt = _read_json(z, "quilt.mod.json")
            if isinstance(quilt, dict):
                jar.loader = "quilt"
                qloader = quilt.get("quilt_loader") or {}
                jar.metadata_raw = quilt
                jar.mod_id = qloader.get("id") or quilt.get("id")
                meta_obj = qloader.get("metadata") or {}
                jar.mod_name = meta_obj.get("name") or quilt.get("name")
                jar.mod_version = qloader.get("version") or quilt.get("version")
                depends = qloader.get("depends") or []
                if isinstance(depends, list):
                    for dep in depends:
                        if isinstance(dep, dict) and str(dep.get("id", "")).lower() == "minecraft":
                            jar.mc_version = str(dep.get("versions") or dep.get("version") or "") or None

        
        for toml_name in ("META-INF/mods.toml", "META-INF/neoforge.mods.toml"):
            if toml_name not in entries:
                continue
            try:
                text = z.read(toml_name).decode("utf-8", "replace")
            except Exception:
                continue
            jar.loader = jar.loader or ("neoforge" if "neoforge" in toml_name else "forge")
            if not jar.mod_id:
                m = re.search(r'(?m)^\s*modId\s*=\s*"([^"]+)"', text)
                if m:
                    jar.mod_id = m.group(1)
            if not jar.mod_name:
                m = re.search(r'(?m)^\s*displayName\s*=\s*"([^"]+)"', text)
                if m:
                    jar.mod_name = m.group(1)
            if not jar.mod_version:
                m = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
                if m:
                    jar.mod_version = m.group(1)
            if not jar.mc_version:
                jar.mc_version = _extract_mc_version_forge(text)
            break

        
        if not jar.mod_id:
            for name in entries:
                if name.endswith("addon.json") or name == "addon.json":
                    addon = _read_json(z, name)
                    if isinstance(addon, dict):
                        jar.loader = "labymod"
                        jar.mod_id = addon.get("namespace") or addon.get("uuid")
                        jar.mod_name = addon.get("name")
                        jar.mod_version = addon.get("version")
                        
                        break

        if not jar.mc_version:
            jar.mc_version = _guess_mc_from_name(path.name)

        pkgs: set[str] = set()
        all_strings: list[str] = []
        class_entries = [n for n in entries if n.endswith(".class") and not n.startswith("META-INF/")]
        
        
        interesting_paths = set()
        ep = jar.entrypoints or {}
        for vals in ep.values():
            items = vals if isinstance(vals, list) else [vals]
            for item in items:
                if isinstance(item, str):
                    interesting_paths.add(item.replace(".", "/") + ".class")
        ranked = sorted(class_entries, key=lambda n: z.getinfo(n).file_size, reverse=True)
        selected = []
        for n in class_entries:
            low = n.lower()
            if (
                n in interesting_paths
                or "/module/" in low
                or "esp" in low
                or "hack" in low
                or "cheat" in low
                or "aura" in low
                or "xray" in low
                or "freecam" in low
                or "baritone" in low
                or "killaura" in low
                or "triggerbot" in low
                or "targetbot" in low
                or "autoswap" in low
                or "autoeat" in low
                or "autocrystal" in low
            ):
                selected.append(n)
        for n in ranked[:40]:
            if n not in selected:
                selected.append(n)
        selected = selected[:80]

        for name in entries:
            if name.endswith((".json", ".lang", ".txt", ".properties", ".toml")):
                try:
                    all_strings.append(z.read(name).decode("utf-8", "replace"))
                except Exception:
                    pass

        for name in selected:
            data = z.read(name)
            cls = summarize_class(name, data)
            jar.classes.append(cls)
            all_strings.extend(cls.strings)
            parts = name.split("/")
            if len(parts) >= 2:
                pkgs.add("/".join(parts[:-1]))

        for name in class_entries:
            parts = name.split("/")
            if len(parts) >= 2:
                pkgs.add("/".join(parts[:-1]))
            all_strings.append(name)

        _ingest_nested_jars(z, jar, pkgs, all_strings)

        jar.packages = sorted(pkgs)
        if len(all_strings) > 30000:
            all_strings = all_strings[:30000]
        jar.all_strings = all_strings
        log.info(
            "jar meta id=%s name=%s mc=%s classes_total=%d parsed=%d packages=%d strings=%d nested=%d",
            jar.mod_id,
            jar.mod_name,
            jar.mc_version,
            len(class_entries),
            len(jar.classes),
            len(jar.packages),
            len(jar.all_strings),
            len(jar.nested_jars),
        )
        return jar

def _nested_suspicious(meta: dict, class_names: list[str], strings: list[str]) -> tuple[bool, str]:
    from .guide import LEGIT_NESTED_MOD_IDS

    mid = str(meta.get("id") or "").lower()
    eps = meta.get("entrypoints") or {}
    mixins = meta.get("mixins") or []
    blob = "\n".join(strings + class_names).lower()
    has_client_ep = any(k in eps for k in ("client", "cleint", "main", "modinitializer"))
    has_mixins = bool(mixins) or any(".mixins.json" in n for n in class_names)
    cheatish = any(
        k in blob
        for k in (
            "onisglowing",
            "onisinvisible",
            "forced_glow",
            "playeresp",
            "killaura",
            "triggerbot",
            "freecam",
            "t.me/ghostbitbox",
            "shouldunload",
            "increasehitbox",
            "applyhitboxscale",
            "panicmodebinding",
            "hitboxesp",
            "playeresp",
        )
    )
    fake_lib = any(x in mid for x in ("lwjgl", "glfw", "library", "commons", "guava"))
    if cheatish:
        return True, "nested jar содержит чит-сигналы"
    if fake_lib and (has_client_ep or has_mixins):
        return True, f"nested jar id={mid} маскируется под библиотеку, но имеет entrypoints/mixins"
    if mid in LEGIT_NESTED_MOD_IDS or mid.startswith("fabric-"):
        return False, ""
    if has_client_ep and has_mixins and "fabric-api" not in mid:
        return True, f"nested jar id={mid} с client entrypoints + mixins"
    return False, ""

def _ingest_nested_jars(
    z: zipfile.ZipFile,
    jar: JarInfo,
    pkgs: set[str],
    all_strings: list[str],
) -> None:
    nested_paths = [
        n
        for n in z.namelist()
        if n.startswith("META-INF/jars/") and n.lower().endswith(".jar")
    ]
    for nested_path in nested_paths:
        try:
            raw = z.read(nested_path)
            with zipfile.ZipFile(io.BytesIO(raw)) as nz:
                names = nz.namelist()
                meta = _read_json(nz, "fabric.mod.json") or {}
                if not isinstance(meta, dict):
                    meta = {}
                ep = meta.get("entrypoints") or {}
                mixins = meta.get("mixins") or []
                mix_list = [m if isinstance(m, str) else str((m or {}).get("config") or "") for m in mixins]
                nested_strings: list[str] = []
                nested_class_names: list[str] = []
                for name in names:
                    prefix = f"{nested_path}!{name}"
                    if name.endswith((".json", ".txt", ".properties", ".toml", ".lang")):
                        try:
                            text = nz.read(name).decode("utf-8", "replace")
                            nested_strings.append(text)
                            all_strings.append(f"{prefix}:{text[:500]}")
                        except Exception:
                            pass
                    if not name.endswith(".class"):
                        continue
                    nested_class_names.append(name)
                    data = nz.read(name)
                    cls = summarize_class(prefix, data)
                    jar.classes.append(cls)
                    nested_strings.extend(cls.strings)
                    all_strings.extend(cls.strings)
                    all_strings.append(prefix)
                    parts = name.split("/")
                    if len(parts) >= 2:
                        pkgs.add("/".join(parts[:-1]))

                suspicious, reason = _nested_suspicious(meta, nested_class_names, nested_strings)
                info = NestedJarInfo(
                    path=nested_path,
                    mod_id=meta.get("id"),
                    entrypoints=ep if isinstance(ep, dict) else {},
                    mixins=mix_list,
                    suspicious=suspicious,
                    reason=reason,
                )
                jar.nested_jars.append(info)
                if suspicious:
                    log.warning("NESTED SUSPICIOUS %s: %s", nested_path, reason)
                    all_strings.append(f"NESTED_SUSPICIOUS:{nested_path}:{reason}")
        except Exception as exc:
            log.debug("nested jar skip %s: %s", nested_path, exc)

def class_digest(cls: ClassInfo, limit: int = 32) -> str:
    interesting = []
    for s in cls.strings:
        if any(
            k in s.lower()
            for k in (
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
                "baritone",
                "mixin",
                "player",
                "entity",
                "critical",
                "sword",
                "cooldown",
                "outline",
                "tracer",
                "radar",
                "steal",
                "webhook",
            )
        ) or re.search(r"[A-Z][a-z]+[A-Z]", s):
            if len(s) <= 220:
                interesting.append(s)
    interesting = sorted(set(interesting))[:limit]
    methods = sorted(set(cls.methods))[:18]
    body = (
        f"class={cls.path} size={cls.size}\n"
        f"methods_sample={methods}\n"
        f"strings_sample={interesting}"
    )
    if len(body) > 1800:
        body = body[:1797] + "..."
    return body
