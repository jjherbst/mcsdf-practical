from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple
import sys
import yara
# ---- minimal API ----

def compile_rules(rule_file: Path):
    """Compile a YARA rule file, or return None if yara isn't available."""
    try:
        return yara.compile(filepath=str(rule_file))
    except Exception as e:
        sys.stderr.write(f"[!] Failed to compile {rule_file}: {e}\n")
        return None


def scan_yara_file(path: Path, rules) -> List[Dict[str, Any]]:
    """
    Scan a single file with a compiled ruleset.
    Returns a simple list of dicts: {"rule", "tags", "meta", "strings", "offsets"}.
    """
    if rules is None:
        return []
    if not path.is_file():
        sys.stderr.write(f"[!] Not a file: {path}\n")
        return []

    try:
        data = path.read_bytes()
    except Exception as e:
        sys.stderr.write(f"[!] Read failed {path}: {e}\n")
        return []

    try:
        matches = rules.match(data=data, timeout=15)
    except Exception as e:
        sys.stderr.write(f"[!] YARA error on {path}: {e}\n")
        return []

    out: List[Dict[str, Any]] = []
    for m in matches:
        strings: List[Tuple[int, str, bytes]] = _extract_strings(m)
        out.append({
            "rule": getattr(m, "rule", ""),
            "tags": list(getattr(m, "tags", [])),
            "meta": dict(getattr(m, "meta", {})),
            "strings": [_preview(blob) for (_, _, blob) in strings],
            "offsets": [off for (off, _, _) in strings],
            "filename": str(Path(path).name),
        })
    return out


def _extract_strings(m) -> List[Tuple[int, str, bytes]]:
    """
    Support the two common yara-python formats:
      1) classic: [(offset, identifier, bytes), ...]
      2) newer:   m.strings -> objs with .identifier and .instances
    """
    s = getattr(m, "strings", []) or []
    if not s:
        return []

    # classic tuples already
    if isinstance(s[0], tuple) and len(s[0]) == 3:
        return [(int(off), str(ident), bytes(blob)) for (off, ident, blob) in s]

    # newer object style
    out: List[Tuple[int, str, bytes]] = []
    try:
        for entry in s:
            ident = str(getattr(entry, "identifier", ""))
            for inst in getattr(entry, "instances", []) or []:
                off = int(getattr(inst, "offset", 0))
                data = getattr(inst, "matched_data", b"") or getattr(inst, "data", b"") or b""
                if isinstance(data, memoryview):
                    data = data.tobytes()
                out.append((off, ident, bytes(data)))
    except Exception:
        return []
    return out


def _preview(b: bytes, limit: int = 160) -> str:
    t = b.decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
    return t if len(t) <= limit else t[:limit] + "..."
