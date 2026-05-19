import hashlib
import time
from pathlib import Path

import yara


def hash_file(path: str) -> dict:
    """Return md5/sha1/sha256 hashes and size for a file on disk.

    On success: {"path", "size_bytes", "md5", "sha1", "sha256"}
    On error:   {"error", "path", "detail"}
    Error codes: file_not_found | permission_denied | not_a_regular_file
    """
    p = Path(path)
    if not p.exists():
        if p.is_symlink():
            return {"error": "not_a_regular_file", "path": path, "detail": "Broken symlink"}
        return {"error": "file_not_found", "path": path, "detail": f"No such file: {path}"}
    if not p.is_file():
        return {"error": "not_a_regular_file", "path": path, "detail": f"Not a regular file: {path}"}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0
        with open(p, "rb") as f:
            while chunk := f.read(1024 * 1024):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
        return {
            "path": path,
            "size_bytes": size,
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except PermissionError:
        return {"error": "permission_denied", "path": path, "detail": f"Permission denied: {path}"}


def yara_scan(target_path: str, rules_path: str, timeout_seconds: int = 30) -> dict:
    """Compile a YARA ruleset and scan a single file, returning structured matches.

    On success: {target_path, target_sha256, rules_path, rules_sha256, matches, scan_duration_ms}
    On error:   {error, ...} where error is one of:
      target_not_found | target_not_a_regular_file | rules_not_found |
      rules_compile_error | scan_timeout
    Matched string data is always lowercase hex — never decoded as UTF-8.
    """
    target = Path(target_path)
    rules_p = Path(rules_path)

    if not target.exists():
        if target.is_symlink():
            return {"error": "target_not_a_regular_file", "path": target_path, "detail": "Broken symlink"}
        return {"error": "target_not_found", "path": target_path, "detail": f"No such file: {target_path}"}
    if not target.is_file():
        return {"error": "target_not_a_regular_file", "path": target_path, "detail": f"Not a regular file: {target_path}"}

    if not rules_p.exists():
        return {"error": "rules_not_found", "path": rules_path, "detail": f"No such file: {rules_path}"}

    try:
        compiled_rules = yara.compile(filepath=str(rules_p))
    except yara.SyntaxError as e:
        return {"error": "rules_compile_error", "path": rules_path, "detail": str(e)}

    target_sha256 = _sha256_file(target)
    rules_sha256 = _sha256_file(rules_p)

    start = time.monotonic()
    try:
        raw_matches = compiled_rules.match(filepath=str(target), timeout=timeout_seconds)
    except yara.TimeoutError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "error": "scan_timeout",
            "target_path": target_path,
            "detail": f"Scan did not complete within {timeout_seconds}s",
            "elapsed_ms": elapsed_ms,
        }
    elapsed_ms = int((time.monotonic() - start) * 1000)

    matches = []
    for m in raw_matches:
        strings = []
        for sm in m.strings:
            for inst in sm.instances:
                strings.append({
                    "identifier": sm.identifier,
                    "offset": inst.offset,
                    "data": inst.matched_data.hex(),
                })
        matches.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "strings": strings,
        })

    return {
        "target_path": target_path,
        "target_sha256": target_sha256,
        "rules_path": rules_path,
        "rules_sha256": rules_sha256,
        "matches": matches,
        "scan_duration_ms": elapsed_ms,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()
