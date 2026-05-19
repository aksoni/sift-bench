import hashlib
from pathlib import Path


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
