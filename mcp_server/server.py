from mcp.server.fastmcp import FastMCP
from . import tools

mcp = FastMCP("sift-bench-enrichment")


@mcp.tool()
def hash_file(path: str) -> dict:
    """Return MD5/SHA1/SHA256 hashes and size for a file on disk.

    On success returns {path, size_bytes, md5, sha1, sha256}.
    On error returns {error, path, detail} where error is one of:
    file_not_found | permission_denied | not_a_regular_file
    """
    return tools.hash_file(path)


@mcp.tool()
def yara_scan(target_path: str, rules_path: str, timeout_seconds: int = 30) -> dict:
    """Compile a YARA ruleset and scan a single file, returning structured matches.

    On success returns {target_path, target_sha256, rules_path, rules_sha256,
    matches, scan_duration_ms}. Matched string data is lowercase hex.
    On error returns {error, ...} where error is one of:
    target_not_found | target_not_a_regular_file | rules_not_found |
    rules_compile_error | scan_timeout
    """
    return tools.yara_scan(target_path, rules_path, timeout_seconds)
