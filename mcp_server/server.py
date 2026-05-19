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
