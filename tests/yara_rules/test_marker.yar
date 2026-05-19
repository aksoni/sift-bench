rule TestMarker {
    meta:
        description = "Test rule for SIFT-Bench MCP server"
    strings:
        $marker = "FIND_EVIL_MARKER"
    condition:
        $marker
}
