/*
 * SIFT-Bench SRL-2018 Novel Rules
 *
 * Two original rules authored for the SRL-2018 case. Not derived from any
 * public signature base. See design/yara-rules-v2.md for rationale,
 * pre-registered outcomes, and test plan.
 *
 * License: MIT (original authorship, see project LICENSE)
 * Author: SIFT-Bench / aksoni, 2026-05-20
 */


// ── 1. Sysinternals ProcDump binary identification ────────────────────────────
//
// Matches any Sysinternals ProcDump binary via PE version-resource strings
// stored as UTF-16LE. Fires against an extracted PE binary or raw memory region
// containing the procdump image.
//
// Forensic context (GT F012): procdump.exe found in the Dashlane application
// directory — covert staging outside the tool's normal installation path.
// A match here confirms the binary is the genuine Sysinternals tool (not a
// malware lookalike), which has evidentiary value separate from the placement
// anomaly.
//
// Pre-registered outcome: MATCH expected against extracted procdump.exe
// (SHA256: 8b87ad36...) from Run 6.
//
// Target artifact: extracted PE binary or memory dump containing the procdump image.

rule SIFT_Procdump_Sysinternals_Marker {
    meta:
        description = "Identifies Sysinternals ProcDump binary via PE version-resource strings (UTF-16LE)"
        author = "aksoni / SIFT-Bench"
        date = "2026-05-20"
        license = "MIT"
        case = "SRL-2018"
        gt_finding = "F012"
        target_artifact = "extracted PE binary (procdump.exe)"
        sift_bench_note = "Novel rule — not derived from public signature bases"
    strings:
        // PE VERSIONINFO FileDescription field (UTF-16LE)
        $procdump_name   = "ProcDump" wide nocase
        // PE VERSIONINFO CompanyName field (UTF-16LE)
        $sysinternals    = "Sysinternals" wide nocase
        // PE VERSIONINFO author string present across versions (UTF-16LE)
        $russinovich     = "Mark Russinovich" wide nocase
    condition:
        2 of them
}


// ── 2. 32-bit PowerShell stealth invocation in memory (wide strings) ──────────
//
// Detects a 32-bit PowerShell process invoked with 3 or more stealth flags,
// running from the SysWOW64 path. Designed for scanning raw memory images or
// per-process memory dumps where command-line arguments are stored as UTF-16LE
// in the process PEB.
//
// Addresses two gaps in the operative Rule 4 (SUSP_PowerShell_Param_Combo):
//   - Rule 4 uses ASCII-only string matching; UTF-16LE command-line strings
//     in a memory image are invisible to ASCII patterns.
//   - Rule 4 requires only 2 flags; 2-flag combos are common in legitimate
//     IT automation. A 3-flag threshold + SysWOW64 path indicator is a much
//     stronger signal.
//
// Forensic context (GT F005): PowerShell PID 5848, 32-bit (SysWOW64), C2 shell
// to 172.16.4.10:8080 with stealth invocation flags.
//
// Pre-registered outcome: MATCH expected against raw memory image
// (base-rd01-memory.img) at the PID 5848 process PEB region. NOT expected to
// match against extracted PE binaries (p.exe, procdump.exe) — runtime
// command-line is not present in PE static content.
//
// Target artifact: raw memory image or per-process memory dump. Not a PE binary.

rule SIFT_PS_SysWOW64_Stealth_Memory {
    meta:
        description = "Detects 32-bit PowerShell with 3+ stealth flags in memory image (UTF-16LE; requires SysWOW64 path)"
        author = "aksoni / SIFT-Bench"
        date = "2026-05-20"
        license = "MIT"
        case = "SRL-2018"
        gt_finding = "F005"
        target_artifact = "raw memory image or per-process memory dump"
        sift_bench_note = "Novel rule — fixes encoding gap in operative Rule 4; 3-flag threshold reduces FP rate"
    strings:
        // SysWOW64 path indicator — 32-bit PS on 64-bit OS (UTF-16LE)
        $syswow64_path  = "SysWOW64\\WindowsPowerShell" wide nocase

        // Stealth invocation flags as they appear in UTF-16LE command-line memory
        $flag_noprofile = "-NoProfile" wide nocase
        $flag_noexit    = "-NoExit" wide nocase
        $flag_nolog     = "-NoLogo" wide nocase
        $flag_hidden    = "-WindowStyle Hidden" wide nocase
        $flag_bypass    = "-ExecutionPolicy Bypass" wide nocase
        $flag_enc       = "-EncodedCommand" wide nocase
        $flag_noni      = "-NonInteractive" wide nocase
    condition:
        $syswow64_path and 3 of ($flag_*)
}
