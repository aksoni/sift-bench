/*
 * SIFT-Bench SRL-2018 Operative YARA Ruleset
 *
 * One community detection rule, scoped to an artifact type present in the
 * SRL-2018 memory image: the C2 implant (p.exe). The project's original
 * detection contribution lives in yara_rules/srl-2018-novel.yar.
 *
 * Source:
 *   [B] Yara-Rules/rules (GPLv2)
 *       https://github.com/Yara-Rules/rules
 *
 * NOTE: Three CC BY-NC 4.0 community rules (Neo23x0/signature-base —
 * HKTL_Meterpreter_inMemory, HKTL_CobaltStrike_Beacon_Strings,
 * SUSP_PowerShell_Param_Combo) were removed on 2026-06-13 to keep the bundled
 * ruleset fully permissive. They were inert (0 matches) in all committed runs
 * (the only operative-ruleset scans were Run 6's two mcp__yara_scan calls,
 * both 0 matches), so no scored/frozen detection result is affected.
 *
 * See yara_rules/README.md for full provenance and licensing notes.
 * This rule is excerpted/adapted; see the source file for authoritative text.
 */


// ── Meterpreter reverse-TCP transport constants [B] ───────────────────────
// Source:    Yara-Rules/rules  malware/RAT_Meterpreter_Reverse_Tcp.yar
// Rule name: Meterpreter_Reverse_Tcp  (renamed here to avoid collision)
// Authors:   Yara-Rules Project

rule RAT_Meterpreter_Reverse_Tcp {
    meta:
        description = "Detects Meterpreter reverse-TCP payload via transport-layer constants"
        author = "Yara-Rules Project"
        reference = "https://github.com/Yara-Rules/rules/blob/master/malware/RAT_Meterpreter_Reverse_Tcp.yar"
        license = "GPLv2"
        sift_bench_scope = "p.exe C2 implant — transport configuration strings"
    strings:
        $s1 = "METERPRETER_TRANSPORT_SSL" ascii fullword
        $s2 = "METERPRETER_UA" ascii fullword
        $s3 = "ReflectiveLoader" ascii fullword
        $s4 = "metsrv.dll" ascii fullword
    condition:
        2 of them
}
