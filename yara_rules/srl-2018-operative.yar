/*
 * SIFT-Bench SRL-2018 Operative YARA Ruleset
 *
 * Four rules from two established sources, scoped to artifact types
 * present in the SRL-2018 memory image: C2 implant (p.exe), stealth
 * PowerShell C2 shell (PID 5848), and reflective shellcode runners
 * (six short-lived rundll32 instances).
 *
 * Sources:
 *   [A] Neo23x0/signature-base (CC BY-NC 4.0)
 *       https://github.com/Neo23x0/signature-base
 *   [B] Yara-Rules/rules (GPLv2)
 *       https://github.com/Yara-Rules/rules
 *
 * See yara_rules/README.md for full provenance and licensing notes.
 * These rules are excerpted/adapted; see source files for authoritative text.
 */


// ── 1. Meterpreter in-memory DLL naming patterns [A] ──────────────────────
// Source:    Neo23x0/signature-base  yara/gen_metasploit_payloads.yar
// Rule name: HKTL_Meterpreter_inMemory
// Authors:   netbiosX, Florian Roth (Nextron Systems)

rule HKTL_Meterpreter_inMemory {
    meta:
        description = "Detects Meterpreter in-memory via DLL naming patterns"
        author = "netbiosX, Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_metasploit_payloads.yar"
        license = "CC BY-NC 4.0"
        sift_bench_scope = "p.exe implant identification"
    strings:
        $s1 = "metsrv.dll" ascii fullword
        $s2 = "metsrv.x64.dll" ascii fullword
        $s3 = "WS2_32.dll" ascii fullword
        $s4 = "ReflectiveLoader" ascii fullword
    condition:
        2 of them
}


// ── 2. Cobalt Strike beacon diagnostic strings [A] ─────────────────────────
// Source:    Neo23x0/signature-base  yara/apt_cobaltstrike.yar
// Rule name: HKTL_CobaltStrike_Beacon_Strings
// Credit:    Elastic

rule HKTL_CobaltStrike_Beacon_Strings {
    meta:
        description = "Identifies strings used in Cobalt Strike Beacon DLL"
        author = "Elastic"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike.yar"
        license = "CC BY-NC 4.0"
        sift_bench_scope = "p.exe alternative C2 identification"
    strings:
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s2 = "Started service %s on %s" ascii
        $s3 = "%s as %s\\%s: %d" ascii
    condition:
        2 of them
}


// ── 3. Meterpreter reverse-TCP transport constants [B] ────────────────────
// Source:    Yara-Rules/rules  malware/RAT_Meterpreter_Reverse_Tcp.yar
// Rule name: Meterpreter_Reverse_Tcp  (renamed here to avoid collision with #1)
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


// ── 4. Suspicious PowerShell execution flags [A] ──────────────────────────
// Source:    Neo23x0/signature-base  yara/gen_powershell_susp.yar
// Rule name: SUSP_PowerShell_Param_Combo (adapted — exact name uncertain; see README)
// Author:    Florian Roth (Nextron Systems)

rule SUSP_PowerShell_Param_Combo {
    meta:
        description = "Detects suspicious PowerShell invocation parameter combinations"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_powershell_susp.yar"
        license = "CC BY-NC 4.0"
        sift_bench_scope = "powershell.exe stealth C2 shell — stealth flag detection"
    strings:
        $s1 = " -nop " ascii nocase
        $s2 = " -noni " ascii nocase
        $s3 = " -enc " ascii nocase
        $s4 = " -w hidden " ascii nocase
        $s5 = " -EncodedCommand " ascii nocase
        $s6 = " -WindowStyle Hidden " ascii nocase
    condition:
        2 of them
}
