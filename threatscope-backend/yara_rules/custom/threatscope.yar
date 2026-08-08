/*
   ThreatScope AI — Custom YARA Rules
   Author: ThreatScope AI Platform
   Description: Detect patterns commonly observed in malware analysed on this platform.
   Last updated: 2026-06-29
*/

// ──────────────────────────────────────────────────────────────
// Encoded / Obfuscated PowerShell
// ──────────────────────────────────────────────────────────────

rule Suspicious_PowerShell_Encoded {
    meta:
        author      = "ThreatScope AI"
        description = "Detects encoded or obfuscated PowerShell invocations"
        severity    = "medium"
        mitre       = "T1059.001"
    strings:
        $ps    = "powershell" nocase
        $enc1  = "-enc " nocase
        $enc2  = "-encodedcommand" nocase
        $enc3  = "-e " nocase
        $b64   = "FromBase64String" nocase
        $iex   = "IEX" nocase
        $nop   = "-nop" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        ($ps and ($enc1 or $enc2 or $enc3)) or
        ($ps and $iex) or
        ($ps and $bypass) or
        $b64
}

// ──────────────────────────────────────────────────────────────
// Suspicious cmd.exe Execution
// ──────────────────────────────────────────────────────────────

rule Suspicious_CMD_Execution {
    meta:
        author      = "ThreatScope AI"
        description = "Detects suspicious cmd.exe execution patterns"
        severity    = "medium"
        mitre       = "T1059.003"
    strings:
        $cmd   = "cmd.exe" nocase
        $slash = "/c " nocase
        $del   = "del /f" nocase
        $echo  = "echo off" nocase
        $pipe  = "| " nocase
        $redir = "> " nocase
    condition:
        $cmd and ($slash or $del) and ($echo or $pipe or $redir)
}

// ──────────────────────────────────────────────────────────────
// Ransomware Indicators
// ──────────────────────────────────────────────────────────────

rule Generic_Ransomware_Indicators {
    meta:
        author      = "ThreatScope AI"
        description = "Detects strings commonly found in ransomware payloads"
        severity    = "high"
        mitre       = "T1486"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypt" nocase
        $note1 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $note2 = "HOW_TO_DECRYPT" nocase
        $note3 = "README_DECRYPT" nocase
        $note4 = "RECOVER_FILES" nocase
        $note5 = "pay the ransom" nocase
        $note6 = "bitcoin" nocase
        $note7 = "decrypt your files" nocase
        $api1  = "CryptEncrypt"
        $api2  = "CryptGenKey"
    condition:
        2 of ($ext*) or 2 of ($note*) or (1 of ($ext*) and 1 of ($note*)) or
        (1 of ($api*) and 1 of ($note*))
}

// ──────────────────────────────────────────────────────────────
// C2 Beacon / Network Indicators
// ──────────────────────────────────────────────────────────────

rule Suspicious_Network_Beacon {
    meta:
        author      = "ThreatScope AI"
        description = "Detects command-and-control beacon communication patterns"
        severity    = "high"
        mitre       = "T1071.001"
    strings:
        $ua      = "User-Agent:" nocase
        $post    = "POST /" nocase
        $sleep   = "Sleep(" nocase
        $connect = "InternetConnect" nocase
        $http    = "HttpSendRequest" nocase
        $open    = "InternetOpen" nocase
        $urlmon  = "URLDownloadToFile" nocase
    condition:
        3 of them
}

// ──────────────────────────────────────────────────────────────
// Process Injection APIs
// ──────────────────────────────────────────────────────────────

rule Process_Injection_APIs {
    meta:
        author      = "ThreatScope AI"
        description = "Detects API calls commonly used for process injection"
        severity    = "high"
        mitre       = "T1055"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
        $api5 = "QueueUserAPC"
        $api6 = "RtlCreateUserThread"
        $api7 = "NtQueueApcThread"
        $api8 = "SetThreadContext"
    condition:
        2 of them
}

// ──────────────────────────────────────────────────────────────
// Anti-Debug / Anti-VM
// ──────────────────────────────────────────────────────────────

rule AntiDebug_AntiVM {
    meta:
        author      = "ThreatScope AI"
        description = "Detects anti-debug and anti-VM evasion techniques"
        severity    = "medium"
        mitre       = "T1497"
    strings:
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "CheckRemoteDebuggerPresent"
        $dbg3 = "NtQueryInformationProcess"
        $dbg4 = "OutputDebugString"
        $vm1  = "VBOX" nocase
        $vm2  = "VMWARE" nocase
        $vm3  = "SANDBOXIE" nocase
        $vm4  = "VIRTUAL" nocase
        $vm5  = "sbiedll" nocase
        $vm6  = "vboxservice" nocase
    condition:
        2 of ($dbg*) or 2 of ($vm*) or (1 of ($dbg*) and 1 of ($vm*))
}

// ──────────────────────────────────────────────────────────────
// Credential Harvesting
// ──────────────────────────────────────────────────────────────

rule Credential_Harvesting {
    meta:
        author      = "ThreatScope AI"
        description = "Detects strings associated with credential theft"
        severity    = "high"
        mitre       = "T1003"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa" nocase
        $s3 = "lsass.exe" nocase
        $s4 = "SAM database" nocase
        $s5 = "credential manager" nocase
        $s6 = "wdigest" nocase
        $s7 = "kerberos ticket" nocase
        $s8 = "procdump" nocase
    condition:
        2 of them
}

// ──────────────────────────────────────────────────────────────
// Persistence via Registry
// ──────────────────────────────────────────────────────────────

rule Registry_Persistence {
    meta:
        author      = "ThreatScope AI"
        description = "Detects registry-based persistence mechanisms"
        severity    = "medium"
        mitre       = "T1547.001"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "CurrentVersion\\RunOnce" nocase
        $run3 = "CurrentVersion\\RunServices" nocase
        $svc  = "CurrentVersion\\Explorer\\Shell Folders" nocase
        $api1 = "RegSetValueEx"
        $api2 = "RegCreateKeyEx"
    condition:
        (1 of ($run*) or $svc) and (1 of ($api*))
}

// ──────────────────────────────────────────────────────────────
// Keylogger Patterns
// ──────────────────────────────────────────────────────────────

rule Keylogger_Indicators {
    meta:
        author      = "ThreatScope AI"
        description = "Detects keylogging API usage patterns"
        severity    = "high"
        mitre       = "T1056.001"
    strings:
        $api1 = "SetWindowsHookEx"
        $api2 = "GetAsyncKeyState"
        $api3 = "GetKeyState"
        $api4 = "GetKeyboardState"
        $api5 = "MapVirtualKey"
        $log  = "keylog" nocase
    condition:
        2 of ($api*) or ($log and 1 of ($api*))
}

// ──────────────────────────────────────────────────────────────
// Packed / UPX Compressed
// ──────────────────────────────────────────────────────────────

rule Packed_UPX {
    meta:
        author      = "ThreatScope AI"
        description = "Detects UPX-packed executables"
        severity    = "low"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        uint16(0) == 0x5A4D and 2 of ($upx*)
}
