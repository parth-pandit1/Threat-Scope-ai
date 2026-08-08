"""
Windows PE (Portable Executable) file parser for security-relevant metadata.

Extracts machine type, compile timestamps, section information,
imported/exported functions, and flags suspicious API imports
commonly used by malware (process injection, anti-debug, persistence).

Scoring contribution: 0-30 points toward the overall threat score.
"""

import logging
import math
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Dangerous Windows API calls commonly abused by malware
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_IMPORTS: set[str] = {
    # Process injection
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC",
    "NtQueueApcThread", "RtlCreateUserThread", "SetThreadContext",
    "NtWriteVirtualMemory", "NtCreateThreadEx",
    # Anti-debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
    "NtSetInformationThread",
    # Persistence
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    # Code execution
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUserA", "CreateProcessAsUserW",
    # Network
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW",
    "InternetConnectA", "InternetConnectW",
    "HttpSendRequestA", "HttpSendRequestW",
    "InternetReadFile",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
    "CryptGenKey", "CryptDeriveKey",
    # Memory manipulation
    "VirtualProtect", "VirtualProtectEx", "VirtualAlloc",
    # Library loading
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    # Keylogging
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    # Screen capture
    "BitBlt", "CreateCompatibleDC",
    # Service control
    "CreateServiceA", "CreateServiceW",
    "StartServiceA", "StartServiceW",
}

MACHINE_TYPE_MAP: dict[int, str] = {
    0x0: "Unknown",
    0x14C: "x86",
    0x8664: "AMD64",
    0x1C0: "ARM",
    0xAA64: "ARM64",
    0x200: "IA64",
}

SUBSYSTEM_MAP: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
}

RESOURCE_TYPE_MAP: dict[int, str] = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
    24: "RT_MANIFEST",
}


def is_pe_file(file_path: str) -> bool:
    """Check whether the file starts with the MZ magic bytes."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
        return magic == b"MZ"
    except Exception:
        return False


def get_suspicious_imports() -> set[str]:
    """Return a copy of the known-dangerous import set."""
    return SUSPICIOUS_IMPORTS.copy()


def parse_pe_header(file_path: str) -> dict[str, Any]:
    """
    Parse a PE file and extract security-relevant metadata.

    Returns a dictionary covering machine type, compile timestamp,
    sections (with entropy and permission flags), imported and exported
    functions, resource types, overlay data, and a pe_score (0-30).

    Returns ``{"is_pe": False, "pe_score": 0}`` for non-PE files.
    """
    if not is_pe_file(file_path):
        return {"is_pe": False, "pe_score": 0}

    try:
        import pefile
    except ImportError:
        logger.warning("pefile not installed — cannot parse PE header")
        return {"is_pe": True, "pe_score": 0, "error": "pefile not installed"}

    try:
        pe = pefile.PE(file_path)
    except Exception as exc:
        logger.warning("Failed to parse PE file %s: %s", file_path, str(exc))
        return {"is_pe": True, "pe_score": 0, "error": str(exc)}

    pe_score = 0

    try:
        result: dict[str, Any] = {"is_pe": True}

        # ── Machine type ─────────────────────
        result["machine_type"] = MACHINE_TYPE_MAP.get(
            pe.FILE_HEADER.Machine,
            f"0x{pe.FILE_HEADER.Machine:04X}",
        )

        # ── Compile timestamp ────────────────
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            result["compile_timestamp"] = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            now_year = datetime.now(timezone.utc).year
            result["is_timestamp_suspicious"] = (
                compile_dt.year < 2000 or compile_dt.year > now_year + 1
            )
        except (OSError, ValueError, OverflowError):
            result["compile_timestamp"] = None
            result["is_timestamp_suspicious"] = True

        if result.get("is_timestamp_suspicious"):
            pe_score += 3

        # ── Subsystem / DLL / Driver ─────────
        result["subsystem"] = SUBSYSTEM_MAP.get(
            pe.OPTIONAL_HEADER.Subsystem, "Unknown"
        )
        result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result["is_driver"] = pe.OPTIONAL_HEADER.Subsystem == 1

        # ── Sections ─────────────────────────
        sections: list[dict[str, Any]] = []
        suspicious_sections: list[dict[str, Any]] = []

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            sec_data = section.get_data()

            # Section entropy
            if sec_data and len(sec_data) > 0:
                counter = Counter(sec_data)
                length = len(sec_data)
                sec_entropy = round(
                    -sum((c / length) * math.log2(c / length) for c in counter.values()),
                    4,
                )
            else:
                sec_entropy = 0.0

            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)
            is_read = bool(section.Characteristics & 0x40000000)

            flags = (
                ("r" if is_read else "-")
                + ("w" if is_write else "-")
                + ("x" if is_exec else "-")
            )

            sec_info: dict[str, Any] = {
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": sec_entropy,
                "is_executable": is_exec,
                "is_writable": is_write,
                "flags": flags,
            }
            sections.append(sec_info)

            # Flag suspicious sections
            reasons: list[str] = []
            if not name.strip():
                reasons.append("unnamed section")
            if sec_entropy > 7.0:
                reasons.append(f"high entropy ({sec_entropy:.2f})")
            if is_exec and is_write:
                reasons.append("writable + executable (rwx)")

            if reasons:
                suspicious_sections.append({"name": name or "(empty)", "reasons": reasons})
                pe_score += 3

        result["sections"] = sections
        result["suspicious_sections"] = suspicious_sections

        # ── Imports ──────────────────────────
        imports: dict[str, list[str]] = {}
        found_suspicious: list[str] = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                funcs: list[str] = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="replace")
                        funcs.append(func_name)
                        if func_name in SUSPICIOUS_IMPORTS:
                            found_suspicious.append(func_name)
                imports[dll_name] = funcs

        result["imports"] = imports
        result["suspicious_imports"] = sorted(set(found_suspicious))
        pe_score += min(10, len(found_suspicious) * 2)

        # ── Exports ──────────────────────────
        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="replace"))
        result["exports"] = exports

        # ── Resources ────────────────────────
        result["has_resources"] = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
        resource_types: list[str] = []
        if result["has_resources"]:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rt_name = RESOURCE_TYPE_MAP.get(entry.id, f"RT_{entry.id}")
                resource_types.append(rt_name)
        result["resource_types"] = resource_types

        # ── Overlay data ─────────────────────
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            try:
                file_size = os.path.getsize(file_path)
                result["overlay_size"] = file_size - overlay_offset
                if result["overlay_size"] > 1024:
                    pe_score += 3  # Suspicious appended data
            except OSError:
                result["overlay_size"] = 0
        else:
            result["overlay_size"] = 0

        result["pe_score"] = min(30, pe_score)

        pe.close()
        return result

    except Exception as exc:
        logger.error("PE header parsing failed for %s: %s", file_path, str(exc))
        try:
            pe.close()
        except Exception:
            pass
        return {"is_pe": True, "pe_score": 0, "error": str(exc)}
