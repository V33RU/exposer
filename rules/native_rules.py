"""Rules for detecting security issues in native (.so) libraries bundled in the APK.

Three rules:
  EXP-051  UnsafeNativeFunctionsRule    — imports of dangerous libc functions
  EXP-052  MissingELFProtectionsRule    — missing PIE / stack-canary / RELRO / NX
  EXP-053  NativeHardcodedSecretsRule   — plaintext secrets in .so string tables
"""

import re
import struct
from typing import List, Optional, Set, Tuple

from .base_rule import BaseRule, Finding, Severity, Confidence

# ── ELF constants ─────────────────────────────────────────────────────────────
_ELF_MAGIC      = b"\x7fELF"
_ELFCLASS32     = 1
_ELFCLASS64     = 2
_ELFDATA2LSB    = 1   # little-endian
_ET_DYN         = 3   # shared object (PIE exec or .so)
_ET_EXEC        = 2   # non-PIE executable
_PT_GNU_STACK   = 0x6474e551
_PT_GNU_RELRO   = 0x6474e552
_SHT_DYNSYM     = 11
_SHT_STRTAB     = 3
_SHT_DYNAMIC    = 6
_DT_NULL        = 0
_DT_FLAGS       = 30
_DT_FLAGS_1     = 0x6FFFFFFB
_DF_BIND_NOW    = 0x8
_DF_1_NOW       = 0x1
_PF_X           = 0x1   # executable segment flag

# Dangerous libc / POSIX functions and their CWE
_DANGEROUS_FUNCS: dict = {
    "gets":        "CWE-120: Unbounded read — always unsafe",
    "strcpy":      "CWE-120: Buffer copy without size check",
    "strcat":      "CWE-120: Buffer concatenation without size check",
    "sprintf":     "CWE-134: Uncontrolled format string / overflow",
    "vsprintf":    "CWE-134: Uncontrolled format string / overflow",
    "scanf":       "CWE-120: Unbounded input from stdin",
    "sscanf":      "CWE-120: Unbounded input from string",
    "system":      "CWE-78: OS command injection",
    "popen":       "CWE-78: OS command injection via shell",
    "execl":       "CWE-78: Command injection — verify arguments are not user-controlled",
    "execlp":      "CWE-78: Command injection via PATH lookup",
    "execle":      "CWE-78: Command injection",
    "execv":       "CWE-78: Command injection — verify argv",
    "execvp":      "CWE-78: Command injection via PATH lookup",
    "execvpe":     "CWE-78: Command injection",
    "strtok":      "CWE-119: Non-reentrant; unsafe in multi-threaded code",
    "setuid":      "CWE-250: Potential privilege escalation",
    "setgid":      "CWE-250: Potential privilege escalation",
}

# Regex patterns for secrets embedded as strings inside .so files
_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),               "Google API key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"),                      "AWS Access Key ID"),
    (re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"),              "Stripe live secret key"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"),                   "GitHub personal access token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Embedded private key PEM block"),
    (re.compile(
        rb"(?:password|passwd|secret|api_key|api_secret|access_key)\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{8,})['\"]",
        re.IGNORECASE,
    ), "Hardcoded credential assignment"),
]

# ── Minimal ELF analyser ──────────────────────────────────────────────────────

class _ELFInfo:
    """Parse the ELF header + program headers + dynamic section of a .so blob."""

    __slots__ = (
        "valid", "arch", "is_pie",
        "has_canary", "has_nx", "has_relro", "has_full_relro",
        "imported_symbols",
    )

    def __init__(self, data: bytes) -> None:
        self.valid           = False
        self.arch            = "?"
        self.is_pie          = False
        self.has_canary      = False
        self.has_nx          = False
        self.has_relro       = False
        self.has_full_relro  = False
        self.imported_symbols: Set[str] = set()

        if len(data) < 16 or data[:4] != _ELF_MAGIC:
            return

        ei_class = data[4]
        ei_data  = data[5]

        is64 = ei_class == _ELFCLASS64
        end  = "<" if ei_data == _ELFDATA2LSB else ">"
        self.arch = "arm64" if is64 else "arm"

        try:
            self._parse(data, is64, end)
        except Exception:
            pass   # corrupt / truncated ELF — still mark valid=True for partial info

        self.valid = True

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _cstr(buf: bytes, offset: int) -> str:
        end = buf.find(b"\x00", offset)
        if end == -1:
            return ""
        return buf[offset:end].decode("ascii", errors="ignore")

    def _parse(self, d: bytes, is64: bool, end: str) -> None:
        # ELF header fields we need
        if is64:
            e_type, _, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, \
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                f"{end}HHIQQQIHHHHHH", d, 16)
        else:
            e_type, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, \
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                f"{end}HHIIIIIHHHHHH", d, 16)

        self.is_pie = (e_type == _ET_DYN)

        # ── Program headers → NX and RELRO ───────────────────────────────────
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is64:
                if off + 56 > len(d):
                    break
                p_type, p_flags = struct.unpack_from(f"{end}II", d, off)
            else:
                if off + 32 > len(d):
                    break
                p_type = struct.unpack_from(f"{end}I", d, off)[0]
                p_flags = struct.unpack_from(f"{end}I", d, off + 24)[0]

            if p_type == _PT_GNU_STACK:
                self.has_nx = not bool(p_flags & _PF_X)
            elif p_type == _PT_GNU_RELRO:
                self.has_relro = True

        # ── Section headers → .dynstr / .dynsym / .dynamic ───────────────────
        if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
            return

        def read_shdr(idx: int):
            off = e_shoff + idx * e_shentsize
            if is64:
                return struct.unpack_from(f"{end}IIQQQQIIQQ", d, off)
            else:
                return struct.unpack_from(f"{end}IIIIIIIIII", d, off)

        # Section name string table
        sh = read_shdr(e_shstrndx)
        sh_offset, sh_size = (sh[4], sh[5]) if is64 else (sh[4], sh[5])
        shstrtab = d[sh_offset: sh_offset + sh_size]

        dynstr   = b""
        dynsym_offset = dynsym_size = dynsym_entsize = 0
        dynamic_offset = dynamic_size = 0

        for i in range(e_shnum):
            sh = read_shdr(i)
            sh_name, sh_type = sh[0], sh[1]
            sh_offset, sh_size = (sh[4], sh[5]) if is64 else (sh[4], sh[5])
            sh_entsize = sh[9] if is64 else sh[8]
            name = self._cstr(shstrtab, sh_name)

            if sh_type == _SHT_DYNSYM:
                dynsym_offset  = sh_offset
                dynsym_size    = sh_size
                dynsym_entsize = sh_entsize or (24 if is64 else 16)
            elif sh_type == _SHT_STRTAB and name == ".dynstr":
                dynstr = d[sh_offset: sh_offset + sh_size]
            elif sh_type == _SHT_DYNAMIC:
                dynamic_offset = sh_offset
                dynamic_size   = sh_size

        # Parse .dynsym for imported symbol names
        if dynsym_offset and dynstr and dynsym_entsize:
            n = dynsym_size // dynsym_entsize
            for i in range(n):
                sym_off = dynsym_offset + i * dynsym_entsize
                st_name = struct.unpack_from(f"{end}I", d, sym_off)[0]
                sym = self._cstr(dynstr, st_name)
                if sym:
                    self.imported_symbols.add(sym)

        self.has_canary = (
            "__stack_chk_fail" in self.imported_symbols
            or "__stack_chk_guard" in self.imported_symbols
        )

        # Parse .dynamic for BIND_NOW → full RELRO
        if dynamic_offset and dynamic_size:
            entry_sz = 16 if is64 else 8
            fmt = f"{end}qq" if is64 else f"{end}ii"
            for i in range(dynamic_size // entry_sz):
                off = dynamic_offset + i * entry_sz
                d_tag, d_val = struct.unpack_from(fmt, d, off)
                if d_tag == _DT_NULL:
                    break
                if d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
                    self.has_full_relro = self.has_relro
                elif d_tag == _DT_FLAGS_1 and (d_val & _DF_1_NOW):
                    self.has_full_relro = self.has_relro


def _get_so_files(apk_parser) -> List[Tuple[str, bytes]]:
    """Return (name, bytes) for every .so embedded in the APK."""
    apk = apk_parser.apk
    if apk is None:
        return []
    results = []
    for fname in apk.get_files():
        if fname.endswith(".so"):
            try:
                data = apk.get_file(fname)
                if data:
                    results.append((fname, data))
            except Exception:
                pass
    return results


# ── EXP-051: Unsafe Native Functions ─────────────────────────────────────────

class UnsafeNativeFunctionsRule(BaseRule):
    """Detect imports of dangerous libc functions in bundled .so libraries — CWE-120/78."""

    rule_id      = "EXP-051"
    title        = "Unsafe Native Function Usage in .so Library"
    severity     = Severity.HIGH
    cwe          = "CWE-120"
    component_type = "native"
    description  = (
        "One or more bundled native libraries import unsafe C standard library "
        "functions (e.g. strcpy, sprintf, system) that are classic sources of "
        "buffer overflows, format-string bugs, and OS command injection. "
        "Even if the vulnerability is latent, the presence of these calls raises "
        "the attack surface and is flagged by Play Store security checks."
    )
    remediation  = (
        "Replace unsafe functions with their bounds-checked counterparts: "
        "strcpy → strlcpy/strncpy, sprintf → snprintf, gets → fgets, "
        "system/popen → avoid or validate all arguments rigorously. "
        "Enable compiler hardening: -fstack-protector-all, -D_FORTIFY_SOURCE=2."
    )
    references   = (
        "https://cwe.mitre.org/data/definitions/120.html",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://developer.android.com/ndk/guides/abis#security",
    )

    def check(self) -> List[Finding]:
        findings = []
        so_files = _get_so_files(self.apk_parser)
        if not so_files:
            return findings

        # Aggregate dangerous hits across all .so files
        hits: dict = {}   # func_name → [lib_name, …]
        for lib_name, data in so_files:
            elf = _ELFInfo(data)
            if not elf.valid:
                continue
            for sym in elf.imported_symbols:
                # Strip leading underscore (macOS convention) or version suffix
                base = sym.lstrip("_").split("@")[0]
                if base in _DANGEROUS_FUNCS:
                    hits.setdefault(base, []).append(lib_name.split("/")[-1])

        for func, libs in hits.items():
            libs_str = ", ".join(sorted(set(libs)))
            findings.append(self.create_finding(
                component_name=f"native::{func}",
                confidence=Confidence.CONFIRMED,
                code_snippet=f"// Dangerous import detected in: {libs_str}\n{func}(...);",
                exploit_commands=[
                    f"# Identify callers with radare2 or Ghidra",
                    f"r2 -AA {libs[0]} -q -c 'afl~{func}'",
                    f"# Or with nm:",
                    f"nm -D {libs[0]} | grep {func}",
                ],
                exploit_scenario=(
                    f"'{func}' is imported in [{libs_str}]. "
                    f"{_DANGEROUS_FUNCS[func]}. "
                    "If attacker-controlled data reaches this call, memory corruption "
                    "or command injection may be achieved."
                ),
                details={
                    "function":  func,
                    "libraries": sorted(set(libs)),
                    "risk":      _DANGEROUS_FUNCS[func],
                },
            ))

        return findings


# ── EXP-052: Missing ELF Security Features ───────────────────────────────────

class MissingELFProtectionsRule(BaseRule):
    """Detect .so files missing PIE, stack canary, RELRO, or NX — CWE-693."""

    rule_id      = "EXP-052"
    title        = "Missing ELF Security Hardening in Native Library"
    severity     = Severity.MEDIUM
    cwe          = "CWE-693"
    component_type = "native"
    description  = (
        "Native libraries bundled in the APK are missing one or more ELF security "
        "mitigations: PIE (position-independent), stack canary, RELRO (relocation "
        "read-only), or NX (non-executable stack). These make exploitation of memory "
        "corruption bugs significantly easier."
    )
    remediation  = (
        "Compile with: -fPIC -pie -fstack-protector-strong -Wl,-z,relro,-z,now. "
        "Ensure the NDK build system sets these flags (the default NDK toolchain "
        "enables them for API >= 17). Do not use legacy standalone toolchains."
    )
    references   = (
        "https://source.android.com/docs/security/enhancements",
        "https://cwe.mitre.org/data/definitions/693.html",
        "https://developer.android.com/ndk/guides/abis#security",
    )

    def check(self) -> List[Finding]:
        findings = []
        so_files = _get_so_files(self.apk_parser)
        if not so_files:
            return findings

        for lib_name, data in so_files:
            elf = _ELFInfo(data)
            if not elf.valid:
                continue

            missing = []
            if not elf.has_canary:
                missing.append("Stack Canary")
            if not elf.has_nx:
                missing.append("NX (non-executable stack)")
            if not elf.has_relro:
                missing.append("RELRO")
            elif not elf.has_full_relro:
                missing.append("Full RELRO (only partial)")

            if not missing:
                continue

            short = lib_name.split("/")[-1]
            findings.append(self.create_finding(
                component_name=f"native::{short}",
                confidence=Confidence.CONFIRMED,
                exploit_commands=[
                    f"# Check protection flags with checksec (pwntools):",
                    f"checksec --file={short}",
                    f"# Or with readelf:",
                    f"readelf -l {short} | grep -E 'GNU_STACK|GNU_RELRO'",
                    f"nm -D {short} | grep stack_chk",
                ],
                exploit_scenario=(
                    f"{short} is missing: {', '.join(missing)}. "
                    "An attacker who finds a memory-corruption bug (e.g. buffer overflow) "
                    "in this library can exploit it more easily: no canary means stack smashing "
                    "goes undetected; no RELRO means GOT overwrite is possible; no NX means "
                    "shellcode can be injected on the stack."
                ),
                details={
                    "library":  short,
                    "arch":     elf.arch,
                    "missing":  missing,
                    "has_pie":       elf.is_pie,
                    "has_canary":    elf.has_canary,
                    "has_nx":        elf.has_nx,
                    "has_relro":     elf.has_relro,
                    "has_full_relro": elf.has_full_relro,
                },
            ))

        return findings


# ── EXP-053: Hardcoded Secrets in Native Binaries ────────────────────────────

class NativeHardcodedSecretsRule(BaseRule):
    """Detect API keys, credentials, and private keys embedded in .so files — CWE-798."""

    rule_id      = "EXP-053"
    title        = "Hardcoded Secret in Native Library"
    severity     = Severity.CRITICAL
    cwe          = "CWE-798"
    component_type = "native"
    description  = (
        "A native library (.so) embedded in the APK contains what appears to be a "
        "hardcoded API key, credential, or private key in its string table. "
        "These can be extracted trivially with 'strings' or a hex editor — no "
        "decompilation or root access required."
    )
    remediation  = (
        "Never embed secrets in native code. Store credentials server-side or use "
        "Android Keystore for on-device key material. For API keys, use certificate "
        "pinning + server-side validation to limit the blast radius of exposure."
    )
    references   = (
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://developer.android.com/training/articles/keystore",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
    )

    def check(self) -> List[Finding]:
        findings = []
        seen: Set[str] = set()
        so_files = _get_so_files(self.apk_parser)
        if not so_files:
            return findings

        for lib_name, data in so_files:
            short = lib_name.split("/")[-1]
            for pattern, label in _SECRET_PATTERNS:
                for m in pattern.finditer(data):
                    snippet = m.group(0)[:80].decode("ascii", errors="replace")
                    key = f"{short}:{label}:{snippet[:30]}"
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(self.create_finding(
                        component_name=f"native::{short}",
                        confidence=Confidence.LIKELY,
                        code_snippet=f'// In {short} at offset {m.start():#x}:\n"{snippet}"',
                        exploit_commands=[
                            f"# Extract all strings from the library:",
                            f"strings -n 8 {short} | grep -i 'key\\|secret\\|password\\|AKIA\\|AIza'",
                            f"# Or view raw bytes around the match:",
                            f"xxd {short} | grep -A2 '{snippet[:10]}'",
                        ],
                        exploit_scenario=(
                            f"The string table of {short} contains a {label}. "
                            "An attacker who unpacks the APK (apktool d app.apk) and runs "
                            f"'strings {short}' will obtain the secret without any additional tools."
                        ),
                        details={
                            "library": short,
                            "type":    label,
                            "snippet": snippet,
                            "offset":  hex(m.start()),
                        },
                    ))

        return findings
