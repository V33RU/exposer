"""Rules for obfuscation and runtime packer detection.

Two rules:
  EXP-054  MissingObfuscationRule   — readable class names → easy reverse engineering
  EXP-055  PackerDetectionRule      — known runtime packer / protector signatures
"""

import re
from collections import Counter
from typing import List, Set

from .base_rule import BaseRule, Finding, Severity, Confidence

# ── Known packer / protector fingerprints ─────────────────────────────────────
# Each entry: (display_name, list_of_file_or_class_indicators)
_PACKER_SIGNATURES: List[tuple] = [
    (
        "Bangcle (SecShell)",
        [
            "assets/bangcle_classes.jar",
            "assets/secshell",
            "com/secshell",
            "libsecexe.so",
            "libSecShell.so",
        ],
    ),
    (
        "Ijiami (AjShield)",
        [
            "assets/ijiami.dat",
            "assets/ajlibi",
            "com/ijiami",
            "libijiami.so",
        ],
    ),
    (
        "Qihoo 360 (Jiagu)",
        [
            "assets/jiagu",
            "com/qihoo360",
            "com/stub360",
            "libjiagu.so",
            "libprotectClass.so",
        ],
    ),
    (
        "Tencent Legu",
        [
            "assets/tencent_legu",
            "com/tencent/StubShell",
            "libshella",
            "libtup.so",
        ],
    ),
    (
        "Baidu Protection",
        [
            "assets/baiduprotect",
            "com/baidu/protect",
            "libbaiduprotect.so",
        ],
    ),
    (
        "DexProtector",
        [
            "assets/dexprotector",
            "com/dexprotect",
        ],
    ),
    (
        "DexGuard",
        [
            "com/saikoa/dexguard",
            "assets/dexguard",
        ],
    ),
    (
        "ApkProtect",
        [
            "assets/apkprotect",
            "com/apkprotect",
            "libAPKProtect.so",
        ],
    ),
    (
        "Promon SHIELD",
        [
            "com/promon",
            "assets/promon",
        ],
    ),
    (
        "nqshield",
        [
            "com/nqmobile/antivirus20/shield",
            "libnqshield.so",
        ],
    ),
]

# Regex for a clearly obfuscated class/package segment (1-2 lowercase chars)
_OBFUSCATED_SEGMENT = re.compile(r"^[a-z]{1,2}$")

# Minimum number of classes in an APK before we bother scoring obfuscation
_MIN_CLASS_COUNT = 20


def _class_to_package_path(dalvik_name: str) -> str:
    """Convert 'Lcom/example/Foo;' → 'com/example/Foo'."""
    return dalvik_name.lstrip("L").rstrip(";").replace("\\", "/")


def _looks_obfuscated(class_path: str) -> bool:
    """Return True if the class name looks obfuscated (e.g. a.b.C, a/b/C)."""
    parts = class_path.replace("/", ".").split(".")
    if not parts:
        return False
    # Obfuscated: most segments are 1–2 lowercase chars
    obf_segments = sum(1 for p in parts if _OBFUSCATED_SEGMENT.match(p))
    return obf_segments >= max(1, len(parts) // 2)


def _get_all_class_names(apk_parser) -> List[str]:
    """Return a flat list of dotted class names from all DEX files."""
    names: List[str] = []
    if not apk_parser.analysis:
        return names
    try:
        for cls in apk_parser.analysis.get_classes():
            names.append(_class_to_package_path(cls.name))
    except Exception:
        pass
    return names


def _get_apk_file_list(apk_parser) -> List[str]:
    """Return the list of file names inside the APK."""
    if apk_parser.apk is None:
        return []
    try:
        return list(apk_parser.apk.get_files())
    except Exception:
        return []


# ── EXP-054: Missing Obfuscation ─────────────────────────────────────────────

class MissingObfuscationRule(BaseRule):
    """Flag apps with unobfuscated class names — easy reverse engineering target."""

    rule_id        = "EXP-054"
    title          = "Missing Code Obfuscation (No ProGuard/R8)"
    severity       = Severity.MEDIUM
    cwe            = "CWE-656"
    component_type = "obfuscation"
    description    = (
        "The application's class names and package structure are human-readable, "
        "suggesting ProGuard, R8, or DexGuard was not applied. An attacker can "
        "decompile the APK with jadx or apktool and immediately navigate the "
        "business logic, authentication flow, and API endpoints without any "
        "reverse-engineering effort."
    )
    remediation    = (
        "Enable R8 / ProGuard in your release build:\n"
        "  android { buildTypes { release { minifyEnabled true\n"
        "    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),\n"
        "    'proguard-rules.pro' } } }\n"
        "Consider DexGuard for additional string encryption and class encryption."
    )
    references     = (
        "https://developer.android.com/build/shrink-code",
        "https://cwe.mitre.org/data/definitions/656.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering",
    )

    def check(self) -> List[Finding]:
        class_names = _get_all_class_names(self.apk_parser)

        # Filter out Android framework / support library classes
        app_pkg = self.apk_parser.get_package_name().replace(".", "/")
        app_classes = [
            c for c in class_names
            if not c.startswith((
                "android/", "androidx/", "kotlin/", "kotlinx/",
                "com/google/android/", "java/", "javax/",
                "com/google/gson", "okhttp3/", "retrofit2/",
            ))
        ]

        if len(app_classes) < _MIN_CLASS_COUNT:
            return []

        obfuscated   = sum(1 for c in app_classes if _looks_obfuscated(c))
        readable     = len(app_classes) - obfuscated
        obf_ratio    = obfuscated / len(app_classes)

        # If more than 60 % of app classes look obfuscated, consider it OK
        if obf_ratio > 0.60:
            return []

        score = int((1 - obf_ratio) * 10)   # 0 = fully obfuscated, 10 = fully readable

        sample_readable = sorted(
            (c for c in app_classes if not _looks_obfuscated(c)),
            key=len,
        )[:8]

        return [self.create_finding(
            component_name=self.apk_parser.get_package_name() or "Application",
            confidence=Confidence.CONFIRMED,
            exploit_commands=[
                "# Decompile with jadx (no obfuscation = immediate source readability):",
                "jadx -d output/ target.apk",
                "# Or apktool for smali:",
                "apktool d target.apk -o output/",
                "# Browse the class tree directly:",
                "jadx-gui target.apk",
            ],
            exploit_scenario=(
                f"{readable} out of {len(app_classes)} app classes have readable names "
                f"(obfuscation score: {score}/10). "
                "An attacker can decompile the APK and immediately locate authentication logic, "
                "API keys, business rules, and hardcoded endpoints without any reverse-engineering tooling."
            ),
            details={
                "total_app_classes":   len(app_classes),
                "readable_classes":    readable,
                "obfuscated_classes":  obfuscated,
                "obfuscation_ratio":   f"{obf_ratio:.0%}",
                "obfuscation_score":   f"{score}/10 (10 = fully readable)",
                "sample_class_names":  sample_readable,
            },
        )]


# ── EXP-055: Runtime Packer Detection ────────────────────────────────────────

class PackerDetectionRule(BaseRule):
    """Detect known runtime packers / protectors embedded in the APK."""

    rule_id        = "EXP-055"
    title          = "Runtime Packer / Protector Detected"
    severity       = Severity.INFO
    cwe            = "CWE-656"
    component_type = "obfuscation"
    description    = (
        "The APK contains signatures of a known runtime packer or application "
        "protector. Packers unpack the real DEX at runtime, which can hide "
        "malicious code from static analysis tools and complicates security review. "
        "Some packers also actively block Frida, root detection bypasses, and "
        "dynamic analysis frameworks."
    )
    remediation    = (
        "If the packer is intentional (anti-tamper), document it and ensure it "
        "does not interfere with security testing or compliance audits. "
        "For security testing, use Frida scripts to dump the unpacked DEX at runtime "
        "or run the app in an emulator with memory dumping enabled."
    )
    references     = (
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering",
        "https://github.com/pxb1988/dex2jar",
    )

    def check(self) -> List[Finding]:
        findings = []
        apk_files  = set(_get_apk_file_list(self.apk_parser))
        class_names = set(_get_all_class_names(self.apk_parser))

        # Merge into one searchable blob of strings
        all_strings = apk_files | class_names

        for packer_name, indicators in _PACKER_SIGNATURES:
            matched = [ind for ind in indicators if any(ind in s for s in all_strings)]
            if not matched:
                continue

            findings.append(self.create_finding(
                component_name=f"packer::{packer_name.split()[0].lower()}",
                confidence=Confidence.CONFIRMED if len(matched) >= 2 else Confidence.LIKELY,
                exploit_commands=[
                    f"# Dump unpacked DEX at runtime with Frida:",
                    f"frida -U -n {self.apk_parser.get_package_name()} "
                    f"-e \"Memory.scan(...)\"",
                    f"# Or use dexdump after unpacking with apktool:",
                    f"apktool d target.apk && dex2jar target/classes.dex",
                    f"# Anti-packer scripts (fridantifrida bypass):",
                    f"frida -U --codeshare dzonerzy/fridantifrida -n {self.apk_parser.get_package_name()}",
                ],
                exploit_scenario=(
                    f"Packer '{packer_name}' was detected via: {', '.join(matched)}. "
                    "The actual application DEX is unpacked into memory at runtime. "
                    "Static analysis tools see only a stub — the real code is hidden. "
                    "Dynamic analysis may be blocked by anti-Frida / anti-root checks built into the packer."
                ),
                details={
                    "packer":         packer_name,
                    "matched_indicators": matched,
                },
            ))

        return findings
