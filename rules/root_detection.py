"""Rules for detecting root/jailbreak detection mechanisms and generating bypass scripts."""

from typing import List, Set, Tuple

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java


class _RootDetectionBase(BaseRule):
    """Shared infrastructure for root-detection rules.

    Provides curated signature catalogues and helper methods used by all
    three concrete rules (file-based, API-based, native-based).
    """

    component_type = "security"

    # ── File-system artefacts checked by common root-detection libraries ──────

    ROOT_BINARIES: Tuple[str, ...] = (
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/su/bin/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU/SuperSU.apk",
    )

    ROOT_PACKAGES: Tuple[str, ...] = (
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine",
        "com.topjohnwu.magisk",
        "me.phh.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.onecleanmaster",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "io.github.vvb2060.magisk",
    )

    DANGEROUS_PROPS: Tuple[str, ...] = (
        "ro.debuggable",
        "ro.secure",
        "ro.build.selinux",
        "ro.build.tags",
        "service.adb.root",
    )

    # ── Call-graph search patterns ────────────────────────────────────────────

    # Java / Kotlin API patterns that indicate programmatic root checks.
    API_SIGNATURES: Tuple[str, ...] = (
        # Runtime.exec("su") / ProcessBuilder("su")
        "Runtime;->exec",
        "ProcessBuilder;-><init>",
        # File.exists() preceded by string constants of su paths
        "File;->exists",
        "File;->canRead",
        "File;->canWrite",
        "File;->canExecute",
        # PackageManager.getPackageInfo for root packages
        "PackageManager;->getPackageInfo",
        "PackageManager;->getInstalledPackages",
        "PackageManager;->getInstalledApplications",
        # Build.TAGS == "test-keys"
        "Build;->TAGS",
        # Settings.Secure / Settings.Global for ADB enabled
        "Settings$Secure;->getString",
        "Settings$Global;->getString",
    )

    # Patterns indicating native (JNI / .so) root detection.
    NATIVE_SIGNATURES: Tuple[str, ...] = (
        "System;->loadLibrary",
        "System;->load",
        "Runtime;->loadLibrary",
        "Runtime;->load",
    )

    # Well-known root-detection library class prefixes.
    ROOT_DETECTION_LIBRARIES: Tuple[str, ...] = (
        "com.scottyab.rootbeer",
        "com.scottyab.rootchecker",
        "com.noshufou.android.su.util",
        "com.stericson.RootTools",
        "com.stericson.RootShell",
        "de.robv.android.xposed",
        "com.devadvance.rootcloak",
        "com.topjohnwu.magisk",
        "com.guardsquare.dexguard",
        "com.scottyab.safetynet",
        "com.google.android.gms.safetynet",
        "com.google.android.play.core.integrity",
    )

    # ── Helper methods ────────────────────────────────────────────────────────

    def _search_string_pool(self, needles: Tuple[str, ...]) -> List[str]:
        """Return DEX string-pool entries that contain any of *needles*."""
        if not (hasattr(self.apk_parser, "apk") and self.apk_parser.apk):
            return []

        hits: List[str] = []
        strings: Set[str] = set()
        try:
            for dex in self.apk_parser.apk.get_all_dex():
                if hasattr(dex, "get_strings"):
                    strings.update(dex.get_strings())
        except Exception:
            return hits

        for s in strings:
            text = str(s).strip()
            if any(needle in text for needle in needles):
                hits.append(text)
        return hits

    def _methods_referencing_library(self, prefixes: Tuple[str, ...]) -> List[str]:
        """Return call-graph method signatures whose class matches a known library prefix."""
        if not self.callgraph:
            return []

        results: List[str] = []
        for prefix in prefixes:
            dalvik_prefix = "L" + prefix.replace(".", "/")
            for sig in self.callgraph.search_methods(dalvik_prefix):
                results.append(sig)
        return results


# ─────────────────────────────────────────────────────────────────────────────
# EXP-044  File-Based Root Detection
# ─────────────────────────────────────────────────────────────────────────────

class FileBasedRootDetectionRule(_RootDetectionBase):
    """Detect file-system checks for su binaries, root packages, and system properties."""

    rule_id = "EXP-044"
    title = "File-Based Root Detection"
    severity = Severity.INFO
    cwe = "CWE-919"
    description = (
        "The application checks for the presence of su binaries, root-management "
        "packages, or dangerous system properties on the file system. While this "
        "is a defensive measure, it can be trivially bypassed with Frida or Magisk "
        "Hide, and pentesters need ready-made bypass scripts."
    )
    remediation = (
        "Root detection alone is insufficient. Combine with SafetyNet/Play Integrity "
        "attestation, certificate pinning, and runtime application self-protection (RASP). "
        "Avoid relying solely on file-existence checks."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/919.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0004/",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        # Strategy 1: Scan the string pool for su paths and root package names.
        su_hits = self._search_string_pool(self.ROOT_BINARIES)
        pkg_hits = self._search_string_pool(self.ROOT_PACKAGES)
        prop_hits = self._search_string_pool(self.DANGEROUS_PROPS)

        all_hits = su_hits + pkg_hits + prop_hits
        if not all_hits:
            return findings

        # Deduplicate and categorise.
        su_paths = sorted({h for h in su_hits if "/" in h})
        root_pkgs = sorted({h for h in pkg_hits if "." in h and "/" not in h})
        props = sorted(set(prop_hits))

        details = {}
        snippet_parts: List[str] = []

        if su_paths:
            details["su_binary_paths"] = su_paths[:10]
            snippet_parts.append(
                "// Su binary checks detected:\n"
                + "\n".join(f'new File("{p}").exists();' for p in su_paths[:5])
            )
        if root_pkgs:
            details["root_packages"] = root_pkgs[:10]
            snippet_parts.append(
                "// Root package checks detected:\n"
                + "\n".join(
                    f'pm.getPackageInfo("{p}", 0);' for p in root_pkgs[:5]
                )
            )
        if props:
            details["system_properties"] = props
            snippet_parts.append(
                "// System property checks detected:\n"
                + "\n".join(f'System.getProperty("{p}");' for p in props[:5])
            )

        confidence = (
            Confidence.CONFIRMED
            if len(all_hits) >= 3
            else Confidence.LIKELY
        )

        findings.append(self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=details,
            exploit_commands=[
                "# Bypass file-based root detection with Magisk Hide / DenyList:",
                "magisk --denylist add <package_name>",
                "# Or use the auto-generated Frida script to hook File.exists():",
                f"frida -U -f {self.apk_parser.get_package_name()} -l EXP-044_Application.js --no-pause",
            ],
            exploit_scenario=(
                "The app checks for su binaries and root management packages on "
                "the file system. An attacker can bypass all checks using Magisk "
                "DenyList (hides mount namespace) or a Frida script that returns "
                "false for every probed path."
            ),
            api_level_affected="All",
        ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# EXP-045  API-Based Root Detection
# ─────────────────────────────────────────────────────────────────────────────

class APIBasedRootDetectionRule(_RootDetectionBase):
    """Detect Java/Kotlin API calls used for root detection (exec, Build.TAGS, etc.)."""

    rule_id = "EXP-045"
    title = "API-Based Root Detection"
    severity = Severity.INFO
    cwe = "CWE-919"
    description = (
        "The application uses Java APIs to detect a rooted environment: "
        "Runtime.exec(\"su\"), Build.TAGS == \"test-keys\", or PackageManager "
        "queries for root-management apps. These checks are hookable at the "
        "Java layer with Frida."
    )
    remediation = (
        "Supplement API-based checks with native (NDK) detection, SafetyNet / "
        "Play Integrity attestation, and anti-tamper mechanisms. Obfuscate "
        "detection logic to raise the cost of bypassing."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/919.html",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0004/",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        if not self.callgraph:
            return findings

        # Collect call-graph hits for each API pattern.
        detected_apis: List[str] = []
        seen: Set[str] = set()

        for pattern in self.API_SIGNATURES:
            for sig in self.callgraph.search_methods(pattern):
                class_name = dalvik_to_java(sig)
                if self._is_third_party_component(class_name):
                    continue
                if sig in seen:
                    continue
                seen.add(sig)
                detected_apis.append(sig)

        # Also check for known root-detection library usage.
        lib_methods = self._methods_referencing_library(self.ROOT_DETECTION_LIBRARIES)
        lib_classes: Set[str] = set()
        for sig in lib_methods:
            cls = dalvik_to_java(sig)
            if cls and not self._is_third_party_component(cls):
                lib_classes.add(cls)

        if not detected_apis and not lib_classes:
            return findings

        details: dict = {}
        snippet_parts: List[str] = []

        if detected_apis:
            # Group by detection category for clarity.
            exec_calls = [s for s in detected_apis if "exec" in s or "ProcessBuilder" in s]
            file_calls = [s for s in detected_apis if "File;" in s]
            pkg_calls = [s for s in detected_apis if "PackageManager" in s]
            build_calls = [s for s in detected_apis if "Build" in s or "Settings" in s]

            if exec_calls:
                details["runtime_exec_checks"] = exec_calls[:5]
                snippet_parts.append(
                    "// Runtime.exec / ProcessBuilder root checks:\n"
                    'Runtime.getRuntime().exec("su");'
                )
            if file_calls:
                details["file_existence_checks"] = file_calls[:5]
                snippet_parts.append(
                    "// File.exists checks for su paths:\n"
                    'new File("/system/bin/su").exists();'
                )
            if pkg_calls:
                details["package_manager_checks"] = pkg_calls[:5]
                snippet_parts.append(
                    "// PackageManager root-package queries:\n"
                    'pm.getPackageInfo("com.topjohnwu.magisk", 0);'
                )
            if build_calls:
                details["build_property_checks"] = build_calls[:5]
                snippet_parts.append(
                    "// Build.TAGS / Settings checks:\n"
                    'String tags = android.os.Build.TAGS;  // \"test-keys\" == rooted'
                )

        if lib_classes:
            details["root_detection_libraries"] = sorted(lib_classes)[:10]
            snippet_parts.append(
                "// Third-party root detection libraries in use:\n"
                + "\n".join(f"// - {cls}" for cls in sorted(lib_classes)[:5])
            )

        confidence = Confidence.CONFIRMED if lib_classes else (
            Confidence.LIKELY if len(detected_apis) >= 3 else Confidence.POSSIBLE
        )

        pkg = self.apk_parser.get_package_name()
        findings.append(self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=details,
            exploit_commands=[
                "# Bypass API-based root detection with Frida:",
                f"frida -U -f {pkg} -l EXP-045_Application.js --no-pause",
                "# Or use objection for quick bypass:",
                f"objection -g {pkg} explore --startup-command 'android root disable'",
            ],
            exploit_scenario=(
                "The app uses Java APIs (Runtime.exec, Build.TAGS, PackageManager) "
                "to detect root. All these APIs operate in the Java layer and can "
                "be intercepted with Frida. The generated bypass script hooks every "
                "detected check point and returns safe values."
            ),
            api_level_affected="All",
        ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# EXP-046  Native Root Detection & Integrity Attestation
# ─────────────────────────────────────────────────────────────────────────────

class NativeRootDetectionRule(_RootDetectionBase):
    """Detect native library loading and SafetyNet/Play Integrity attestation calls."""

    rule_id = "EXP-046"
    title = "Native / Attestation Root Detection"
    severity = Severity.LOW
    cwe = "CWE-919"
    description = (
        "The application loads native libraries (potentially for NDK-level root "
        "detection) or calls Google SafetyNet / Play Integrity APIs for device "
        "attestation. Native checks are harder to bypass but not impossible; "
        "attestation can be replayed or the response spoofed client-side."
    )
    remediation = (
        "Native detection raises the bar but is still bypassable via Frida's "
        "Interceptor or LD_PRELOAD. Combine native checks with server-side "
        "attestation verification — never trust client-side verdicts alone. "
        "Pin the attestation API certificate."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/919.html",
        "https://developer.android.com/training/safetynet/attestation",
        "https://developer.android.com/google/play/integrity/overview",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0004/",
    )

    # Heuristic: native libraries whose names suggest security / integrity checks.
    _SECURITY_LIB_KEYWORDS = (
        "root", "detect", "integrity", "tamper", "guard", "protect",
        "secure", "safety", "shield", "checker", "verify", "anti",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        if not self.callgraph:
            return findings

        # 1. Detect System.loadLibrary / System.load calls.
        native_loads: List[str] = []
        seen: Set[str] = set()
        for pattern in self.NATIVE_SIGNATURES:
            for sig in self.callgraph.search_methods(pattern):
                if sig in seen:
                    continue
                seen.add(sig)
                class_name = dalvik_to_java(sig)
                if not self._is_third_party_component(class_name):
                    native_loads.append(sig)

        # 2. Check string pool for library names suggesting security checks.
        security_libs = self._search_string_pool(self._SECURITY_LIB_KEYWORDS)
        # Filter to short strings that look like .so names.
        so_names = sorted({
            s for s in security_libs
            if len(s) < 80 and any(kw in s.lower() for kw in self._SECURITY_LIB_KEYWORDS)
        })

        # 3. Detect SafetyNet / Play Integrity attestation API calls.
        attestation_methods: List[str] = []
        attestation_patterns = (
            "SafetyNet",
            "safetynet",
            "IntegrityManager",
            "PlayIntegrity",
            "play/core/integrity",
        )
        for pattern in attestation_patterns:
            for sig in self.callgraph.search_methods(pattern):
                if sig not in seen:
                    seen.add(sig)
                    attestation_methods.append(sig)

        if not native_loads and not attestation_methods:
            return findings

        details: dict = {}
        snippet_parts: List[str] = []

        if native_loads:
            details["native_library_loads"] = native_loads[:8]
            snippet_parts.append(
                "// Native library loading (potential NDK root detection):\n"
                + "\n".join(
                    f"// {dalvik_to_java(sig)}" for sig in native_loads[:5]
                )
            )
        if so_names:
            details["security_library_names"] = so_names[:10]
            snippet_parts.append(
                "// Suspected security-related native libraries:\n"
                + "\n".join(f'System.loadLibrary("{name}");' for name in so_names[:5])
            )
        if attestation_methods:
            details["attestation_apis"] = attestation_methods[:5]
            snippet_parts.append(
                "// SafetyNet / Play Integrity attestation calls:\n"
                + "\n".join(
                    f"// {dalvik_to_java(sig)}" for sig in attestation_methods[:5]
                )
            )

        has_attestation = len(attestation_methods) > 0
        confidence = Confidence.CONFIRMED if has_attestation else (
            Confidence.LIKELY if so_names else Confidence.POSSIBLE
        )

        pkg = self.apk_parser.get_package_name()
        findings.append(self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=details,
            exploit_commands=[
                "# Bypass native root detection with Frida Interceptor:",
                f"frida -U -f {pkg} -l EXP-046_Application.js --no-pause",
                "# For SafetyNet bypass, use a modified Magisk module:",
                "# https://github.com/kdrag0n/safetynet-fix (Universal SafetyNet Fix)",
                "# Or spoof the attestation response with Frida:",
                f"frida -U -f {pkg} -l safetynet_bypass.js --no-pause",
            ],
            exploit_scenario=(
                "The app uses native libraries and/or Google attestation APIs for "
                "root detection. Native checks can be bypassed with Frida's "
                "Interceptor.attach on libc fopen/access/stat. SafetyNet/Play "
                "Integrity responses can be spoofed client-side or bypassed with "
                "Magisk modules (Universal SafetyNet Fix, Play Integrity Fix)."
            ),
            api_level_affected="All",
        ))

        return findings
