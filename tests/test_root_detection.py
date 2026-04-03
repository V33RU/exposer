"""Tests for rules.root_detection — Root/Jailbreak Detection rules."""

from unittest.mock import MagicMock, PropertyMock

import pytest

from rules.root_detection import (
    FileBasedRootDetectionRule,
    APIBasedRootDetectionRule,
    NativeRootDetectionRule,
)
from rules.base_rule import Severity, Confidence


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_apk_parser(strings=None, package_name="com.test.app"):
    """Create a mock APKParser whose DEX string pool returns *strings*."""
    parser = MagicMock()
    parser.get_package_name.return_value = package_name

    if strings is not None:
        dex = MagicMock()
        dex.get_strings.return_value = strings
        apk = MagicMock()
        apk.get_all_dex.return_value = [dex]
        parser.apk = apk
    else:
        parser.apk = None

    return parser


def _mock_callgraph(search_results=None, callee_map=None):
    """Create a mock CallGraph.

    *search_results* maps pattern strings to lists of matching signatures.
    *callee_map* maps a method signature to its list of callees.
    """
    cg = MagicMock()

    def _search(pattern):
        if search_results is None:
            return []
        for key, sigs in search_results.items():
            if key in pattern or pattern in key:
                return sigs
        return []

    cg.search_methods.side_effect = _search
    cg.get_callees.side_effect = lambda sig: (callee_map or {}).get(sig, [])
    return cg


def _make_rule(rule_cls, strings=None, search_results=None, callee_map=None,
               package_name="com.test.app"):
    """Instantiate a root-detection rule with mocked dependencies."""
    parser = _mock_apk_parser(strings=strings, package_name=package_name)
    cg = _mock_callgraph(search_results=search_results, callee_map=callee_map)
    taint = MagicMock()
    return rule_cls(parser, cg, taint)


# ─────────────────────────────────────────────────────────────────────────────
# FileBasedRootDetectionRule (EXP-044)
# ─────────────────────────────────────────────────────────────────────────────

class TestFileBasedRootDetection:

    def test_rule_metadata(self):
        rule = _make_rule(FileBasedRootDetectionRule)
        assert rule.rule_id == "EXP-044"
        assert rule.severity == Severity.INFO
        assert rule.cwe == "CWE-919"

    def test_no_findings_when_no_strings(self):
        rule = _make_rule(FileBasedRootDetectionRule, strings=[])
        findings = rule.check()
        assert findings == []

    def test_no_findings_when_apk_not_loaded(self):
        rule = _make_rule(FileBasedRootDetectionRule, strings=None)
        findings = rule.check()
        assert findings == []

    def test_detects_su_binary_paths(self):
        strings = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "hello world"]
        rule = _make_rule(FileBasedRootDetectionRule, strings=strings)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].rule_id == "EXP-044"
        assert findings[0].confidence == Confidence.CONFIRMED
        assert "su_binary_paths" in findings[0].details

    def test_detects_root_packages(self):
        strings = [
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "de.robv.android.xposed.installer",
        ]
        rule = _make_rule(FileBasedRootDetectionRule, strings=strings)
        findings = rule.check()
        assert len(findings) == 1
        assert "root_packages" in findings[0].details

    def test_detects_dangerous_properties(self):
        strings = ["ro.debuggable", "ro.secure", "ro.build.selinux"]
        rule = _make_rule(FileBasedRootDetectionRule, strings=strings)
        findings = rule.check()
        assert len(findings) == 1
        assert "system_properties" in findings[0].details

    def test_likely_confidence_with_fewer_hits(self):
        strings = ["/system/bin/su", "some_other_string"]
        rule = _make_rule(FileBasedRootDetectionRule, strings=strings)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.LIKELY

    def test_exploit_commands_include_package_name(self):
        strings = ["/system/bin/su", "/sbin/su", "com.topjohnwu.magisk"]
        rule = _make_rule(FileBasedRootDetectionRule, strings=strings,
                         package_name="com.example.target")
        findings = rule.check()
        assert len(findings) == 1
        assert any("com.example.target" in cmd for cmd in findings[0].exploit_commands)


# ─────────────────────────────────────────────────────────────────────────────
# APIBasedRootDetectionRule (EXP-045)
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIBasedRootDetection:

    def test_rule_metadata(self):
        rule = _make_rule(APIBasedRootDetectionRule)
        assert rule.rule_id == "EXP-045"
        assert rule.severity == Severity.INFO
        assert rule.cwe == "CWE-919"

    def test_no_findings_without_callgraph(self):
        parser = _mock_apk_parser(strings=[])
        rule = APIBasedRootDetectionRule(parser, None, MagicMock())
        findings = rule.check()
        assert findings == []

    def test_no_findings_when_no_apis_detected(self):
        rule = _make_rule(APIBasedRootDetectionRule, search_results={})
        findings = rule.check()
        assert findings == []

    def test_detects_runtime_exec(self):
        search_results = {
            "Runtime;->exec": [
                "Lcom/example/app/RootChecker;->checkRoot()V",
            ],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].rule_id == "EXP-045"

    def test_detects_build_tags(self):
        search_results = {
            "Build;->TAGS": [
                "Lcom/example/app/SecurityCheck;->isTestBuild()Z",
            ],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1

    def test_detects_package_manager_queries(self):
        search_results = {
            "PackageManager;->getPackageInfo": [
                "Lcom/example/app/RootChecker;->hasRootApps()Z",
            ],
            "PackageManager;->getInstalledPackages": [
                "Lcom/example/app/RootChecker;->scanPackages()V",
            ],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1

    def test_confirmed_confidence_for_known_libraries(self):
        search_results = {
            "Lcom/scottyab/rootbeer": [
                "Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z",
            ],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.CONFIRMED
        assert "root_detection_libraries" in findings[0].details

    def test_skips_third_party_components(self):
        search_results = {
            "Runtime;->exec": [
                "Landroidx/core/app/SomeHelper;->init()V",
            ],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert findings == []

    def test_multiple_api_hits_increase_confidence(self):
        search_results = {
            "Runtime;->exec": ["Lcom/app/Root;->check1()V"],
            "Build;->TAGS": ["Lcom/app/Root;->check2()V"],
            "File;->exists": ["Lcom/app/Root;->check3()V"],
        }
        rule = _make_rule(APIBasedRootDetectionRule, search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.LIKELY


# ─────────────────────────────────────────────────────────────────────────────
# NativeRootDetectionRule (EXP-046)
# ─────────────────────────────────────────────────────────────────────────────

class TestNativeRootDetection:

    def test_rule_metadata(self):
        rule = _make_rule(NativeRootDetectionRule)
        assert rule.rule_id == "EXP-046"
        assert rule.severity == Severity.LOW
        assert rule.cwe == "CWE-919"

    def test_no_findings_without_callgraph(self):
        parser = _mock_apk_parser(strings=[])
        rule = NativeRootDetectionRule(parser, None, MagicMock())
        findings = rule.check()
        assert findings == []

    def test_no_findings_when_no_native_loads(self):
        rule = _make_rule(NativeRootDetectionRule, strings=[], search_results={})
        findings = rule.check()
        assert findings == []

    def test_detects_native_library_loading(self):
        search_results = {
            "System;->loadLibrary": [
                "Lcom/example/app/Security;->loadNative()V",
            ],
        }
        rule = _make_rule(NativeRootDetectionRule, strings=[], search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].rule_id == "EXP-046"
        assert "native_library_loads" in findings[0].details

    def test_detects_safetynet_attestation(self):
        search_results = {
            "SafetyNet": [
                "Lcom/example/app/Attestation;->verify()V",
            ],
        }
        rule = _make_rule(NativeRootDetectionRule, strings=[], search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.CONFIRMED
        assert "attestation_apis" in findings[0].details

    def test_detects_play_integrity(self):
        search_results = {
            "IntegrityManager": [
                "Lcom/example/app/Integrity;->requestToken()V",
            ],
        }
        rule = _make_rule(NativeRootDetectionRule, strings=[], search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        assert "attestation_apis" in findings[0].details

    def test_security_library_names_in_details(self):
        search_results = {
            "System;->loadLibrary": [
                "Lcom/example/app/JNI;->init()V",
            ],
        }
        strings = ["librootdetect.so", "libintegrity.so", "normal_string"]
        rule = _make_rule(NativeRootDetectionRule, strings=strings,
                         search_results=search_results)
        findings = rule.check()
        assert len(findings) == 1
        details = findings[0].details
        if "security_library_names" in details:
            assert any("detect" in name or "integrity" in name
                      for name in details["security_library_names"])

    def test_skips_third_party_native_loads(self):
        search_results = {
            "System;->loadLibrary": [
                "Lcom/google/firebase/FirebaseApp;->init()V",
            ],
        }
        rule = _make_rule(NativeRootDetectionRule, strings=[], search_results=search_results)
        findings = rule.check()
        assert findings == []
