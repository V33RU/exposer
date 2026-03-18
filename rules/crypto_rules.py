"""Rules for detecting cryptographic and code-quality vulnerabilities."""

import re
from typing import List

from .base_rule import BaseRule, Finding, Severity, Confidence


class HardcodedCryptoKeyRule(BaseRule):
    """Detect hardcoded cryptographic keys in code."""

    rule_id = "EXP-016"
    title = "Hardcoded Cryptographic Key"
    severity = Severity.CRITICAL
    cwe = "CWE-798"
    description = "Cryptographic keys are hardcoded in the application, allowing extraction and misuse."

    def check(self) -> List[Finding]:
        """Check for hardcoded keys in strings."""
        findings = []

        key_patterns = [
            "AES", "DES", "RSA", "HMAC", "secret", "private_key",
            "api_key", "apikey", "api-secret", "privatekey"
        ]

        if hasattr(self.apk_parser, 'apk') and self.apk_parser.apk:
            strings = set()
            try:
                for dex in self.apk_parser.apk.get_all_dex():
                    if hasattr(dex, 'get_strings'):
                        strings.update(dex.get_strings())
            except Exception:
                pass

            for string in strings:
                string_lower = str(string).lower()
                for pattern in key_patterns:
                    if pattern.lower() in string_lower:
                        if len(string) >= 16 and self._is_likely_key(string):
                            findings.append(self.create_finding(
                                component_name="Application",
                                confidence=Confidence.LIKELY,
                                details={"hardcoded_string": string[:50] + "..." if len(string) > 50 else string},
                                code_snippet=f"String: {string[:100]}",
                                remediation="Use Android Keystore or secure key management. Never hardcode cryptographic keys.",
                                exploit_commands=["# Extract from APK strings", "strings base.apk | grep -i 'key'"]
                            ))
                            break

        return findings

    def _is_likely_key(self, string: str) -> bool:
        """Check if string has characteristics of a cryptographic key."""
        if re.search(r'[A-Za-z]', string) and re.search(r'[0-9]', string):
            unique_chars = len(set(string))
            if unique_chars > len(string) * 0.5:
                return True
        return False


class InsecureRandomRule(BaseRule):
    """Detect use of insecure random number generators."""

    rule_id = "EXP-024"
    title = "Insecure Random Number Generator"
    severity = Severity.MEDIUM
    cwe = "CWE-338"
    description = "App uses java.util.Random instead of SecureRandom for security operations."

    def check(self) -> List[Finding]:
        """Check for insecure random usage."""
        findings = []

        if not self.callgraph:
            return findings

        random_methods = self.callgraph.search_methods("java.util.Random")
        math_random = self.callgraph.search_methods("Math.random")

        for method in random_methods + math_random:
            findings.append(self.create_finding(
                component_name=method.split("->")[0] if "->" in method else "Application",
                confidence=Confidence.LIKELY,
                details={
                    "issue": "Insecure random generator used",
                    "method": method
                },
                code_snippet="Random random = new Random();  // Use SecureRandom instead",
                remediation="Replace java.util.Random with java.security.SecureRandom.",
                exploit_commands=[]
            ))

        return findings
