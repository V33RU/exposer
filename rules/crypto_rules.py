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

    # Strings that contain crypto keyword names but are NOT keys — they are
    # algorithm/mode/padding specs, class names, or log messages.
    _BENIGN_PATTERNS = (
        # JCA algorithm spec strings  (e.g. "AES/CBC/PKCS5Padding")
        "/cbc/", "/ecb/", "/gcm/", "/cfb/", "/ofb/", "/ctr/",
        "pkcs5", "pkcs7", "nopadding", "iso10126",
        # Common class / package path fragments
        "javax.crypto", "java.security", "android.security",
        "secretkeyspec", "secretkeyfactory", "keygenerator",
        "keystore", "keypairgen", "keyagreement",
        "rsaengine", "aesengine", "desengine",
        # Bouncycastle / conscrypt internal names
        "org.bouncycastle", "com.android.org",
        # Log / exception messages that mention key type by name
        "invalidkeyexception", "nosuchalgorithmexception",
        "illegalblocksizeexception", "badpaddingexception",
        # Resource / config keys (very short tokens that match "key" literally)
        "apikey_placeholder", "your_api_key", "insert_key_here",
        "todo", "fixme", "example", "test", "demo", "sample",
    )

    # Only flag strings that look like they could be literal key material:
    # base64 blobs, hex strings, or high-entropy alphanumeric strings.
    _KEY_VALUE_PATTERNS = [
        # Base64 key material (at least 24 chars, only base64 chars, ends with = optional)
        re.compile(r'^[A-Za-z0-9+/]{24,}={0,2}$'),
        # Hex string (at least 32 hex chars = 128-bit key)
        re.compile(r'^[0-9a-fA-F]{32,}$'),
        # High-entropy alphanumeric (letters + digits, no spaces, ≥20 chars)
        re.compile(r'^[A-Za-z0-9_\-]{20,}$'),
    ]

    def check(self) -> List[Finding]:
        """Check for hardcoded keys in strings."""
        findings = []

        # Keywords whose *presence in a string value* suggests a hardcoded secret.
        # We look for strings that both (a) match a key-value pattern AND (b) are
        # assigned to a variable / field whose name contains one of these words.
        # Since we only have the string pool, we use the string value itself as
        # the heuristic — a pure value match.
        key_label_patterns = [
            "secret", "private_key", "api_key", "apikey",
            "api-secret", "privatekey", "access_key", "auth_token",
            "client_secret", "signing_key", "encryption_key",
        ]

        if not (hasattr(self.apk_parser, 'apk') and self.apk_parser.apk):
            return findings

        strings = set()
        try:
            for dex in self.apk_parser.apk.get_all_dex():
                if hasattr(dex, 'get_strings'):
                    strings.update(dex.get_strings())
        except Exception:
            pass

        seen: set = set()
        for string in strings:
            s = str(string).strip()
            s_lower = s.lower()

            # Skip short strings — too short to be a real key
            if len(s) < 16:
                continue

            # Skip known benign patterns immediately
            if any(bp in s_lower for bp in self._BENIGN_PATTERNS):
                continue

            # Skip strings with spaces — keys don't have spaces
            if ' ' in s:
                continue

            # The string itself must look like key material
            if not self._matches_key_value(s):
                continue

            # Optionally: string contains a label keyword (extra signal)
            has_label = any(kw in s_lower for kw in key_label_patterns)
            confidence = Confidence.LIKELY if has_label else Confidence.POSSIBLE

            key = s[:60]
            if key in seen:
                continue
            seen.add(key)

            findings.append(self.create_finding(
                component_name="Application",
                confidence=confidence,
                details={"hardcoded_string": s[:80] + ("..." if len(s) > 80 else "")},
                code_snippet=f'String key = "{s[:80]}{"..." if len(s) > 80 else ""}";',
                remediation="Use Android Keystore or secure key management. Never hardcode cryptographic keys.",
                exploit_commands=[
                    "# Extract all strings from APK",
                    "apktool d app.apk -o app_decoded",
                    "grep -r 'key\\|secret\\|token' app_decoded/smali/",
                ]
            ))

        return findings

    def _matches_key_value(self, s: str) -> bool:
        """Return True if the string looks like key material (base64, hex, or high-entropy)."""
        for pattern in self._KEY_VALUE_PATTERNS:
            if pattern.fullmatch(s):
                # Extra entropy check: require >50% unique characters
                if len(set(s)) > len(s) * 0.4:
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
