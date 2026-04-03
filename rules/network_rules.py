"""Rules for detecting network security weaknesses: URL/endpoint extraction,
certificate pinning detection, API key leakage, and cleartext traffic patterns."""

import re
from typing import Dict, List, Set, Tuple

from .base_rule import BaseRule, Finding, Severity, Confidence, dalvik_to_java


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

class _NetworkBase(BaseRule):
    """Common infrastructure for network-security rules."""

    component_type = "network"

    def _collect_string_pool(self) -> Set[str]:
        """Return deduplicated DEX string pool."""
        strings: Set[str] = set()
        if not (hasattr(self.apk_parser, "apk") and self.apk_parser.apk):
            return strings
        try:
            for dex in self.apk_parser.apk.get_all_dex():
                if hasattr(dex, "get_strings"):
                    strings.update(str(s).strip() for s in dex.get_strings())
        except Exception:
            pass
        return strings


# ─────────────────────────────────────────────────────────────────────────────
# EXP-047  URL / Endpoint Extraction
# ─────────────────────────────────────────────────────────────────────────────

class URLEndpointExtractionRule(_NetworkBase):
    """Extract and catalogue all URLs and API endpoints embedded in the APK."""

    rule_id = "EXP-047"
    title = "Embedded URLs / API Endpoints"
    severity = Severity.INFO
    cwe = "CWE-200"
    description = (
        "The application embeds URLs and API endpoints in the DEX string pool. "
        "Exposed endpoints can reveal backend infrastructure, internal APIs, "
        "staging/debug environments, and potential attack surface."
    )
    remediation = (
        "Avoid hardcoding production API endpoints in client code. Use build-time "
        "configuration injection and certificate pinning to protect communications. "
        "Remove debug/staging URLs from release builds."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/200.html",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/",
    )

    # Regex for http(s) URLs - requires host with at least one dot
    _URL_RE = re.compile(
        r"https?://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+"
        r"(?::\d{1,5})?"
        r"(?:/[^\s\"'<>\\]*)?",
    )

    # Domains to skip - common SDK / system endpoints
    _SKIP_DOMAINS: Tuple[str, ...] = (
        "schemas.android.com",
        "www.w3.org",
        "ns.adobe.com",
        "xmlpull.org",
        "xml.org",
        "www.apache.org",
        "developer.android.com",
        "play.google.com/store",
        "www.google.com/admob",
        "github.com",
        "raw.githubusercontent.com",
        "maven.google.com",
        "dl.google.com",
        "jcenter.bintray.com",
        "repo1.maven.org",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        strings = self._collect_string_pool()
        if not strings:
            return findings

        urls: Dict[str, Set[str]] = {
            "http_cleartext": set(),
            "https_secure": set(),
            "api_endpoints": set(),
            "staging_debug": set(),
        }

        for s in strings:
            match = self._URL_RE.search(s)
            if not match:
                continue
            url = match.group(0).rstrip("/.,;:)")
            if len(url) < 12 or len(url) > 500:
                continue
            if any(skip in url for skip in self._SKIP_DOMAINS):
                continue

            url_lower = url.lower()

            # Categorise
            if any(kw in url_lower for kw in (
                "staging", "debug", "dev.", "test.", "localhost",
                "127.0.0.1", "10.0.", "192.168.", "internal",
            )):
                urls["staging_debug"].add(url)
            elif any(kw in url_lower for kw in (
                "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
                "/rest/", "/rpc/", "/json", "/xml",
            )):
                urls["api_endpoints"].add(url)
            elif url_lower.startswith("http://"):
                urls["http_cleartext"].add(url)
            else:
                urls["https_secure"].add(url)

        total = sum(len(v) for v in urls.values())
        if total == 0:
            return findings

        details: Dict[str, list] = {}
        snippet_parts: List[str] = []

        if urls["staging_debug"]:
            details["staging_debug_urls"] = sorted(urls["staging_debug"])[:15]
            snippet_parts.append(
                "// Staging / debug endpoints found:\n"
                + "\n".join(f'// {u}' for u in sorted(urls["staging_debug"])[:5])
            )
        if urls["http_cleartext"]:
            details["cleartext_urls"] = sorted(urls["http_cleartext"])[:15]
            snippet_parts.append(
                "// Cleartext HTTP URLs:\n"
                + "\n".join(f'// {u}' for u in sorted(urls["http_cleartext"])[:5])
            )
        if urls["api_endpoints"]:
            details["api_endpoints"] = sorted(urls["api_endpoints"])[:20]
            snippet_parts.append(
                "// API endpoints:\n"
                + "\n".join(f'// {u}' for u in sorted(urls["api_endpoints"])[:5])
            )
        if urls["https_secure"]:
            details["https_urls"] = sorted(urls["https_secure"])[:20]

        details["total_unique_urls"] = total

        confidence = Confidence.CONFIRMED if urls["staging_debug"] else (
            Confidence.LIKELY if urls["http_cleartext"] else Confidence.POSSIBLE
        )
        severity_override = None
        if urls["staging_debug"]:
            severity_override = Severity.MEDIUM

        finding = self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts) if snippet_parts else "",
            details=details,
            exploit_commands=[
                "# Enumerate all URLs from the APK:",
                "apktool d app.apk -o app_decoded",
                "grep -rhoP 'https?://[^\"\\s<>]+' app_decoded/ | sort -u",
                "# Probe discovered endpoints:",
                "# httpx -l urls.txt -status-code -title",
            ],
            exploit_scenario=(
                "Extracted endpoints reveal backend API structure. Staging/debug "
                "URLs may lack authentication. Cleartext URLs are interceptable."
            ),
            api_level_affected="All",
        )
        if severity_override:
            finding.severity = severity_override
        findings.append(finding)

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# EXP-048  Certificate Pinning Detection
# ─────────────────────────────────────────────────────────────────────────────

class CertificatePinningDetectionRule(_NetworkBase):
    """Detect certificate pinning implementations and suggest bypass techniques."""

    rule_id = "EXP-048"
    title = "Certificate Pinning Detected"
    severity = Severity.INFO
    cwe = "CWE-295"
    description = (
        "The application implements certificate pinning, which prevents MITM "
        "interception even when a custom CA is installed on the device. This "
        "is a strong defensive measure but can be bypassed with Frida for "
        "authorized security testing."
    )
    remediation = (
        "Certificate pinning is a best practice. Ensure pins are rotated before "
        "expiry, include backup pins, and use Network Security Config for pinning "
        "on API 24+. Never pin to leaf certificates alone."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://developer.android.com/training/articles/security-config#CertificatePinning",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/",
    )

    # Call-graph patterns for pinning libraries
    _PINNING_PATTERNS: Tuple[str, ...] = (
        # OkHttp CertificatePinner
        "CertificatePinner",
        "CertificatePinner$Builder",
        "certificatePinner",
        # Retrofit / OkHttp pin SHA
        "sha256/",
        "sha1/",
        # TrustKit
        "TrustKit",
        # Network Security Config (parsed separately)
        "network_security_config",
        # Custom X509TrustManager (may implement pinning)
        "checkServerTrusted",
        # Apache / legacy
        "AbstractVerifier",
        "SSLPeerUnverifiedException",
    )

    # String pool indicators
    _PIN_STRING_MARKERS: Tuple[str, ...] = (
        "sha256/",
        "sha1/",
        "pin-sha256",
        "pin-sha1",
        "certificate_pinner",
        "certificatepinner",
        "trustkit",
        "network_security_config",
        "pin-set",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        detected_mechanisms: Dict[str, List[str]] = {}
        strings = self._collect_string_pool()

        # 1. Check string pool for pinning indicators
        pin_hashes: List[str] = []
        pin_markers: List[str] = []
        for s in strings:
            s_lower = s.lower()
            if s.startswith("sha256/") or s.startswith("sha1/"):
                pin_hashes.append(s)
            elif any(marker in s_lower for marker in self._PIN_STRING_MARKERS):
                if len(s) < 200:
                    pin_markers.append(s)

        if pin_hashes:
            detected_mechanisms["certificate_pins"] = sorted(set(pin_hashes))[:10]
        if pin_markers:
            detected_mechanisms["pinning_indicators"] = sorted(set(pin_markers))[:10]

        # 2. Check call graph for pinning APIs
        if self.callgraph:
            api_hits: List[str] = []
            for pattern in ("CertificatePinner", "TrustKit", "checkServerTrusted"):
                for sig in self.callgraph.search_methods(pattern):
                    cls = dalvik_to_java(sig)
                    if not self._is_third_party_component(cls):
                        api_hits.append(sig)
            if api_hits:
                detected_mechanisms["pinning_api_calls"] = sorted(set(api_hits))[:10]

        # 3. Check for Network Security Config with pin-set
        nsc_pinning = self._check_network_security_config()
        if nsc_pinning:
            detected_mechanisms["network_security_config_pins"] = nsc_pinning

        if not detected_mechanisms:
            return findings

        snippet_parts: List[str] = []
        if "certificate_pins" in detected_mechanisms:
            snippet_parts.append(
                "// Certificate pin hashes found:\n"
                + "\n".join(f'// {h}' for h in detected_mechanisms["certificate_pins"][:5])
            )
        if "pinning_api_calls" in detected_mechanisms:
            snippet_parts.append(
                "// Pinning API calls:\n"
                + "\n".join(
                    f'// {dalvik_to_java(sig)}' for sig in detected_mechanisms["pinning_api_calls"][:5]
                )
            )

        has_pins = bool(detected_mechanisms.get("certificate_pins"))
        has_nsc = bool(detected_mechanisms.get("network_security_config_pins"))
        confidence = (
            Confidence.CONFIRMED if has_pins or has_nsc
            else Confidence.LIKELY if detected_mechanisms.get("pinning_api_calls")
            else Confidence.POSSIBLE
        )

        pkg = self.apk_parser.get_package_name()
        findings.append(self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=detected_mechanisms,
            exploit_commands=[
                "# Bypass certificate pinning with objection:",
                f"objection -g {pkg} explore --startup-command 'android sslpinning disable'",
                "# Or use Frida universal SSL pinning bypass:",
                f"frida -U -f {pkg} -l EXP-048_Application.js --no-pause",
                "# For OkHttp specifically:",
                f"frida -U -n {pkg} -e \"Java.perform(function(){{var p=Java.use('okhttp3.CertificatePinner');p.check.overload('java.lang.String','java.util.List').implementation=function(h,c){{console.log('Bypassed pin for: '+h);}};}})\"",
            ],
            exploit_scenario=(
                "The app implements certificate pinning which blocks MITM proxies. "
                "For authorized testing, use the Frida bypass script to disable "
                "all pinning mechanisms (OkHttp, TrustKit, Network Security Config)."
            ),
            api_level_affected="All",
        ))

        return findings

    def _check_network_security_config(self) -> List[str]:
        """Check if Network Security Config contains pin-set directives."""
        if not (hasattr(self.apk_parser, "apk") and self.apk_parser.apk):
            return []
        try:
            data = self.apk_parser.apk.get_file("res/xml/network_security_config.xml")
            if data:
                text = data.decode("utf-8", errors="ignore")
                if "pin-set" in text or "pin" in text.lower():
                    return ["res/xml/network_security_config.xml contains pin-set"]
        except Exception:
            pass
        return []


# ─────────────────────────────────────────────────────────────────────────────
# EXP-049  API Key Leakage Detection
# ─────────────────────────────────────────────────────────────────────────────

class APIKeyLeakageRule(_NetworkBase):
    """Detect leaked API keys for Google Maps, AWS, Firebase, and other services."""

    rule_id = "EXP-049"
    title = "API Key Leakage"
    severity = Severity.HIGH
    cwe = "CWE-798"
    description = (
        "The application contains hardcoded API keys for cloud services. Leaked "
        "keys can be used to abuse quotas, access backend resources, or escalate "
        "privileges depending on the key's permissions."
    )
    remediation = (
        "Restrict API keys by package name, SHA-1 fingerprint, and IP. Use "
        "Android Keystore or runtime-fetched tokens instead of embedding keys. "
        "Rotate any key found in a public APK immediately."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/",
    )

    # Each entry: (display_name, regex_pattern, severity_boost)
    _KEY_PATTERNS: Tuple[Tuple[str, re.Pattern, bool], ...] = (
        ("Google Maps API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), False),
        ("Google Cloud API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), False),
        ("Firebase API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), False),
        ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), True),
        ("AWS Secret Key", re.compile(r"(?:aws.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), True),
        ("Google OAuth Client ID", re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"), False),
        ("Firebase URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), False),
        ("Firebase Storage", re.compile(r"[a-z0-9-]+\.appspot\.com"), False),
        ("Slack Token", re.compile(r"xox[bpors]-[0-9]{10,13}-[0-9a-zA-Z]{10,48}"), True),
        ("Slack Webhook", re.compile(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"), True),
        ("Twitter Bearer Token", re.compile(r"AAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+"), True),
        ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), True),
        ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), False),
        ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), True),
        ("Twilio Account SID", re.compile(r"AC[a-f0-9]{32}"), False),
        ("SendGrid API Key", re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"), True),
        ("Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), False),
        ("Square Access Token", re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), True),
        ("Square OAuth Secret", re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"), True),
    )

    # Strings that are clearly not real keys (SDK constants, class names, etc.)
    _FALSE_POSITIVE_MARKERS: Tuple[str, ...] = (
        "com.google.android",
        "example",
        "placeholder",
        "your_api_key",
        "INSERT_KEY",
        "API_KEY_HERE",
        "TODO",
        "FIXME",
        "test",
        "debug",
        "mock",
        "dummy",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        strings = self._collect_string_pool()
        if not strings:
            return findings

        leaked_keys: Dict[str, List[str]] = {}
        is_critical = False

        for s in strings:
            if len(s) < 10 or len(s) > 500:
                continue
            s_lower = s.lower()
            if any(fp in s_lower for fp in self._FALSE_POSITIVE_MARKERS):
                continue

            for key_name, pattern, critical in self._KEY_PATTERNS:
                match = pattern.search(s)
                if match:
                    key_val = match.group(0)
                    # Mask the middle portion for safety
                    if len(key_val) > 12:
                        masked = key_val[:8] + "..." + key_val[-4:]
                    else:
                        masked = key_val[:4] + "..."
                    leaked_keys.setdefault(key_name, []).append(masked)
                    if critical:
                        is_critical = True
                    break  # one match per string

        if not leaked_keys:
            return findings

        details: Dict[str, object] = {}
        snippet_parts: List[str] = []
        total_keys = 0

        for key_name, values in leaked_keys.items():
            unique = sorted(set(values))[:5]
            details[key_name.lower().replace(" ", "_")] = unique
            total_keys += len(unique)
            snippet_parts.append(
                f"// {key_name} found:\n"
                + "\n".join(f'// {v}' for v in unique[:3])
            )

        details["total_leaked_keys"] = total_keys

        confidence = Confidence.CONFIRMED if total_keys >= 2 else Confidence.LIKELY

        finding = self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=details,
            exploit_commands=[
                "# Extract all potential API keys:",
                "apktool d app.apk -o decoded && grep -rP 'AIza|AKIA|sk_live|pk_live|xox[bpors]' decoded/",
                "# Validate Google API key:",
                "# curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=<KEY>'",
                "# Check AWS key permissions:",
                "# aws sts get-caller-identity --access-key-id <KEY>",
            ],
            exploit_scenario=(
                "Hardcoded API keys were extracted from the APK. An attacker can use "
                "these keys to access backend services, abuse quotas, or escalate "
                "privileges depending on the key's scope and restrictions."
            ),
            api_level_affected="All",
        )
        if is_critical:
            finding.severity = Severity.CRITICAL
        findings.append(finding)

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# EXP-050  Cleartext Traffic Pattern Detection
# ─────────────────────────────────────────────────────────────────────────────

class CleartextTrafficPatternRule(_NetworkBase):
    """Detect cleartext traffic patterns beyond manifest usesCleartextTraffic flag."""

    rule_id = "EXP-050"
    title = "Cleartext Traffic Patterns"
    severity = Severity.MEDIUM
    cwe = "CWE-319"
    description = (
        "The application uses cleartext HTTP communication, unencrypted sockets, "
        "or insecure protocol patterns beyond what the manifest flag indicates. "
        "Data sent over cleartext channels is readable by any network observer."
    )
    remediation = (
        "Migrate all network communication to HTTPS/TLS. Use Network Security "
        "Config to enforce cleartext restrictions. Replace raw Socket usage with "
        "SSLSocket where encryption is needed."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://developer.android.com/training/articles/security-config",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/",
    )

    # Call-graph patterns indicating cleartext communication
    _CLEARTEXT_API_PATTERNS: Tuple[str, ...] = (
        "HttpURLConnection",
        "DefaultHttpClient",
        "AndroidHttpClient",
        "Socket;-><init>",
        "Socket;->connect",
        "DatagramSocket",
        "ServerSocket;-><init>",
        "URLConnection;->connect",
    )

    # String pool markers for cleartext
    _CLEARTEXT_MARKERS: Tuple[str, ...] = (
        "http://",
    )

    def check(self) -> List[Finding]:
        findings: List[Finding] = []

        detected: Dict[str, List[str]] = {}
        snippet_parts: List[str] = []

        # 1. Call-graph analysis for cleartext APIs
        if self.callgraph:
            for pattern in self._CLEARTEXT_API_PATTERNS:
                for sig in self.callgraph.search_methods(pattern):
                    cls = dalvik_to_java(sig)
                    if self._is_third_party_component(cls):
                        continue
                    category = "raw_socket_usage" if "Socket" in pattern else "http_api_usage"
                    detected.setdefault(category, []).append(sig)

        # 2. Count cleartext HTTP URLs in string pool
        strings = self._collect_string_pool()
        http_urls: Set[str] = set()
        for s in strings:
            if s.startswith("http://") and "." in s and len(s) < 500:
                # Skip XML namespace / schema URLs
                if any(skip in s for skip in (
                    "schemas.android.com", "www.w3.org", "xmlpull.org",
                    "xml.org", "apache.org",
                )):
                    continue
                http_urls.add(s[:120])

        if http_urls:
            detected["cleartext_http_urls"] = sorted(http_urls)[:15]

        if not detected:
            return findings

        # Build details
        details: Dict[str, object] = {}
        if "http_api_usage" in detected:
            sigs = sorted(set(detected["http_api_usage"]))[:10]
            details["http_api_usage"] = sigs
            snippet_parts.append(
                "// Cleartext HTTP API usage:\n"
                + "\n".join(f'// {dalvik_to_java(s)}' for s in sigs[:5])
            )
        if "raw_socket_usage" in detected:
            sigs = sorted(set(detected["raw_socket_usage"]))[:10]
            details["raw_socket_usage"] = sigs
            snippet_parts.append(
                "// Raw socket usage (unencrypted):\n"
                + "\n".join(f'// {dalvik_to_java(s)}' for s in sigs[:5])
            )
        if "cleartext_http_urls" in detected:
            details["cleartext_http_urls"] = detected["cleartext_http_urls"]
            snippet_parts.append(
                "// Cleartext HTTP URLs:\n"
                + "\n".join(f'// {u}' for u in detected["cleartext_http_urls"][:5])
            )

        has_sockets = bool(detected.get("raw_socket_usage"))
        has_http = bool(detected.get("http_api_usage"))
        confidence = (
            Confidence.CONFIRMED if has_sockets and has_http
            else Confidence.LIKELY if has_sockets or has_http
            else Confidence.POSSIBLE
        )

        pkg = self.apk_parser.get_package_name()
        findings.append(self.create_finding(
            component_name="Application",
            confidence=confidence,
            code_snippet="\n\n".join(snippet_parts),
            details=details,
            exploit_commands=[
                "# Intercept cleartext traffic with mitmproxy:",
                "mitmproxy --mode transparent --showhost",
                "# Or capture with tcpdump on device:",
                f"adb shell tcpdump -i any -w /sdcard/capture.pcap",
                "# Pull and analyze:",
                "adb pull /sdcard/capture.pcap && wireshark capture.pcap",
            ],
            exploit_scenario=(
                "The app sends data over cleartext HTTP or unencrypted sockets. "
                "An attacker on the same network can passively sniff or actively "
                "modify this traffic using ARP spoofing or a rogue access point."
            ),
            api_level_affected="All",
        ))

        return findings
