"""Vulnerability detection rules for Android components."""

from .base_rule import BaseRule, Finding, Severity, Confidence
from .activities import (
    ExportedActivityRule, IntentToWebViewRule, NestedIntentForwardingRule,
    TaskHijackingRule, TapjackingVulnerabilityRule, JavaScriptBridgeRule,
    FragmentInjectionRule, InsecureWebResourceResponseRule,
    WebViewFileAccessRule, IntentRedirectionRule,
)
from .services import ExportedServiceRule, ServiceIntentInjectionRule
from .receivers import ExportedReceiverRule, DynamicReceiverRule, ReceiverInjectionRule, UnprotectedSendBroadcastRule, StickyBroadcastRule
from .providers import (
    ExportedProviderRule, ProviderSQLInjectionRule, ProviderPathTraversalRule,
    GrantUriPermissionsRule, TypoPermissionRule, FileProviderBroadPathsRule,
)
from .deeplinks import DeepLinkAutoVerifyRule, DeepLinkOpenRedirectRule, CustomSchemeHijackingRule
from .manifest_rules import (
    InsecureNetworkConfigRule, DebugModeEnabledRule,
    BackupEnabledRule, PendingIntentVulnerabilityRule
)
from .crypto_rules import HardcodedCryptoKeyRule, InsecureRandomRule, BrokenTrustManagerRule, AllowAllHostnameVerifierRule, WebViewSslErrorIgnoredRule
from .storage_rules import InsecureLoggingRule, DynamicCodeLoadingRule, SecureScreenFlagRule
from .root_detection import FileBasedRootDetectionRule, APIBasedRootDetectionRule, NativeRootDetectionRule
from .network_rules import URLEndpointExtractionRule, CertificatePinningDetectionRule, APIKeyLeakageRule, CleartextTrafficPatternRule

__all__ = [
    "BaseRule", "Finding", "Severity", "Confidence",
    # Activity rules
    "ExportedActivityRule", "IntentToWebViewRule", "NestedIntentForwardingRule",
    "TaskHijackingRule", "TapjackingVulnerabilityRule", "JavaScriptBridgeRule",
    "FragmentInjectionRule", "InsecureWebResourceResponseRule",
    "WebViewFileAccessRule", "IntentRedirectionRule",
    # Service rules
    "ExportedServiceRule", "ServiceIntentInjectionRule",
    # Receiver rules
    "ExportedReceiverRule", "DynamicReceiverRule", "ReceiverInjectionRule",
    "UnprotectedSendBroadcastRule", "StickyBroadcastRule",
    # Provider rules
    "ExportedProviderRule", "ProviderSQLInjectionRule", "ProviderPathTraversalRule",
    "GrantUriPermissionsRule", "TypoPermissionRule", "FileProviderBroadPathsRule",
    # Deep link rules
    "DeepLinkAutoVerifyRule", "DeepLinkOpenRedirectRule", "CustomSchemeHijackingRule",
    # Manifest/config rules
    "InsecureNetworkConfigRule", "DebugModeEnabledRule",
    "BackupEnabledRule", "PendingIntentVulnerabilityRule",
    # Crypto/code quality rules
    "HardcodedCryptoKeyRule", "InsecureRandomRule",
    "BrokenTrustManagerRule", "AllowAllHostnameVerifierRule", "WebViewSslErrorIgnoredRule",
    # Storage rules
    "InsecureLoggingRule", "DynamicCodeLoadingRule", "SecureScreenFlagRule",
    # Root detection rules
    "FileBasedRootDetectionRule", "APIBasedRootDetectionRule", "NativeRootDetectionRule",
    # Network rules
    "URLEndpointExtractionRule", "CertificatePinningDetectionRule",
    "APIKeyLeakageRule", "CleartextTrafficPatternRule",
]
