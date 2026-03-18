"""Taint engine for tracking data flow from sources to sinks."""

from dataclasses import dataclass
from typing import List, Optional, Set, Dict, Any
import logging

from androguard.core.analysis.analysis import Analysis, MethodAnalysis
from androguard.core.dex import DEX

from core.callgraph import get_method_signature

logger = logging.getLogger(__name__)


@dataclass
class TaintStep:
    """Single step in a taint path."""
    method: str
    instruction: str
    line_number: int = 0


@dataclass
class TaintPath:
    """Complete taint path from source to sink."""
    source: str
    sink: str
    steps: List[TaintStep]
    confidence: str = "POSSIBLE"  # CONFIRMED, LIKELY, POSSIBLE


class TaintEngine:
    """Track taint from sources to sinks."""

    # Common taint sources
    SOURCES = [
        "getIntent()",
        "getStringExtra",
        "getIntExtra",
        "getBundleExtra",
        "getData()",
        "getDataString()",
        "getQueryParameter",
        "getLastPathSegment",
        "onReceive",
        "query(",
    ]

    # Common taint sinks
    SINKS = [
        "loadUrl",
        "loadData",
        "exec(",
        "ProcessBuilder",
        "rawQuery",
        "execSQL",
        "openFile(",
        "openFileOutput",
        "startActivity",
        "startService",
        "sendBroadcast",
        "Log.",
    ]

    def __init__(self, dexes: List[DEX], analysis: Analysis) -> None:
        """Initialize taint engine.

        Args:
            dexes: List of DEX objects.
            analysis: Androguard analysis object.
        """
        self.dexes = dexes
        self.analysis = analysis
        self.taint_paths: List[TaintPath] = []

    def find_sources(self) -> List[MethodAnalysis]:
        """Find all app-defined methods whose signature matches a taint source pattern.

        Returns:
            List of methods containing sources.
        """
        sources = []
        for method in self.analysis.get_methods():
            if method.is_external():
                continue

            method_str = str(method.get_method())
            for source_pattern in self.SOURCES:
                if source_pattern in method_str:
                    sources.append(method)
                    break

        return sources

    def find_sinks(self) -> List[MethodAnalysis]:
        """Find all app-defined methods whose signature matches a taint sink pattern.

        Returns:
            List of methods containing sinks.
        """
        sinks = []
        for method in self.analysis.get_methods():
            if method.is_external():
                continue

            method_str = str(method.get_method())
            for sink_pattern in self.SINKS:
                if sink_pattern in method_str:
                    sinks.append(method)
                    break

        return sinks

    def track_taint(
        self,
        source_methods: List[MethodAnalysis],
        sink_methods: List[MethodAnalysis],
        max_depth: int = 5
    ) -> List[TaintPath]:
        """Track taint from sources to sinks.

        Args:
            source_methods: Methods containing taint sources.
            sink_methods: Methods containing taint sinks.
            max_depth: Maximum propagation depth.

        Returns:
            List of discovered taint paths.
        """
        paths = []
        sink_sigs = {self._get_method_sig(m) for m in sink_methods}

        for source in source_methods:
            visited: Set[str] = set()
            current_path: List[TaintStep] = []

            self._dfs_taint(
                source,
                sink_sigs,
                visited,
                current_path,
                paths,
                max_depth,
                0
            )

        self.taint_paths = paths
        return paths

    def _dfs_taint(
        self,
        current: MethodAnalysis,
        targets: Set[str],
        visited: Set[str],
        path: List[TaintStep],
        found_paths: List[TaintPath],
        max_depth: int,
        depth: int
    ) -> bool:
        """DFS to find taint paths.

        Args:
            current: Current method being analyzed.
            targets: Set of target sink signatures.
            visited: Set of visited method signatures.
            path: Current path being built.
            found_paths: List to store found paths.
            max_depth: Maximum search depth.
            depth: Current depth.

        Returns:
            True if a path was found.
        """
        if depth > max_depth:
            return False

        sig = self._get_method_sig(current)
        if sig in visited:
            return False

        visited.add(sig)

        # Check if current method is a sink
        if sig in targets:
            step = TaintStep(method=sig, instruction="sink", line_number=0)
            full_path = path + [step]
            found_paths.append(TaintPath(
                source=path[0].method if path else sig,
                sink=sig,
                steps=full_path,
                confidence="CONFIRMED"
            ))
            return True

        # Add to path
        step = TaintStep(method=sig, instruction="call", line_number=0)
        path.append(step)

        # Explore callees (forward taint propagation)
        found = False
        for xref in current.get_xref_to():
            target_class, target_method, _ = xref
            if self._dfs_taint(target_method, targets, visited, path, found_paths, max_depth, depth + 1):
                found = True

        path.pop()
        return found

    def _get_method_sig(self, method: MethodAnalysis) -> str:
        return get_method_signature(method)

    def get_paths_to_sink(self, sink_pattern: str) -> List[TaintPath]:
        """Get all taint paths leading to a specific sink.

        Args:
            sink_pattern: Sink method pattern to search for.

        Returns:
            List of matching taint paths.
        """
        return [p for p in self.taint_paths if sink_pattern in p.sink]
