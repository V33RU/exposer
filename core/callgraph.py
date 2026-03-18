"""Callgraph analysis using androguard for method invocation tracking."""

from typing import List, Dict, Set, Optional, Any
import logging

from androguard.core.analysis.analysis import Analysis, MethodAnalysis
from androguard.core.dex import DEX

logger = logging.getLogger(__name__)


def get_method_signature(method: MethodAnalysis) -> str:
    """Return a canonical string signature for a MethodAnalysis object."""
    full_name = method.full_name
    if full_name:
        return str(full_name)
    return f"{method.class_name}->{method.name}{method.descriptor}"


class CallGraph:
    """Build and query callgraph for taint analysis."""

    def __init__(self, dexes: List[DEX], analysis: Analysis) -> None:
        """Initialize callgraph with DEX and analysis objects.

        Args:
            dexes: List of DEX objects.
            analysis: Androguard analysis object.
        """
        self.dexes = dexes
        self.analysis = analysis
        self.call_graph: Dict[str, Set[str]] = {}
        self._build_graph()

    def _build_graph(self) -> None:
        """Build the callgraph from method analysis."""
        logger.info("Building callgraph...")

        for method in self.analysis.get_methods():
            method_name = self._get_method_signature(method)
            self.call_graph[method_name] = set()

            # Get call targets from xref_to
            for xref in method.get_xref_to():
                target_class, target_method, _ = xref
                target_sig = self._get_external_method_signature(target_class, target_method)
                self.call_graph[method_name].add(target_sig)

        logger.info(f"Callgraph built: {len(self.call_graph)} methods")

    def _get_method_signature(self, method: MethodAnalysis) -> str:
        return get_method_signature(method)

    def _get_external_method_signature(self, class_obj: Any, method: Any) -> str:
        """Get signature for external method reference.

        Args:
            class_obj: Class object.
            method: Method object.

        Returns:
            Method signature string.
        """
        class_name = class_obj.name if hasattr(class_obj, 'name') else str(class_obj)
        method_name = method.name if hasattr(method, 'name') else str(method)
        descriptor = method.descriptor if hasattr(method, 'descriptor') else "()V"
        return f"{class_name}->{method_name}{descriptor}"

    def get_callers(self, method_sig: str) -> List[str]:
        """Get all methods that call the given method.

        Args:
            method_sig: Target method signature.

        Returns:
            List of caller method signatures.
        """
        callers = []
        for caller, callees in self.call_graph.items():
            if method_sig in callees:
                callers.append(caller)
        return callers

    def get_callees(self, method_sig: str) -> Set[str]:
        """Get all methods called by the given method.

        Args:
            method_sig: Source method signature.

        Returns:
            Set of callee method signatures.
        """
        return self.call_graph.get(method_sig, set())

    def find_path(self, source: str, sink: str, max_depth: int = 10) -> Optional[List[str]]:
        """Find call path from source to sink.

        Args:
            source: Source method signature.
            sink: Sink method signature.
            max_depth: Maximum search depth.

        Returns:
            List of method signatures forming the path, or None if not found.
        """
        visited: Set[str] = set()
        path: List[str] = []

        def dfs(current: str, depth: int) -> bool:
            if depth > max_depth:
                return False
            if current == sink:
                path.append(current)
                return True
            if current in visited:
                return False

            visited.add(current)
            path.append(current)

            for callee in self.get_callees(current):
                if dfs(callee, depth + 1):
                    return True

            path.pop()
            return False

        if dfs(source, 0):
            return path
        return None

    def search_methods(self, pattern: str) -> List[str]:
        """Search for methods matching a pattern.

        Args:
            pattern: Substring to search for in method signatures.

        Returns:
            List of matching method signatures.
        """
        return [
            sig for sig in self.call_graph.keys()
            if pattern in sig or any(pattern in callee for callee in self.call_graph[sig])
        ]
