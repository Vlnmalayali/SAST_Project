"""Basic taint analysis engine for tracking data flow from sources to sinks."""

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Taint sources — functions/attributes that introduce untrusted data
TAINT_SOURCES = {
    "request.args",
    "request.form",
    "request.data",
    "request.json",
    "request.GET",
    "request.POST",
    "request.values",
    "request.files",
    "request.query_string",
    "request.cookies",
    "request.headers",
    "input",
    "sys.stdin.read",
    "sys.stdin.readline",
}

# Taint sinks — functions where tainted data is dangerous
TAINT_SINKS = {
    "cursor.execute": "sql_injection",
    "db.execute": "sql_injection",
    "os.system": "command_injection",
    "os.popen": "command_injection",
    "subprocess.call": "command_injection",
    "subprocess.run": "command_injection",
    "subprocess.Popen": "command_injection",
    "eval": "unsafe_eval",
    "exec": "unsafe_eval",
    "open": "path_traversal",
    "pickle.loads": "insecure_deserialization",
}

# Sanitizers — functions that clean tainted data
SANITIZERS = {
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "shlex.quote",
    "int",
    "float",
    "bool",
    "ast.literal_eval",
    "urllib.parse.quote",
}


@dataclass
class TaintedVariable:
    name: str
    source_line: int
    source_type: str
    tainted: bool = True


@dataclass
class TaintFlowRecord:
    source_file: str
    source_line: int
    source_type: str
    sink_file: str
    sink_line: int
    sink_type: str
    variable_name: str
    flow_path: list[dict] = field(default_factory=list)


class TaintAnalyzer:
    """Performs basic intra-procedural taint analysis."""

    def analyze(
        self, tree: ast.AST, file_path: str, source_lines: list[str]
    ) -> list[TaintFlowRecord]:
        """Run taint analysis on an AST."""
        flows = []
        taint_state: dict[str, TaintedVariable] = {}

        for node in ast.walk(tree):
            # Detect taint sources in assignments
            if isinstance(node, ast.Assign):
                self._process_assignment(node, taint_state, file_path)

            # Detect taint sources in function args
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    if arg.arg in ("request", "req"):
                        # Flask/Django request object — mark as source
                        taint_state[arg.arg] = TaintedVariable(
                            name=arg.arg, source_line=node.lineno, source_type="request_object"
                        )

            # Check sinks for tainted data
            if isinstance(node, ast.Call):
                flow = self._check_sink(node, taint_state, file_path)
                if flow:
                    flows.append(flow)

        return flows

    def _process_assignment(self, node: ast.Assign, taint_state: dict, file_path: str):
        """Track taint through assignments."""
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id

            # Check if RHS is a taint source
            if self._is_taint_source(node.value):
                taint_state[var_name] = TaintedVariable(
                    name=var_name,
                    source_line=node.lineno,
                    source_type="user_input",
                )
            # Check if RHS references tainted variables (propagation)
            elif self._references_tainted(node.value, taint_state):
                # Check for sanitizer
                if self._is_sanitized(node.value):
                    taint_state.pop(var_name, None)
                else:
                    parent = self._find_tainted_parent(node.value, taint_state)
                    if parent:
                        taint_state[var_name] = TaintedVariable(
                            name=var_name,
                            source_line=node.lineno,
                            source_type=f"derived_from_{parent.name}",
                        )

    def _is_taint_source(self, node) -> bool:
        """Check if a node is a known taint source."""
        source_str = self._node_to_dotted_name(node)
        if source_str:
            for src in TAINT_SOURCES:
                if source_str.startswith(src) or source_str == src:
                    return True
        # input() call
        if isinstance(node, ast.Call):
            name = self._node_to_dotted_name(node.func)
            if name in TAINT_SOURCES:
                return True
        return False

    def _references_tainted(self, node, taint_state: dict) -> bool:
        """Check if an expression references any tainted variable."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in taint_state:
                return True
        return False

    def _find_tainted_parent(self, node, taint_state: dict) -> TaintedVariable | None:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in taint_state:
                return taint_state[child.id]
        return None

    def _is_sanitized(self, node) -> bool:
        """Check if the node applies a sanitizer."""
        if isinstance(node, ast.Call):
            name = self._node_to_dotted_name(node.func)
            if name in SANITIZERS:
                return True
        return False

    def _check_sink(
        self, node: ast.Call, taint_state: dict, file_path: str
    ) -> TaintFlowRecord | None:
        """Check if tainted data flows into a sink."""
        func_name = self._node_to_dotted_name(node.func)
        if not func_name:
            return None

        # Check if function is a sink
        sink_type = None
        for sink_pattern, vuln_type in TAINT_SINKS.items():
            if func_name.endswith(sink_pattern.split(".")[-1]) or func_name == sink_pattern:
                sink_type = vuln_type
                break

        if not sink_type:
            return None

        # Check if any argument is tainted
        for arg in node.args:
            if self._references_tainted(arg, taint_state):
                tainted_var = self._find_tainted_parent(arg, taint_state)
                if tainted_var:
                    return TaintFlowRecord(
                        source_file=file_path,
                        source_line=tainted_var.source_line,
                        source_type=tainted_var.source_type,
                        sink_file=file_path,
                        sink_line=node.lineno,
                        sink_type=sink_type,
                        variable_name=tainted_var.name,
                        flow_path=[
                            {
                                "file": file_path,
                                "line": tainted_var.source_line,
                                "variable": tainted_var.name,
                                "operation": "source",
                            },
                            {
                                "file": file_path,
                                "line": node.lineno,
                                "variable": func_name,
                                "operation": "sink",
                            },
                        ],
                    )
        return None

    def _node_to_dotted_name(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._node_to_dotted_name(node.value)
            if val:
                return f"{val}.{node.attr}"
            return node.attr
        return None
