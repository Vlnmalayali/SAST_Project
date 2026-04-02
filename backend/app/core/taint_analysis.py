"""Interprocedural taint analysis engine for source-to-sink flow tracking."""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum

from app.core.taint_rules import load_taint_rules, normalize_taint_language

logger = logging.getLogger(__name__)

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class TaintState(str, Enum):
    UNTAINTED = "untainted"
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    UNKNOWN = "unknown"


@dataclass
class TaintOrigin:
    source_file: str
    source_line: int
    source_type: str
    variable_name: str
    flow_path: list[dict]
    parameter_index: int | None = None


@dataclass
class TaintValue:
    state: TaintState
    origins: list[TaintOrigin] = field(default_factory=list)

    @classmethod
    def untainted(cls) -> "TaintValue":
        return cls(state=TaintState.UNTAINTED, origins=[])

    @classmethod
    def tainted(cls, origins: list[TaintOrigin]) -> "TaintValue":
        return cls(state=TaintState.TAINTED, origins=origins)

    @classmethod
    def sanitized(cls) -> "TaintValue":
        return cls(state=TaintState.SANITIZED, origins=[])

    @classmethod
    def unknown(cls) -> "TaintValue":
        return cls(state=TaintState.UNKNOWN, origins=[])


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


@dataclass
class SinkHitTemplate:
    sink_line: int
    sink_type: str
    sink_name: str
    parameter_indexes: set[int] = field(default_factory=set)
    local_origins: list[TaintOrigin] = field(default_factory=list)


@dataclass
class FunctionSummary:
    name: str
    return_parameter_indexes: set[int] = field(default_factory=set)
    return_local_origins: list[TaintOrigin] = field(default_factory=list)
    returns_sanitized: bool = False
    sink_templates: list[SinkHitTemplate] = field(default_factory=list)


@dataclass
class _SinkHit:
    sink_line: int
    sink_type: str
    sink_name: str
    origins: list[TaintOrigin]


@dataclass
class _AnalysisContext:
    file_path: str
    current_function: str | None = None
    sink_hits: list[_SinkHit] = field(default_factory=list)
    return_values: list[TaintValue] = field(default_factory=list)


class TaintAnalyzer:
    """
    Performs interprocedural taint analysis.

    - Tracks taint state (`untainted`, `tainted`, `sanitized`, `unknown`)
    - Builds function summaries for sink dependencies and return taint
    - Propagates taint across assignments, returns, and function calls
    """

    def __init__(self, language: str = "python") -> None:
        self.language = normalize_taint_language(language)
        rules = load_taint_rules(self.language)
        self.taint_sources = set(rules.sources)
        self.taint_sinks = dict(rules.sinks)
        self.sanitizers = set(rules.sanitizers)

    def analyze(
        self, tree: ast.AST, file_path: str, source_lines: list[str]
    ) -> list[TaintFlowRecord]:
        """Run taint analysis on an AST and return source->sink traces."""
        function_defs = self._collect_functions(tree)
        summaries = self._build_function_summaries(function_defs, file_path)

        module_env: dict[str, TaintValue] = {}
        module_ctx = _AnalysisContext(file_path=file_path, current_function=None)
        self._process_statements(
            statements=getattr(tree, "body", []),
            env=module_env,
            context=module_ctx,
            function_summaries=summaries,
            file_path=file_path,
        )

        flows = self._sink_hits_to_flow_records(module_ctx.sink_hits, file_path=file_path)
        flows.extend(self._emit_unconditional_function_flows(summaries, file_path=file_path))

        return self._deduplicate_flows(flows)

    def _collect_functions(self, tree: ast.AST) -> dict[str, FunctionNode]:
        functions: dict[str, FunctionNode] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name] = node
        return functions

    def _build_function_summaries(
        self, function_defs: dict[str, FunctionNode], file_path: str, max_iterations: int = 6
    ) -> dict[str, FunctionSummary]:
        summaries = {name: FunctionSummary(name=name) for name in function_defs}

        for _ in range(max_iterations):
            changed = False
            for name, function_node in function_defs.items():
                summary = self._summarize_function(
                    node=function_node,
                    file_path=file_path,
                    function_summaries=summaries,
                )
                if summaries.get(name) != summary:
                    summaries[name] = summary
                    changed = True
            if not changed:
                break
        return summaries

    def _summarize_function(
        self,
        node: FunctionNode,
        file_path: str,
        function_summaries: dict[str, FunctionSummary],
    ) -> FunctionSummary:
        env = self._initial_function_env(node=node, file_path=file_path)
        ctx = _AnalysisContext(file_path=file_path, current_function=node.name)

        self._process_statements(
            statements=node.body,
            env=env,
            context=ctx,
            function_summaries=function_summaries,
            file_path=file_path,
        )

        summary = FunctionSummary(name=node.name)
        for ret_value in ctx.return_values:
            if ret_value.state == TaintState.SANITIZED:
                summary.returns_sanitized = True
            for origin in ret_value.origins:
                if origin.parameter_index is not None:
                    summary.return_parameter_indexes.add(origin.parameter_index)
                else:
                    summary.return_local_origins.append(self._clone_origin(origin))

        sink_template_map: dict[tuple[int, str, str], SinkHitTemplate] = {}
        for sink_hit in ctx.sink_hits:
            key = (sink_hit.sink_line, sink_hit.sink_type, sink_hit.sink_name)
            template = sink_template_map.setdefault(
                key,
                SinkHitTemplate(
                    sink_line=sink_hit.sink_line,
                    sink_type=sink_hit.sink_type,
                    sink_name=sink_hit.sink_name,
                ),
            )
            for origin in sink_hit.origins:
                if origin.parameter_index is not None:
                    template.parameter_indexes.add(origin.parameter_index)
                else:
                    template.local_origins.append(self._clone_origin(origin))

        for template in sink_template_map.values():
            template.local_origins = self._dedupe_origins(template.local_origins)
            if template.parameter_indexes or template.local_origins:
                summary.sink_templates.append(template)

        summary.return_local_origins = self._dedupe_origins(summary.return_local_origins)
        summary.sink_templates.sort(
            key=lambda item: (item.sink_line, item.sink_type, item.sink_name)
        )

        return summary

    def _initial_function_env(self, node: FunctionNode, file_path: str) -> dict[str, TaintValue]:
        env: dict[str, TaintValue] = {}
        for index, arg in enumerate(node.args.args):
            param_origin = TaintOrigin(
                source_file=file_path,
                source_line=node.lineno,
                source_type=f"parameter:{arg.arg}",
                variable_name=arg.arg,
                parameter_index=index,
                flow_path=[
                    {
                        "file": file_path,
                        "line": node.lineno,
                        "variable": arg.arg,
                        "operation": "parameter",
                    }
                ],
            )
            env[arg.arg] = TaintValue.tainted([param_origin])
        return env

    def _process_statements(
        self,
        statements: list[ast.stmt],
        env: dict[str, TaintValue],
        context: _AnalysisContext,
        function_summaries: dict[str, FunctionSummary],
        file_path: str,
    ) -> None:
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            if isinstance(stmt, ast.Assign):
                value = self._evaluate_expr(stmt.value, env, context, function_summaries, file_path)
                for target in stmt.targets:
                    for target_name in self._extract_target_names(target):
                        env[target_name] = self._value_for_assignment(
                            value=value,
                            target_name=target_name,
                            line_number=stmt.lineno,
                            file_path=file_path,
                        )
                continue

            if isinstance(stmt, ast.AnnAssign):
                value = self._evaluate_expr(stmt.value, env, context, function_summaries, file_path)
                for target_name in self._extract_target_names(stmt.target):
                    env[target_name] = self._value_for_assignment(
                        value=value,
                        target_name=target_name,
                        line_number=stmt.lineno,
                        file_path=file_path,
                    )
                continue

            if isinstance(stmt, ast.AugAssign):
                left = self._evaluate_expr(stmt.target, env, context, function_summaries, file_path)
                right = self._evaluate_expr(stmt.value, env, context, function_summaries, file_path)
                combined = self._merge_values([left, right])
                for target_name in self._extract_target_names(stmt.target):
                    env[target_name] = self._value_for_assignment(
                        value=combined,
                        target_name=target_name,
                        line_number=stmt.lineno,
                        file_path=file_path,
                    )
                continue

            if isinstance(stmt, ast.Expr):
                self._evaluate_expr(stmt.value, env, context, function_summaries, file_path)
                continue

            if isinstance(stmt, ast.Return):
                ret_value = self._evaluate_expr(
                    stmt.value, env, context, function_summaries, file_path
                ) if stmt.value else TaintValue.untainted()
                context.return_values.append(ret_value)
                continue

            if isinstance(stmt, ast.If):
                self._evaluate_expr(stmt.test, env, context, function_summaries, file_path)
                body_env = self._clone_env(env)
                else_env = self._clone_env(env)
                self._process_statements(
                    stmt.body,
                    body_env,
                    context,
                    function_summaries,
                    file_path,
                )
                self._process_statements(
                    stmt.orelse,
                    else_env,
                    context,
                    function_summaries,
                    file_path,
                )
                merged = self._merge_envs(env, body_env, else_env)
                env.clear()
                env.update(merged)
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                iter_value = self._evaluate_expr(
                    stmt.iter, env, context, function_summaries, file_path
                )
                loop_env = self._clone_env(env)
                for target_name in self._extract_target_names(stmt.target):
                    loop_env[target_name] = self._value_for_assignment(
                        value=iter_value,
                        target_name=target_name,
                        line_number=stmt.lineno,
                        file_path=file_path,
                    )
                self._process_statements(
                    stmt.body,
                    loop_env,
                    context,
                    function_summaries,
                    file_path,
                )
                self._process_statements(
                    stmt.orelse,
                    loop_env,
                    context,
                    function_summaries,
                    file_path,
                )
                merged = self._merge_envs(env, loop_env)
                env.clear()
                env.update(merged)
                continue

            if isinstance(stmt, ast.While):
                self._evaluate_expr(stmt.test, env, context, function_summaries, file_path)
                loop_env = self._clone_env(env)
                self._process_statements(
                    stmt.body,
                    loop_env,
                    context,
                    function_summaries,
                    file_path,
                )
                self._process_statements(
                    stmt.orelse,
                    loop_env,
                    context,
                    function_summaries,
                    file_path,
                )
                merged = self._merge_envs(env, loop_env)
                env.clear()
                env.update(merged)
                continue

            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                with_env = self._clone_env(env)
                for item in stmt.items:
                    context_value = self._evaluate_expr(
                        item.context_expr, with_env, context, function_summaries, file_path
                    )
                    if item.optional_vars:
                        for target_name in self._extract_target_names(item.optional_vars):
                            with_env[target_name] = self._value_for_assignment(
                                value=context_value,
                                target_name=target_name,
                                line_number=stmt.lineno,
                                file_path=file_path,
                            )
                self._process_statements(
                    stmt.body,
                    with_env,
                    context,
                    function_summaries,
                    file_path,
                )
                merged = self._merge_envs(env, with_env)
                env.clear()
                env.update(merged)
                continue

            if isinstance(stmt, ast.Try):
                body_env = self._clone_env(env)
                self._process_statements(
                    stmt.body,
                    body_env,
                    context,
                    function_summaries,
                    file_path,
                )

                orelse_env = self._clone_env(body_env)
                self._process_statements(
                    stmt.orelse,
                    orelse_env,
                    context,
                    function_summaries,
                    file_path,
                )

                handler_envs: list[dict[str, TaintValue]] = []
                for handler in stmt.handlers:
                    handler_env = self._clone_env(env)
                    if handler.name:
                        handler_env[handler.name] = TaintValue.unknown()
                    self._process_statements(
                        handler.body,
                        handler_env,
                        context,
                        function_summaries,
                        file_path,
                    )
                    handler_envs.append(handler_env)

                final_env = self._clone_env(env)
                self._process_statements(
                    stmt.finalbody,
                    final_env,
                    context,
                    function_summaries,
                    file_path,
                )

                merged = self._merge_envs(env, body_env, orelse_env, final_env, *handler_envs)
                env.clear()
                env.update(merged)
                continue

            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._evaluate_expr(child, env, context, function_summaries, file_path)

    def _evaluate_expr(
        self,
        node: ast.AST | None,
        env: dict[str, TaintValue],
        context: _AnalysisContext,
        function_summaries: dict[str, FunctionSummary],
        file_path: str,
    ) -> TaintValue:
        if node is None:
            return TaintValue.untainted()

        if isinstance(node, ast.Name):
            return self._clone_value(env.get(node.id, TaintValue.unknown()))

        if isinstance(node, ast.Constant):
            return TaintValue.untainted()

        if isinstance(node, ast.Call):
            return self._evaluate_call(node, env, context, function_summaries, file_path)

        if isinstance(node, ast.Attribute):
            dotted = self._node_to_dotted_name(node)
            if dotted and self._is_source_name(dotted):
                source_type = self._source_type_for_name(dotted)
                return self._make_source_value(
                    file_path=file_path,
                    line_number=node.lineno,
                    source_type=source_type,
                    variable_name=dotted.split(".")[-1],
                )
            return self._evaluate_expr(node.value, env, context, function_summaries, file_path)

        if isinstance(node, ast.Subscript):
            container = self._evaluate_expr(node.value, env, context, function_summaries, file_path)
            index = self._evaluate_expr(node.slice, env, context, function_summaries, file_path)
            return self._merge_values([container, index])

        if isinstance(node, ast.JoinedStr):
            parts = [
                self._evaluate_expr(value, env, context, function_summaries, file_path)
                for value in node.values
            ]
            return self._merge_values(parts)

        if isinstance(node, ast.FormattedValue):
            return self._evaluate_expr(node.value, env, context, function_summaries, file_path)

        if isinstance(node, ast.BinOp):
            left = self._evaluate_expr(node.left, env, context, function_summaries, file_path)
            right = self._evaluate_expr(node.right, env, context, function_summaries, file_path)
            return self._merge_values([left, right])

        if isinstance(node, ast.BoolOp):
            values = [
                self._evaluate_expr(value, env, context, function_summaries, file_path)
                for value in node.values
            ]
            return self._merge_values(values)

        if isinstance(node, ast.UnaryOp):
            return self._evaluate_expr(node.operand, env, context, function_summaries, file_path)

        if isinstance(node, ast.Compare):
            parts = [
                self._evaluate_expr(node.left, env, context, function_summaries, file_path)
            ]
            parts.extend(
                self._evaluate_expr(comp, env, context, function_summaries, file_path)
                for comp in node.comparators
            )
            return self._merge_values(parts)

        if isinstance(node, ast.IfExp):
            test = self._evaluate_expr(node.test, env, context, function_summaries, file_path)
            body = self._evaluate_expr(node.body, env, context, function_summaries, file_path)
            orelse = self._evaluate_expr(node.orelse, env, context, function_summaries, file_path)
            return self._merge_values([test, body, orelse])

        if isinstance(node, ast.Dict):
            values = []
            for key in node.keys:
                values.append(self._evaluate_expr(key, env, context, function_summaries, file_path))
            for value in node.values:
                values.append(self._evaluate_expr(value, env, context, function_summaries, file_path))
            return self._merge_values(values)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [
                self._evaluate_expr(elt, env, context, function_summaries, file_path)
                for elt in node.elts
            ]
            return self._merge_values(values)

        if isinstance(node, ast.NamedExpr):
            value = self._evaluate_expr(node.value, env, context, function_summaries, file_path)
            for target_name in self._extract_target_names(node.target):
                env[target_name] = self._value_for_assignment(
                    value=value,
                    target_name=target_name,
                    line_number=node.lineno,
                    file_path=file_path,
                )
            return value

        child_values = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                child_values.append(
                    self._evaluate_expr(child, env, context, function_summaries, file_path)
                )
        if child_values:
            return self._merge_values(child_values)

        return TaintValue.unknown()

    def _evaluate_call(
        self,
        node: ast.Call,
        env: dict[str, TaintValue],
        context: _AnalysisContext,
        function_summaries: dict[str, FunctionSummary],
        file_path: str,
    ) -> TaintValue:
        func_name = self._node_to_dotted_name(node.func) or ""
        arg_values = [
            self._evaluate_expr(arg, env, context, function_summaries, file_path) for arg in node.args
        ]
        kw_values = [
            self._evaluate_expr(kw.value, env, context, function_summaries, file_path)
            for kw in node.keywords
        ]
        all_arg_values = arg_values + kw_values

        sink_type = self._sink_type_for_function(func_name)
        if sink_type:
            tainted_origins = []
            for value in all_arg_values:
                if value.state == TaintState.TAINTED:
                    tainted_origins.extend(value.origins)
            if tainted_origins:
                context.sink_hits.append(
                    _SinkHit(
                        sink_line=node.lineno,
                        sink_type=sink_type,
                        sink_name=func_name or "<call>",
                        origins=self._dedupe_origins(
                            [self._clone_origin(origin) for origin in tainted_origins]
                        ),
                    )
                )

        if self._is_source_call(func_name):
            source_type = self._source_type_for_name(func_name)
            return self._make_source_value(
                file_path=file_path,
                line_number=node.lineno,
                source_type=source_type,
                variable_name=func_name.split(".")[-1] if func_name else "user_input",
            )

        if self._is_sanitizer_call(func_name):
            return TaintValue.sanitized()

        if func_name in function_summaries:
            summary = function_summaries[func_name]
            self._materialize_summary_sink_hits(
                summary=summary,
                call_node=node,
                arg_values=arg_values,
                context=context,
                file_path=file_path,
                call_name=func_name,
            )
            return self._materialize_summary_return(
                summary=summary,
                call_node=node,
                arg_values=arg_values,
                file_path=file_path,
                call_name=func_name,
            )

        tainted_origins = []
        has_unknown = False
        for value in all_arg_values:
            if value.state == TaintState.TAINTED:
                tainted_origins.extend(value.origins)
            elif value.state == TaintState.UNKNOWN:
                has_unknown = True

        if tainted_origins:
            propagated = self._append_step_to_origins(
                origins=tainted_origins,
                file_path=file_path,
                line_number=node.lineno,
                variable_name=func_name or "<call>",
                operation="call",
            )
            return TaintValue.tainted(propagated)

        if has_unknown:
            return TaintValue.unknown()

        return TaintValue.untainted()

    def _materialize_summary_sink_hits(
        self,
        summary: FunctionSummary,
        call_node: ast.Call,
        arg_values: list[TaintValue],
        context: _AnalysisContext,
        file_path: str,
        call_name: str,
    ) -> None:
        for template in summary.sink_templates:
            mapped_origins: list[TaintOrigin] = []
            for param_index in template.parameter_indexes:
                if 0 <= param_index < len(arg_values):
                    value = arg_values[param_index]
                    if value.state == TaintState.TAINTED:
                        mapped_origins.extend(value.origins)
            if not mapped_origins:
                continue

            mapped_with_call = self._append_step_to_origins(
                origins=mapped_origins,
                file_path=file_path,
                line_number=call_node.lineno,
                variable_name=call_name,
                operation="call",
            )
            context.sink_hits.append(
                _SinkHit(
                    sink_line=template.sink_line,
                    sink_type=template.sink_type,
                    sink_name=template.sink_name,
                    origins=mapped_with_call,
                )
            )

    def _materialize_summary_return(
        self,
        summary: FunctionSummary,
        call_node: ast.Call,
        arg_values: list[TaintValue],
        file_path: str,
        call_name: str,
    ) -> TaintValue:
        mapped_origins: list[TaintOrigin] = []
        for param_index in summary.return_parameter_indexes:
            if 0 <= param_index < len(arg_values):
                value = arg_values[param_index]
                if value.state == TaintState.TAINTED:
                    mapped_origins.extend(value.origins)

        mapped_origins.extend(self._clone_origin(origin) for origin in summary.return_local_origins)

        if mapped_origins:
            with_return_step = self._append_step_to_origins(
                origins=mapped_origins,
                file_path=file_path,
                line_number=call_node.lineno,
                variable_name=call_name,
                operation="return",
            )
            return TaintValue.tainted(with_return_step)

        if summary.returns_sanitized:
            return TaintValue.sanitized()

        return TaintValue.untainted()

    def _value_for_assignment(
        self,
        value: TaintValue,
        target_name: str,
        line_number: int,
        file_path: str,
    ) -> TaintValue:
        if value.state != TaintState.TAINTED:
            return TaintValue(state=value.state, origins=[])

        assigned_origins = self._append_step_to_origins(
            origins=value.origins,
            file_path=file_path,
            line_number=line_number,
            variable_name=target_name,
            operation="assign",
        )
        return TaintValue.tainted(assigned_origins)

    def _extract_target_names(self, node: ast.AST | None) -> list[str]:
        if node is None:
            return []
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in node.elts:
                names.extend(self._extract_target_names(elt))
            return names
        return []

    def _merge_values(self, values: list[TaintValue]) -> TaintValue:
        tainted_origins: list[TaintOrigin] = []
        has_unknown = False
        has_sanitized = False
        has_untainted = False

        for value in values:
            if value.state == TaintState.TAINTED:
                tainted_origins.extend(value.origins)
            elif value.state == TaintState.UNKNOWN:
                has_unknown = True
            elif value.state == TaintState.SANITIZED:
                has_sanitized = True
            elif value.state == TaintState.UNTAINTED:
                has_untainted = True

        if tainted_origins:
            return TaintValue.tainted(self._dedupe_origins(tainted_origins))
        if has_unknown:
            return TaintValue.unknown()
        if has_sanitized:
            return TaintValue.sanitized()
        if has_untainted:
            return TaintValue.untainted()
        return TaintValue.unknown()

    def _merge_envs(
        self, base: dict[str, TaintValue], *branches: dict[str, TaintValue]
    ) -> dict[str, TaintValue]:
        merged: dict[str, TaintValue] = {}
        all_keys = set(base)
        for branch in branches:
            all_keys.update(branch)

        for key in all_keys:
            base_value = base.get(key, TaintValue.untainted())
            values = [base_value]
            for branch in branches:
                values.append(branch.get(key, base_value))
            merged[key] = self._merge_values(values)
        return merged

    def _clone_env(self, env: dict[str, TaintValue]) -> dict[str, TaintValue]:
        return {name: self._clone_value(value) for name, value in env.items()}

    def _clone_value(self, value: TaintValue) -> TaintValue:
        if value.state != TaintState.TAINTED:
            return TaintValue(state=value.state, origins=[])
        return TaintValue.tainted([self._clone_origin(origin) for origin in value.origins])

    def _clone_origin(self, origin: TaintOrigin) -> TaintOrigin:
        return TaintOrigin(
            source_file=origin.source_file,
            source_line=origin.source_line,
            source_type=origin.source_type,
            variable_name=origin.variable_name,
            parameter_index=origin.parameter_index,
            flow_path=[dict(step) for step in origin.flow_path],
        )

    def _append_step_to_origins(
        self,
        origins: list[TaintOrigin],
        file_path: str,
        line_number: int,
        variable_name: str,
        operation: str,
    ) -> list[TaintOrigin]:
        appended = []
        step = {
            "file": file_path,
            "line": line_number,
            "variable": variable_name,
            "operation": operation,
        }
        for origin in origins:
            updated = self._clone_origin(origin)
            updated.variable_name = variable_name
            updated.flow_path.append(step)
            appended.append(updated)
        return self._dedupe_origins(appended)

    def _sink_hits_to_flow_records(
        self, sink_hits: list[_SinkHit], file_path: str
    ) -> list[TaintFlowRecord]:
        flows: list[TaintFlowRecord] = []
        for sink_hit in sink_hits:
            for origin in sink_hit.origins:
                if origin.parameter_index is not None:
                    continue
                flow_path = [dict(step) for step in origin.flow_path]
                flow_path.append(
                    {
                        "file": file_path,
                        "line": sink_hit.sink_line,
                        "variable": sink_hit.sink_name,
                        "operation": "sink",
                    }
                )
                flows.append(
                    TaintFlowRecord(
                        source_file=origin.source_file,
                        source_line=origin.source_line,
                        source_type=origin.source_type,
                        sink_file=file_path,
                        sink_line=sink_hit.sink_line,
                        sink_type=sink_hit.sink_type,
                        variable_name=origin.variable_name,
                        flow_path=flow_path,
                    )
                )
        return flows

    def _emit_unconditional_function_flows(
        self, summaries: dict[str, FunctionSummary], file_path: str
    ) -> list[TaintFlowRecord]:
        flows: list[TaintFlowRecord] = []
        for summary in summaries.values():
            for template in summary.sink_templates:
                for origin in template.local_origins:
                    if origin.parameter_index is not None:
                        continue
                    flow_path = [dict(step) for step in origin.flow_path]
                    flow_path.append(
                        {
                            "file": file_path,
                            "line": template.sink_line,
                            "variable": template.sink_name,
                            "operation": "sink",
                        }
                    )
                    flows.append(
                        TaintFlowRecord(
                            source_file=origin.source_file,
                            source_line=origin.source_line,
                            source_type=origin.source_type,
                            sink_file=file_path,
                            sink_line=template.sink_line,
                            sink_type=template.sink_type,
                            variable_name=origin.variable_name,
                            flow_path=flow_path,
                        )
                    )
        return flows

    def _dedupe_origins(self, origins: list[TaintOrigin]) -> list[TaintOrigin]:
        deduped: dict[tuple, TaintOrigin] = {}
        for origin in origins:
            key = (
                origin.source_file,
                origin.source_line,
                origin.source_type,
                origin.variable_name,
                origin.parameter_index,
                tuple(
                    (
                        step.get("file"),
                        step.get("line"),
                        step.get("variable"),
                        step.get("operation"),
                    )
                    for step in origin.flow_path
                ),
            )
            deduped[key] = origin
        return list(deduped.values())

    def _deduplicate_flows(self, flows: list[TaintFlowRecord]) -> list[TaintFlowRecord]:
        deduped: dict[tuple, TaintFlowRecord] = {}
        for flow in flows:
            key = (
                flow.source_file,
                flow.source_line,
                flow.source_type,
                flow.sink_file,
                flow.sink_line,
                flow.sink_type,
                flow.variable_name,
            )
            existing = deduped.get(key)
            if existing is None or len(flow.flow_path) < len(existing.flow_path):
                deduped[key] = flow
        return sorted(deduped.values(), key=lambda flow: (flow.sink_line, flow.source_line))

    def _make_source_value(
        self, file_path: str, line_number: int, source_type: str, variable_name: str
    ) -> TaintValue:
        origin = TaintOrigin(
            source_file=file_path,
            source_line=line_number,
            source_type=source_type,
            variable_name=variable_name,
            flow_path=[
                {
                    "file": file_path,
                    "line": line_number,
                    "variable": variable_name,
                    "operation": "source",
                }
            ],
        )
        return TaintValue.tainted([origin])

    def _source_type_for_name(self, dotted_name: str) -> str:
        for source in self.taint_sources:
            if dotted_name == source or dotted_name.startswith(f"{source}."):
                return source
        return dotted_name or "user_input"

    def _sink_type_for_function(self, func_name: str) -> str | None:
        if not func_name:
            return None
        for sink_pattern, vuln_type in self.taint_sinks.items():
            if func_name == sink_pattern:
                return vuln_type
            suffix = sink_pattern.split(".")[-1]
            if func_name.endswith(f".{suffix}") or func_name == suffix:
                return vuln_type
        return None

    def _is_source_name(self, dotted_name: str) -> bool:
        for source in self.taint_sources:
            if dotted_name == source or dotted_name.startswith(f"{source}."):
                return True
        return False

    def _is_source_call(self, func_name: str) -> bool:
        if not func_name:
            return False
        for source in self.taint_sources:
            if func_name == source or func_name.startswith(f"{source}."):
                return True
        return False

    def _is_sanitizer_call(self, func_name: str) -> bool:
        return func_name in self.sanitizers

    def _node_to_dotted_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._node_to_dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None
