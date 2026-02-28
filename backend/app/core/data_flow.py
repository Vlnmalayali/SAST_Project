"""Data flow analysis utilities — def-use chain tracking."""

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Definition:
    variable: str
    lineno: int
    node: ast.AST


@dataclass
class Use:
    variable: str
    lineno: int
    node: ast.AST


@dataclass
class DefUseChain:
    definition: Definition
    uses: list[Use] = field(default_factory=list)


class DataFlowAnalyzer:
    """Build def-use chains for variables in a function scope."""

    def build_def_use_chains(self, tree: ast.AST) -> dict[str, DefUseChain]:
        """Build def-use chains for all variables."""
        chains: dict[str, DefUseChain] = {}

        # First pass: collect all definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        chains[target.id] = DefUseChain(
                            definition=Definition(
                                variable=target.id,
                                lineno=node.lineno,
                                node=node,
                            )
                        )
            elif isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    chains[arg.arg] = DefUseChain(
                        definition=Definition(
                            variable=arg.arg,
                            lineno=node.lineno,
                            node=node,
                        )
                    )

        # Second pass: collect all uses
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in chains:
                    chains[node.id].uses.append(
                        Use(variable=node.id, lineno=node.lineno, node=node)
                    )

        return chains

    def track_variable_flow(self, chains: dict[str, DefUseChain], variable: str) -> list[int]:
        """Get all line numbers where a variable is used."""
        chain = chains.get(variable)
        if not chain:
            return []
        lines = [chain.definition.lineno]
        lines.extend(use.lineno for use in chain.uses)
        return sorted(set(lines))

    def find_dependencies(self, tree: ast.AST, variable: str) -> set[str]:
        """Find all variables that influence a given variable."""
        deps = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == variable:
                        # Find all Name nodes in the value
                        for child in ast.walk(node.value):
                            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                                deps.add(child.id)
        return deps
