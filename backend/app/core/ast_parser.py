import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    name: str
    lineno: int
    end_lineno: int | None
    args: list[str]
    decorators: list[str]
    body_lines: tuple[int, int]


@dataclass
class CallInfo:
    func_name: str
    lineno: int
    col_offset: int
    args: list
    keywords: dict
    full_call: str = ""


@dataclass
class AssignInfo:
    targets: list[str]
    lineno: int
    value_type: str
    value_repr: str = ""


@dataclass
class ImportInfo:
    module: str
    names: list[str]
    lineno: int


@dataclass
class ParseResult:
    ast_tree: ast.AST
    source_code: str
    source_lines: list[str]
    functions: list[FunctionInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    assignments: list[AssignInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)


class PythonASTParser:
    """Parse Python source code into structured AST information."""

    def parse_file(self, file_path: str) -> ParseResult | None:
        """Parse a Python file and return structured result."""
        try:
            source_code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            return self.parse_source(source_code, file_path)
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")
            return None

    def parse_source(self, source_code: str, file_path: str = "<string>") -> ParseResult | None:
        """Parse Python source code string."""
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return None

        source_lines = source_code.splitlines()
        result = ParseResult(
            ast_tree=tree,
            source_code=source_code,
            source_lines=source_lines,
        )

        visitor = _ASTInfoVisitor(result, source_lines)
        visitor.visit(tree)

        return result


class _ASTInfoVisitor(ast.NodeVisitor):
    """Visitor that extracts structured information from AST."""

    def __init__(self, result: ParseResult, source_lines: list[str]):
        self.result = result
        self.source_lines = source_lines

    def visit_FunctionDef(self, node: ast.FunctionDef):
        args = [arg.arg for arg in node.args.args]
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.dump(dec))

        self.result.functions.append(
            FunctionInfo(
                name=node.name,
                lineno=node.lineno,
                end_lineno=node.end_lineno,
                args=args,
                decorators=decorators,
                body_lines=(node.lineno, node.end_lineno or node.lineno),
            )
        )
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        self.result.classes.append(node.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        if func_name:
            keywords = {}
            for kw in node.keywords:
                if kw.arg:
                    keywords[kw.arg] = self._node_to_str(kw.value)

            self.result.calls.append(
                CallInfo(
                    func_name=func_name,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    args=node.args,
                    keywords=keywords,
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        targets.append(elt.id)

        if targets:
            self.result.assignments.append(
                AssignInfo(
                    targets=targets,
                    lineno=node.lineno,
                    value_type=type(node.value).__name__,
                    value_repr=self._node_to_str(node.value)[:200],
                )
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.result.imports.append(
                ImportInfo(
                    module=alias.name, names=[alias.asname or alias.name], lineno=node.lineno
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        names = [alias.name for alias in node.names]
        self.result.imports.append(ImportInfo(module=module, names=names, lineno=node.lineno))

    def _get_call_name(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_call_name(node.value)
            if value:
                return f"{value}.{node.attr}"
            return node.attr
        return None

    def _node_to_str(self, node) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""
