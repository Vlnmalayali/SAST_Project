import os
import shutil
import zipfile
from pathlib import Path


PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
JAVA_EXTENSIONS = {".java"}

LANGUAGE_EXTENSIONS = {
    "python": PYTHON_EXTENSIONS,
    "javascript": JS_EXTENSIONS,
    "java": JAVA_EXTENSIONS,
}

EXCLUDE_DIRS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".next",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "migrations",
}


def discover_files(root_dir: str, language: str = "python") -> list[str]:
    """Discover all code files in a directory for the given language."""
    extensions = LANGUAGE_EXTENSIONS.get(language, PYTHON_EXTENSIONS)
    files = []
    root = Path(root_dir)

    for path in root.rglob("*"):
        if any(excluded in path.parts for excluded in EXCLUDE_DIRS):
            continue
        if path.suffix in extensions and path.is_file():
            files.append(str(path))

    return sorted(files)


def extract_zip(zip_path: str, extract_to: str) -> str:
    """Extract a zip file and return the root directory."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        # Security: check for zip bombs and path traversal
        total_size = sum(info.file_size for info in zf.infolist())
        if total_size > 500 * 1024 * 1024:  # 500MB limit
            raise ValueError("Zip file too large (>500MB)")

        for info in zf.infolist():
            if info.filename.startswith("/") or ".." in info.filename:
                raise ValueError("Zip contains path traversal attempt")

        zf.extractall(extract_to)

    # Find root directory
    items = os.listdir(extract_to)
    if len(items) == 1 and os.path.isdir(os.path.join(extract_to, items[0])):
        return os.path.join(extract_to, items[0])
    return extract_to


def cleanup_directory(path: str) -> None:
    """Safely remove a directory tree."""
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except Exception:
        pass


def get_code_snippet(source_lines: list[str], line_num: int, context: int = 3) -> str:
    """Extract code snippet around a specific line."""
    start = max(0, line_num - context - 1)
    end = min(len(source_lines), line_num + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>> " if i == line_num - 1 else "    "
        snippet_lines.append(f"{marker}{i + 1:4d} | {source_lines[i]}")
    return "\n".join(snippet_lines)
