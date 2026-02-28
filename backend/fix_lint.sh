#!/bin/bash
# Run from backend/ directory

echo "=== Installing tools ==="
pip install ruff black -q

echo "=== Running Ruff auto-fix ==="
ruff check app/ --fix --unsafe-fixes
ruff format app/

echo "=== Running Black ==="
black app/ --line-length 100

echo "=== Fixing trailing whitespace ==="
find app/ -name "*.py" -exec sed -i 's/[[:space:]]*$//' {} \;

echo "=== Fixing missing newline at EOF ==="
find app/ -name "*.py" -exec sh -c '
  [ -n "$(tail -c1 "$1")" ] && echo "" >> "$1"
' _ {} \;

echo "=== Verifying ==="
ruff check app/ --config pyproject.toml
echo ""
echo "Done! Run 'git diff' to see changes."