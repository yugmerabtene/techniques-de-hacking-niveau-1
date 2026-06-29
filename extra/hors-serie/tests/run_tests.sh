#!/bin/bash
# run_tests.sh — KillChainAgent test suite
# Usage: bash extra/hors-serie/tests/run_tests.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/../backend" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================"
echo " KillChainAgent — Test Suite"
echo "============================================"
echo ""

pass_total=0
fail_total=0

run_python_tests() {
    local file="$1"
    local label="$2"
    echo -n "  ${label}..."
    if python3 -m pytest "$file" -q 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC}"
    elif python3 "$file" 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC}"
    else
        echo -e "  ${RED}FAILED${NC}"
        return 1
    fi
}

# ─── Python unit tests ───
echo "─── Agent Unit Tests ───"
cd "$BACKEND_DIR"

export PYTHONPATH="$BACKEND_DIR:$PYTHONPATH"

echo "  Checking test_agents.py syntax..."
if python3 -c "import py_compile; py_compile.compile('${SCRIPT_DIR}/test_agents.py', doraise=True)"; then
    echo -e "  ${GREEN}Syntax OK${NC}"

    echo "  Running test_agents.py..."
    if python3 "${SCRIPT_DIR}/test_agents.py" -v 2>&1; then
        echo -e "  ${GREEN}Agent tests passed${NC}"
        ((pass_total++))
    else
        echo -e "  ${RED}Agent tests failed${NC}"
        ((fail_total++))
    fi
else
    echo -e "  ${RED}Syntax error in test_agents.py${NC}"
    ((fail_total++))
fi

echo ""

# ─── API integration tests ───
echo "─── API Integration Tests ───"
echo "  Checking test_api.py syntax..."
if python3 -c "import py_compile; py_compile.compile('${SCRIPT_DIR}/test_api.py', doraise=True)"; then
    echo -e "  ${GREEN}Syntax OK${NC}"

    echo "  Running test_api.py..."
    if python3 "${SCRIPT_DIR}/test_api.py" -v 2>&1; then
        echo -e "  ${GREEN}API tests passed${NC}"
        ((pass_total++))
    else
        echo -e "  ${RED}API tests failed${NC}"
        ((fail_total++))
    fi
else
    echo -e "  ${RED}Syntax error in test_api.py${NC}"
    ((fail_total++))
fi

echo ""

# ─── Backend syntax check ───
echo "─── Backend Syntax Check ───"
syntax_ok=0
syntax_fail=0
for pyfile in "$BACKEND_DIR"/*.py "$BACKEND_DIR"/agents/*.py; do
    if python3 -c "import py_compile; py_compile.compile('${pyfile}', doraise=True)" 2>/dev/null; then
        ((syntax_ok++))
    else
        echo -e "  ${RED}✗ $(basename $pyfile)${NC}"
        ((syntax_fail++))
    fi
done
echo -e "  ${GREEN}${syntax_ok} files OK${NC}"
if [ "$syntax_fail" -gt 0 ]; then
    echo -e "  ${RED}${syntax_fail} files with errors${NC}"
    ((fail_total++))
else
    ((pass_total++))
fi

echo ""
echo "============================================"
echo -e " Results: ${GREEN}${pass_total} passed${NC} / ${RED}${fail_total} failed${NC}"
echo "============================================"

if [ "$fail_total" -gt 0 ]; then
    exit 1
fi
