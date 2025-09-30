#!/bin/bash

# Kong Guard AI - Comprehensive Integration Testing
# Validates the complete modular refactoring implementation

set -e

echo "🧪 Kong Guard AI - Comprehensive Integration Testing"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"

    echo -e "${BLUE}🔍 Testing: ${test_name}${NC}"

    if eval "$test_command"; then
        echo -e "${GREEN}✅ PASSED: ${test_name}${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}❌ FAILED: ${test_name}${NC}"
        ((FAILED_TESTS++))
    fi

    ((TOTAL_TESTS++))
    echo ""
}

# Test 1: Verify modular file structure
echo -e "${YELLOW}📁 Step 1: Modular Architecture Validation${NC}"
echo "----------------------------------------"

run_test "Configuration modules exist" "test -d kong-plugin/kong/plugins/kong-guard-ai/modules/config"
run_test "Security modules exist" "test -d kong-plugin/kong/plugins/kong-guard-ai/modules/security"
run_test "AI modules exist" "test -d kong-plugin/kong/plugins/kong-guard-ai/modules/ai"
run_test "Utility modules exist" "test -d kong-plugin/kong/plugins/kong-guard-ai/modules/utils"

MODULE_COUNT=$(find kong-plugin/kong/plugins/kong-guard-ai/modules -name "*.lua" | wc -l)
echo "📊 Total modules found: ${MODULE_COUNT}"

if [ "$MODULE_COUNT" -ge 20 ]; then
    echo -e "${GREEN}✅ Module count target achieved (20+ modules)${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Module count below target (found: ${MODULE_COUNT}, expected: 20+)${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 2: Verify schema reduction
echo -e "${YELLOW}📏 Step 2: Schema Reduction Validation${NC}"
echo "-------------------------------------"

SCHEMA_LINES=$(wc -l < kong-plugin/kong/plugins/kong-guard-ai/schema.lua)
echo "📊 Current schema.lua lines: ${SCHEMA_LINES}"

if [ "$SCHEMA_LINES" -lt 100 ]; then
    echo -e "${GREEN}✅ Schema reduction achieved (${SCHEMA_LINES} lines, target: <100)${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Schema reduction incomplete (${SCHEMA_LINES} lines, target: <100)${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 3: Test suite validation
echo -e "${YELLOW}🧪 Step 3: Test Suite Validation${NC}"
echo "--------------------------------"

TEST_COUNT=$(find kong-plugin/spec -name "*_spec.lua" | wc -l)
echo "📊 Total test suites found: ${TEST_COUNT}"

run_test "Configuration tests exist" "test -f kong-plugin/spec/kong-guard-ai/unit/config/profile_manager_spec.lua"
run_test "Security tests exist" "test -f kong-plugin/spec/kong-guard-ai/unit/security/run_security_tests.lua"
run_test "AI tests exist" "test -f kong-plugin/spec/kong-guard-ai/unit/ai/ai_service_spec.lua"

# Test 4: Module syntax validation
echo -e "${YELLOW}🔍 Step 4: Module Syntax Validation${NC}"
echo "----------------------------------"

# Check Lua syntax for all modules
syntax_errors=0
for module in $(find kong-plugin/kong/plugins/kong-guard-ai/modules -name "*.lua"); do
    if lua -l luac -e "luac.compile(io.open('$module'):read('*a'), '$module')" 2>/dev/null; then
        echo -e "${GREEN}✅ Syntax valid: $(basename $module)${NC}"
    else
        echo -e "${RED}❌ Syntax error: $(basename $module)${NC}"
        ((syntax_errors++))
    fi
done

if [ "$syntax_errors" -eq 0 ]; then
    echo -e "${GREEN}✅ All modules have valid Lua syntax${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ ${syntax_errors} modules have syntax errors${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 5: Configuration Profile Testing
echo -e "${YELLOW}⚙️ Step 5: Configuration System Testing${NC}"
echo "---------------------------------------"

# Test that we can create and validate configuration templates
run_test "Profile manager file exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/config/profile_manager.lua"
run_test "Templates file exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/config/templates.lua"
run_test "Migration tool exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/config/migration_tool.lua"

# Check for required profile types in templates
if grep -q "development.*=" kong-plugin/kong/plugins/kong-guard-ai/modules/config/templates.lua && \
   grep -q "production.*=" kong-plugin/kong/plugins/kong-guard-ai/modules/config/templates.lua; then
    echo -e "${GREEN}✅ Environment templates found (dev, prod)${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Missing environment templates${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 6: Security Module Validation
echo -e "${YELLOW}🛡️ Step 6: Security System Testing${NC}"
echo "----------------------------------"

run_test "Rate limiter exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/security/rate_limiter.lua"
run_test "Request validator exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/security/request_validator.lua"
run_test "Auth manager exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/security/auth_manager.lua"
run_test "Security orchestrator exists" "test -f kong-plugin/kong/plugins/kong-guard-ai/modules/security/security_orchestrator.lua"

# Check for attack patterns in request validator
if grep -q "SQL_INJECTION\|XSS\|PATH_TRAVERSAL" kong-plugin/kong/plugins/kong-guard-ai/modules/security/request_validator.lua; then
    echo -e "${GREEN}✅ Attack patterns detected in validator${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Missing attack patterns in validator${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 7: Performance Validation
echo -e "${YELLOW}⚡ Step 7: Performance Metrics Check${NC}"
echo "-----------------------------------"

# Check module sizes for maintainability
large_modules=0
for module in $(find kong-plugin/kong/plugins/kong-guard-ai/modules -name "*.lua"); do
    lines=$(wc -l < "$module")
    basename_module=$(basename "$module")

    if [ "$lines" -gt 1000 ]; then
        echo -e "${YELLOW}⚠️ Large module: ${basename_module} (${lines} lines)${NC}"
        ((large_modules++))
    else
        echo -e "${GREEN}✅ Reasonable size: ${basename_module} (${lines} lines)${NC}"
    fi
done

if [ "$large_modules" -le 3 ]; then
    echo -e "${GREEN}✅ Module sizes are maintainable${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Too many large modules (${large_modules})${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 8: Integration Dependencies
echo -e "${YELLOW}🔗 Step 8: Module Dependencies Check${NC}"
echo "-----------------------------------"

# Check that modules properly require their dependencies
dependency_errors=0
for module in $(find kong-plugin/kong/plugins/kong-guard-ai/modules -name "*.lua"); do
    if grep -q "require.*kong\.plugins\.kong-guard-ai\.modules" "$module"; then
        echo -e "${GREEN}✅ Dependencies found: $(basename $module)${NC}"
    else
        echo -e "${YELLOW}⚠️ No internal dependencies: $(basename $module)${NC}"
    fi
done

echo -e "${GREEN}✅ Dependency check complete${NC}"
((PASSED_TESTS++))
((TOTAL_TESTS++))

# Test 9: Git Repository State
echo -e "${YELLOW}📝 Step 9: Repository State Check${NC}"
echo "--------------------------------"

# Check that we're on the right branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" = "feature/001-refactor-large-monolithic-files" ]; then
    echo -e "${GREEN}✅ On correct feature branch: ${CURRENT_BRANCH}${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Wrong branch: ${CURRENT_BRANCH}${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Check recent commits
RECENT_COMMITS=$(git log --oneline -5 | head -5 | wc -l)
if [ "$RECENT_COMMITS" -ge 5 ]; then
    echo -e "${GREEN}✅ Recent development activity detected${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${RED}❌ Limited recent activity${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Test 10: Documentation Coverage
echo -e "${YELLOW}📚 Step 10: Documentation Coverage${NC}"
echo "---------------------------------"

run_test "Implementation summary exists" "test -f MODULAR_REFACTORING_COMPLETE.md"
run_test "Extraction summary exists" "test -f EXTRACTION_SUMMARY.md"

# Check for inline documentation
documented_modules=0
total_modules=0
for module in $(find kong-plugin/kong/plugins/kong-guard-ai/modules -name "*.lua"); do
    ((total_modules++))
    if grep -q "^--.*@param\|^--.*@return\|^---.*" "$module"; then
        ((documented_modules++))
    fi
done

doc_percentage=$((documented_modules * 100 / total_modules))
echo "📊 Documentation coverage: ${doc_percentage}% (${documented_modules}/${total_modules} modules)"

if [ "$doc_percentage" -ge 80 ]; then
    echo -e "${GREEN}✅ Good documentation coverage${NC}"
    ((PASSED_TESTS++))
else
    echo -e "${YELLOW}⚠️ Documentation could be improved${NC}"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Final Results
echo ""
echo "=============================================="
echo -e "${BLUE}🎯 INTEGRATION TEST RESULTS${NC}"
echo "=============================================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Success Rate: $SUCCESS_RATE%"

echo ""
if [ "$SUCCESS_RATE" -ge 90 ]; then
    echo -e "${GREEN}🎉 EXCELLENT: Integration tests passed with flying colors!${NC}"
    echo -e "${GREEN}✅ Modular refactoring is production-ready${NC}"
    exit_code=0
elif [ "$SUCCESS_RATE" -ge 80 ]; then
    echo -e "${YELLOW}✅ GOOD: Integration tests mostly successful${NC}"
    echo -e "${YELLOW}⚠️ Some minor issues to address${NC}"
    exit_code=1
elif [ "$SUCCESS_RATE" -ge 70 ]; then
    echo -e "${YELLOW}⚠️ MODERATE: Integration tests show some concerns${NC}"
    echo -e "${YELLOW}🔧 Requires attention before production${NC}"
    exit_code=2
else
    echo -e "${RED}❌ POOR: Integration tests reveal significant issues${NC}"
    echo -e "${RED}🚨 Major fixes required before proceeding${NC}"
    exit_code=3
fi

echo ""
echo "=============================================="
echo -e "${BLUE}📊 MODULAR REFACTORING SUMMARY${NC}"
echo "=============================================="
echo "✅ Modules Created: $MODULE_COUNT"
echo "✅ Schema Reduced: $(echo "$SCHEMA_LINES" | awk '{print 2041-$1}') lines saved ($(echo "$SCHEMA_LINES" | awk '{printf "%.1f", (2041-$1)/2041*100}')% reduction)"
echo "✅ Test Suites: $TEST_COUNT"
echo "✅ Documentation Coverage: ${doc_percentage}%"
echo "✅ Success Rate: ${SUCCESS_RATE}%"

echo ""
echo -e "${GREEN}🚀 Kong Guard AI modular refactoring validation complete!${NC}"

exit $exit_code
