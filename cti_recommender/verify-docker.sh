#!/bin/bash
# Docker Setup Verification Script
# Ensures the Docker environment is correctly configured

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}CTI Recommender - Docker Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test counter
PASSED=0
FAILED=0
TOTAL=10

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC} - $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC} - $1"
    FAILED=$((FAILED + 1))
}

info() {
    echo -e "${YELLOW}ℹ INFO${NC} - $1"
}

# Test 1: Docker installed
echo "Test 1/10: Checking Docker installation..."
if command -v docker &> /dev/null; then
    version=$(docker --version)
    pass "Docker installed: $version"
else
    fail "Docker not found. Please install Docker."
fi

# Test 2: Docker Compose installed
echo "Test 2/10: Checking Docker Compose..."
if command -v docker-compose &> /dev/null; then
    version=$(docker-compose --version)
    pass "Docker Compose installed: $version"
else
    fail "Docker Compose not found. Please install Docker Compose."
fi

# Test 3: Check Dockerfile exists
echo "Test 3/10: Checking Dockerfile..."
if [ -f "Dockerfile" ]; then
    pass "Dockerfile found"
else
    fail "Dockerfile missing"
fi

# Test 4: Check docker-compose.yml exists
echo "Test 4/10: Checking docker-compose.yml..."
if [ -f "docker-compose.yml" ]; then
    pass "docker-compose.yml found"
else
    fail "docker-compose.yml missing"
fi

# Test 5: Check dev compose file
echo "Test 5/10: Checking docker-compose.dev.yml..."
if [ -f "docker-compose.dev.yml" ]; then
    pass "docker-compose.dev.yml found"
else
    fail "docker-compose.dev.yml missing"
fi

# Test 6: Check .dockerignore
echo "Test 6/10: Checking .dockerignore..."
if [ -f ".dockerignore" ]; then
    pass ".dockerignore found"
else
    fail ".dockerignore missing"
fi

# Test 7: Check requirements.txt
echo "Test 7/10: Checking requirements.txt..."
if [ -f "requirements.txt" ]; then
    pass "requirements.txt found"
else
    fail "requirements.txt missing"
fi

# Test 8: Check directory structure
echo "Test 8/10: Checking directory structure..."
required_dirs=("src" "tests" "data" "models" "scripts" "config")
missing_dirs=()

for dir in "${required_dirs[@]}"; do
    if [ ! -d "$dir" ]; then
        missing_dirs+=("$dir")
    fi
done

if [ ${#missing_dirs[@]} -eq 0 ]; then
    pass "All required directories present"
else
    fail "Missing directories: ${missing_dirs[*]}"
fi

# Test 9: Check if we can build the image
echo "Test 9/10: Testing Docker build..."
info "This may take a few minutes on first run..."
if docker-compose build > /tmp/docker_build.log 2>&1; then
    pass "Docker image builds successfully"
else
    fail "Docker build failed. Check /tmp/docker_build.log for details"
fi

# Test 10: Check if we can start the container
echo "Test 10/10: Testing container startup..."
if docker-compose up -d > /tmp/docker_up.log 2>&1; then
    pass "Container starts successfully"
    
    # Wait for container to be ready
    info "Waiting for container to be ready..."
    sleep 5
    
    # Test health endpoint
    echo ""
    echo "Bonus Test: Checking API health..."
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        response=$(curl -s http://localhost:8000/health)
        pass "API health check passed: $response"
        PASSED=$((PASSED + 1))
        TOTAL=$((TOTAL + 1))
    else
        fail "API health check failed"
        FAILED=$((FAILED + 1))
        TOTAL=$((TOTAL + 1))
    fi
    
    # Stop container
    echo ""
    info "Cleaning up test containers..."
    docker-compose down > /dev/null 2>&1
else
    fail "Container failed to start. Check /tmp/docker_up.log"
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verification Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Total Tests:  $TOTAL"
echo -e "${GREEN}Passed:       $PASSED${NC}"
echo -e "${RED}Failed:       $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Your Docker setup is ready to use."
    echo ""
    echo "Next steps:"
    echo "  make up          # Start services"
    echo "  make test-fast   # Run 99 tests"
    echo "  make help        # See all commands"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Please fix the failed tests before proceeding."
    echo "Check the error messages above for details."
    exit 1
fi
