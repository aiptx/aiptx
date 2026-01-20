#!/bin/bash
# =============================================================================
# AIPTX Multi-Platform Publishing Script
# =============================================================================
# Usage: ./scripts/publish.sh <version>
# Example: ./scripts/publish.sh 2.0.6
#
# This script publishes AIPTX to:
# - PyPI (Python)
# - npm (Node.js SDK + CLI)
# - Docker Hub (Container images)
# - Go Module (tag only)
# =============================================================================

set -e

VERSION=${1:-$(grep 'version = ' pyproject.toml | head -1 | cut -d'"' -f2)}

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     AIPTX Multi-Platform Publisher                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Publishing version: $VERSION"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# =============================================================================
# Pre-flight Checks
# =============================================================================

echo -e "${YELLOW}Running pre-flight checks...${NC}"

# Check if logged into PyPI
if ! pip config get global.index-url > /dev/null 2>&1; then
    echo -e "${RED}Warning: PyPI not configured. Run: pip config set global.index-url https://upload.pypi.org/simple${NC}"
fi

# Check if logged into npm
if ! npm whoami > /dev/null 2>&1; then
    echo -e "${RED}Warning: Not logged into npm. Run: npm login${NC}"
fi

# Check if logged into Docker
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Warning: Docker not running or not logged in.${NC}"
fi

echo -e "${GREEN}Pre-flight checks complete.${NC}"
echo ""

# =============================================================================
# 1. Publish to PyPI
# =============================================================================

echo -e "${YELLOW}[1/5] Publishing to PyPI...${NC}"

# Update version in pyproject.toml if needed
sed -i.bak "s/version = \".*\"/version = \"$VERSION\"/" pyproject.toml
rm -f pyproject.toml.bak

# Build
python -m pip install --upgrade build twine
python -m build

# Upload
echo "Uploading to PyPI..."
python -m twine upload dist/*

echo -e "${GREEN}✓ Published to PyPI${NC}"
echo ""

# =============================================================================
# 2. Publish Node.js SDK to npm
# =============================================================================

echo -e "${YELLOW}[2/5] Publishing @aiptx/sdk to npm...${NC}"

cd sdks/nodejs
npm version $VERSION --no-git-tag-version 2>/dev/null || true
npm install
npm run build
npm publish --access public

cd ../..
echo -e "${GREEN}✓ Published @aiptx/sdk to npm${NC}"
echo ""

# =============================================================================
# 3. Publish Node.js CLI to npm
# =============================================================================

echo -e "${YELLOW}[3/5] Publishing @aiptx/cli to npm...${NC}"

cd sdks/nodejs-cli
npm version $VERSION --no-git-tag-version 2>/dev/null || true
npm install
npm run build
npm publish --access public

cd ../..
echo -e "${GREEN}✓ Published @aiptx/cli to npm${NC}"
echo ""

# =============================================================================
# 4. Publish Docker Image
# =============================================================================

echo -e "${YELLOW}[4/5] Publishing Docker image...${NC}"

# Build multi-platform image
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag aiptx/aiptx:latest \
    --tag aiptx/aiptx:$VERSION \
    --push \
    .

echo -e "${GREEN}✓ Published Docker image${NC}"
echo ""

# =============================================================================
# 5. Tag for Go Module
# =============================================================================

echo -e "${YELLOW}[5/5] Creating Git tag for Go module...${NC}"

git tag -a "v$VERSION" -m "Release v$VERSION" 2>/dev/null || echo "Tag already exists"
git push origin "v$VERSION" 2>/dev/null || echo "Tag already pushed"

echo -e "${GREEN}✓ Git tag created${NC}"
echo ""

# =============================================================================
# Summary
# =============================================================================

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Publication Complete!                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "AIPTX v$VERSION is now available via:"
echo ""
echo "  Python:  pip install aiptx==$VERSION"
echo "  npm SDK: npm install @aiptx/sdk@$VERSION"
echo "  npm CLI: npm install -g @aiptx/cli@$VERSION"
echo "  Docker:  docker pull aiptx/aiptx:$VERSION"
echo "  Go:      go get github.com/aiptx/aiptx-go@v$VERSION"
echo ""
echo "Don't forget to:"
echo "  1. Update Homebrew tap formula with new SHA256"
echo "  2. Create GitHub release with changelog"
echo "  3. Announce on social media / community"
echo ""
