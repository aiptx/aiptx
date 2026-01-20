#!/bin/bash
# =============================================================================
# AIPTX Repository Setup Script
# =============================================================================
# This script helps set up the required GitHub repositories for multi-platform
# distribution.
#
# Prerequisites:
# - gh CLI installed and authenticated
# - GitHub organization 'aiptx' created (or use personal account)
# =============================================================================

set -e

ORG=${1:-aiptx}  # GitHub organization or username

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     AIPTX Repository Setup                                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Setting up repositories under: $ORG"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =============================================================================
# Check Prerequisites
# =============================================================================

if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required"
    echo "Install: brew install gh"
    exit 1
fi

if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub"
    echo "Run: gh auth login"
    exit 1
fi

# =============================================================================
# Create Repositories
# =============================================================================

create_repo() {
    local name=$1
    local description=$2
    local public=${3:-true}

    echo -e "${YELLOW}Creating $ORG/$name...${NC}"

    if gh repo view "$ORG/$name" &> /dev/null; then
        echo "  Repository already exists, skipping"
    else
        gh repo create "$ORG/$name" \
            --description "$description" \
            --public \
            --clone=false
        echo -e "${GREEN}  ✓ Created${NC}"
    fi
}

# Main AIPTX repository (if not exists)
create_repo "aiptx" "AI-Powered Penetration Testing Framework"

# Node.js SDK repository
create_repo "aiptx-js" "AIPTX SDK for Node.js (@aiptx/sdk)"

# Go SDK repository
create_repo "aiptx-go" "AIPTX SDK for Go"

# Homebrew tap repository
create_repo "homebrew-tap" "Homebrew formulae for AIPTX"

echo ""

# =============================================================================
# Initialize Homebrew Tap
# =============================================================================

echo -e "${YELLOW}Initializing Homebrew tap...${NC}"

TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

gh repo clone "$ORG/homebrew-tap" 2>/dev/null || true
cd homebrew-tap

# Create Formula directory
mkdir -p Formula

# Copy formula
cp "$(dirname "$0")/../sdks/homebrew/aiptx.rb" Formula/ 2>/dev/null || true

# Create README
cat > README.md << 'EOF'
# AIPTX Homebrew Tap

Official Homebrew tap for [AIPTX](https://aiptx.io) - AI-Powered Penetration Testing Framework.

## Installation

```bash
brew tap aiptx/tap
brew install aiptx
```

## Formulae

| Formula | Description |
|---------|-------------|
| aiptx | AI-Powered Penetration Testing Framework |

## Requirements

- macOS 10.15+ or Linux
- Python 3.9+

## Links

- [AIPTX Documentation](https://aiptx.io/docs)
- [GitHub Repository](https://github.com/aiptx/aiptx)
- [PyPI Package](https://pypi.org/project/aiptx/)
EOF

git add -A
git commit -m "Initialize Homebrew tap" 2>/dev/null || true
git push 2>/dev/null || true

cd ..
rm -rf "$TEMP_DIR"

echo -e "${GREEN}✓ Homebrew tap initialized${NC}"
echo ""

# =============================================================================
# Initialize Go Module
# =============================================================================

echo -e "${YELLOW}Initializing Go module repository...${NC}"

TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

gh repo clone "$ORG/aiptx-go" 2>/dev/null || true
cd aiptx-go

# Copy Go SDK files
cp "$(dirname "$0")/../sdks/go/"* . 2>/dev/null || true

git add -A
git commit -m "Initial Go SDK" 2>/dev/null || true
git push 2>/dev/null || true

cd ..
rm -rf "$TEMP_DIR"

echo -e "${GREEN}✓ Go module initialized${NC}"
echo ""

# =============================================================================
# Summary
# =============================================================================

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Created/verified repositories:"
echo "  • $ORG/aiptx          - Main repository"
echo "  • $ORG/aiptx-js       - Node.js SDK"
echo "  • $ORG/aiptx-go       - Go SDK"
echo "  • $ORG/homebrew-tap   - Homebrew formulae"
echo ""
echo "Next steps:"
echo "  1. Add secrets to GitHub repository settings:"
echo "     - PYPI_API_TOKEN"
echo "     - NPM_TOKEN"
echo "     - DOCKERHUB_USERNAME"
echo "     - DOCKERHUB_TOKEN"
echo "     - HOMEBREW_TAP_TOKEN"
echo ""
echo "  2. Create Docker Hub repository:"
echo "     https://hub.docker.com/repository/create"
echo "     Name: aiptx/aiptx"
echo ""
echo "  3. Create npm organization:"
echo "     https://www.npmjs.com/org/create"
echo "     Name: @aiptx"
echo ""
echo "  4. Run publish script:"
echo "     ./scripts/publish.sh 2.0.6"
echo ""
