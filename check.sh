#!/bin/bash
###############################################################################
# Prerequisite Checker for CA A2A Deployment
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Checking deployment prerequisites...${NC}\n"

READY=true

# Check AWS CLI
echo -n "AWS CLI: "
if command -v aws &> /dev/null; then
    VERSION=$(aws --version 2>&1 | head -1)
    echo -e "${GREEN}✓${NC} Found ($VERSION)"
else
    echo -e "${RED}✗ Not found${NC}"
    echo "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    READY=false
fi

# Check AWS credentials
echo -n "AWS Credentials: "
if aws sts get-caller-identity &> /dev/null; then
    ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    echo -e "${GREEN}✓${NC} Configured (Account: $ACCOUNT)"
else
    echo -e "${RED}✗ Not configured${NC}"
    echo "  Run: aws sso login  OR  aws configure"
    READY=false
fi

# Check Docker
echo -n "Docker: "
if command -v docker &> /dev/null; then
    if docker ps &> /dev/null 2>&1; then
        VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
        echo -e "${GREEN}✓${NC} Running (version $VERSION)"
    else
        echo -e "${YELLOW}⚠${NC} Found but not running"
        echo "  Start Docker Desktop or run: sudo systemctl start docker"
        echo "  (Infrastructure-only deployment still possible)"
    fi
else
    echo -e "${YELLOW}⚠${NC} Not found"
    echo "  Install: https://docs.docker.com/get-docker/"
    echo "  (Infrastructure-only deployment still possible)"
fi

# Check jq (optional)
echo -n "jq (optional): "
if command -v jq &> /dev/null; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (optional, makes output prettier)"
    echo "  Install: brew install jq  OR  sudo apt install jq"
fi

# Check openssl (for password generation)
echo -n "openssl: "
if command -v openssl &> /dev/null; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗${NC} Not found (required)"
    READY=false
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$READY" = true ]; then
    echo -e "${GREEN}✓ All required prerequisites met!${NC}"
    echo ""
    echo "You're ready to deploy. Run:"
    echo -e "  ${BLUE}./deploy.sh${NC}"
    echo ""
else
    echo -e "${RED}✗ Some required prerequisites are missing${NC}"
    echo ""
    echo "Please install the missing requirements above, then run:"
    echo -e "  ${BLUE}./check.sh${NC}"
    echo ""
    exit 1
fi

# Show next steps
echo "Deployment overview:"
echo "  1. The script will create all AWS infrastructure (~15 mins)"
echo "  2. Build and deploy Docker containers (~15 mins)"
echo "  3. You'll get an endpoint URL to test"
echo ""
echo "Estimated total time: 30 minutes"
echo "Estimated monthly cost: €150-180 (can be reduced to €80-100)"
echo ""
