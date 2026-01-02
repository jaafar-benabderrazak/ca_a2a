#!/bin/bash
REGION="eu-west-3"
REPO="ca-a2a/extractor"

echo "============================================"
echo "CHECKING ECR IMAGES"
echo "============================================"
echo ""

echo "Images in ECR repository:"
aws ecr list-images \
    --repository-name ${REPO} \
    --region ${REGION} \
    --query 'imageIds[*].[imageTag,imagePushedAt]' \
    --output table | head -20

echo ""
echo "============================================"
echo "CHECKING LOCAL PYTHON SYNTAX"
echo "============================================"
echo ""

echo "Checking extractor_agent.py..."
python3 -m py_compile extractor_agent.py
if [ $? -eq 0 ]; then
    echo "  ✓ extractor_agent.py is VALID"
else
    echo "  ✗ extractor_agent.py has ERRORS"
    exit 1
fi

echo ""
echo "Checking mcp_context_auto.py..."
python3 -m py_compile mcp_context_auto.py
if [ $? -eq 0 ]; then
    echo "  ✓ mcp_context_auto.py is VALID"
else
    echo "  ✗ mcp_context_auto.py has ERRORS"
    exit 1
fi

echo ""
echo "============================================"
echo "CHECKING SPECIFIC LINES"
echo "============================================"
echo ""

echo "Line 313-315 of extractor_agent.py:"
sed -n '313,315p' extractor_agent.py | cat -A

echo ""
echo "Line 25-27 of mcp_context_auto.py:"
sed -n '25,27p' mcp_context_auto.py | cat -A

echo ""
echo "============================================"
echo "✓ CHECKS COMPLETE"
echo "============================================"

