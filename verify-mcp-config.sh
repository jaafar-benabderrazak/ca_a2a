#!/bin/bash
REGION="eu-west-3"

echo "============================================"
echo "MCP CONFIGURATION VERIFICATION"
echo "============================================"
echo ""

# Check Extractor
echo "1. Checking Extractor MCP configuration..."
EXT_MCP_URL=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-extractor \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`MCP_SERVER_URL`].value' \
    --output text 2>/dev/null)

if [ -z "$EXT_MCP_URL" ]; then
    echo "   ✅ Extractor: Using native MCP (no MCP_SERVER_URL)"
else
    echo "   ❌ Extractor: Using HTTP MCP (MCP_SERVER_URL=$EXT_MCP_URL)"
fi

# Check Archivist
echo ""
echo "2. Checking Archivist MCP configuration..."
ARCH_MCP_URL=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-archivist \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`MCP_SERVER_URL`].value' \
    --output text 2>/dev/null)

if [ -z "$ARCH_MCP_URL" ]; then
    echo "   ✅ Archivist: Using native MCP (no MCP_SERVER_URL)"
else
    echo "   ❌ Archivist: Using HTTP MCP (MCP_SERVER_URL=$ARCH_MCP_URL)"
fi

# Check for errors
echo ""
echo "3. Checking for recent MCP errors..."
MCP_ERRORS=$(aws logs tail /ecs/ca-a2a-extractor /ecs/ca-a2a-archivist --since 10m --region ${REGION} 2>/dev/null | grep -c "Cannot connect to host mcp-server\|RuntimeError: MCP stdio client")

if [ "$MCP_ERRORS" -eq 0 ]; then
    echo "   ✅ No MCP connection errors in last 10 minutes"
else
    echo "   ⚠️  Found $MCP_ERRORS connection errors (check if from old tasks)"
fi

# Check recent successful operations
echo ""
echo "4. Checking recent successful operations..."
RECENT_EXTRACT=$(aws logs tail /ecs/ca-a2a-extractor --since 5m --region ${REGION} 2>/dev/null | grep -c "Successfully extracted document")
RECENT_ARCHIVE=$(aws logs tail /ecs/ca-a2a-archivist --since 5m --region ${REGION} 2>/dev/null | grep -c "Successfully archived document")

echo "   Recent extractions: $RECENT_EXTRACT"
echo "   Recent archivings: $RECENT_ARCHIVE"

if [ "$RECENT_EXTRACT" -gt 0 ] && [ "$RECENT_ARCHIVE" -gt 0 ]; then
    echo "   ✅ Native MCP working correctly"
else
    echo "   ℹ️  No recent operations (agents may be idle)"
fi

echo ""
echo "============================================"
echo "VERIFICATION COMPLETE"
echo "============================================"

