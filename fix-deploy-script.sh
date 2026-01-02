#!/bin/bash
# Quick fix for the deploy-archivist-fix.sh script
# Run this in CloudShell to update the script with the named port mapping

echo "Fixing deploy-archivist-fix.sh to include named port mapping..."

sed -i 's/"portMappings": \[{"containerPort": 8004, "protocol": "tcp"}\]/"portMappings": [{"containerPort": 8004, "protocol": "tcp", "name": "http"}]/' deploy-archivist-fix.sh

echo "✓ Script fixed!"
echo ""
echo "Now run:"
echo "  ./deploy-archivist-fix.sh"

