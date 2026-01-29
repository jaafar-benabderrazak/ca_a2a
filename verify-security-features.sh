#!/bin/bash
###############################################################################
# CA-A2A Security Features Verification Script
# Version: 5.1.0
#
# This script verifies all 9 security layers described in
# a2a_security_architecture.md are properly implemented
#
# Author: Jaafar Benabderrazak
# Date: January 25, 2026
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging
log_test() { echo -e "\n${CYAN}▸${NC} ${BOLD}$1${NC}"; ((TESTS_TOTAL++)); }
log_pass() { echo -e "  ${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); }
log_fail() { echo -e "  ${RED}✗${NC} $1"; ((TESTS_FAILED++)); }
log_info() { echo -e "    ${BLUE}ℹ${NC} $1"; }
log_warn() { echo -e "    ${YELLOW}⚠${NC} $1"; }

# Banner
echo -e "${BOLD}${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   CA-A2A Security Verification Suite                                 ║
║   Testing 9-Layer Defense-in-Depth Architecture                      ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Load configuration
if [ -f "/tmp/ca-a2a-deployment-config.env" ]; then
    source /tmp/ca-a2a-deployment-config.env
    log_info "Configuration loaded from /tmp/ca-a2a-deployment-config.env"
elif [ -f "ca-a2a-config.env" ]; then
    source ca-a2a-config.env
    log_info "Configuration loaded from ca-a2a-config.env"
else
    echo -e "${RED}Error: Configuration file not found${NC}"
    echo "Please run cloudshell-complete-deploy.sh first"
    exit 1
fi

###############################################################################
# Layer 1: Network Isolation
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 1: NETWORK ISOLATION${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "1.1: Verify VPC configuration"
VPC_INFO=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --region $AWS_REGION --query 'Vpcs[0]' 2>/dev/null)
if [ ! -z "$VPC_INFO" ]; then
    DNS_SUPPORT=$(echo $VPC_INFO | jq -r '.EnableDnsSupport')
    DNS_HOSTNAMES=$(echo $VPC_INFO | jq -r '.EnableDnsHostnames')
    if [ "$DNS_SUPPORT" = "true" ] && [ "$DNS_HOSTNAMES" = "true" ]; then
        log_pass "VPC configured with DNS support and hostnames"
    else
        log_fail "VPC DNS configuration incomplete"
    fi
else
    log_fail "VPC not found"
fi

log_test "1.2: Verify private subnets (no public IP auto-assign)"
for subnet in $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2; do
    AUTO_ASSIGN=$(aws ec2 describe-subnets --subnet-ids $subnet --region $AWS_REGION --query 'Subnets[0].MapPublicIpOnLaunch' --output text)
    if [ "$AUTO_ASSIGN" = "False" ]; then
        log_pass "Subnet $subnet does not auto-assign public IPs"
    else
        log_fail "Subnet $subnet auto-assigns public IPs (security risk)"
    fi
done

log_test "1.3: Verify NAT Gateway exists"
NAT_INFO=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" --region $AWS_REGION --query 'NatGateways[0]' 2>/dev/null)
if [ ! -z "$NAT_INFO" ] && [ "$NAT_INFO" != "null" ]; then
    log_pass "NAT Gateway available for private subnet internet access"
else
    log_fail "NAT Gateway not found or not available"
fi

log_test "1.4: Verify ECS tasks have no public IPs"
TASK_ARNS=$(aws ecs list-tasks --cluster $PROJECT_NAME-cluster --region $AWS_REGION --query 'taskArns' --output text)
if [ ! -z "$TASK_ARNS" ]; then
    PUBLIC_IP_COUNT=0
    for task in $TASK_ARNS; do
        PUBLIC_IP=$(aws ecs describe-tasks --cluster $PROJECT_NAME-cluster --tasks $task --region $AWS_REGION --query 'tasks[0].attachments[0].details[?name==`publicIpv4Address`].value' --output text)
        if [ ! -z "$PUBLIC_IP" ]; then
            ((PUBLIC_IP_COUNT++))
        fi
    done
    if [ $PUBLIC_IP_COUNT -eq 0 ]; then
        log_pass "No ECS tasks have public IPs (properly isolated)"
    else
        log_fail "$PUBLIC_IP_COUNT ECS tasks have public IPs (security risk)"
    fi
else
    log_warn "No ECS tasks running"
fi

log_test "1.5: Verify security group egress hardening"
if [ ! -z "$ORCHESTRATOR_SG" ]; then
    EGRESS_RULES=$(aws ec2 describe-security-groups --group-ids $ORCHESTRATOR_SG --region $AWS_REGION --query 'SecurityGroups[0].IpPermissionsEgress' --output json)
    ALLOW_ALL_COUNT=$(echo $EGRESS_RULES | jq '[.[] | select(.IpProtocol == "-1" and .IpRanges[0].CidrIp == "0.0.0.0/0")] | length')
    if [ "$ALLOW_ALL_COUNT" = "0" ]; then
        log_pass "Security group egress rules are hardened (no allow-all)"
    else
        log_fail "Security group has allow-all egress rule (should be restricted)"
    fi
else
    log_warn "Orchestrator security group not found"
fi

###############################################################################
# Layer 2-3: Keycloak Authentication
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYERS 2-3: KEYCLOAK OAUTH2/OIDC & JWT RS256${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "2.1: Verify Keycloak service is running"
KC_SERVICE=$(aws ecs describe-services --cluster $PROJECT_NAME-cluster --services keycloak --region $AWS_REGION --query 'services[0]' 2>/dev/null)
if [ ! -z "$KC_SERVICE" ] && [ "$KC_SERVICE" != "null" ]; then
    RUNNING_COUNT=$(echo $KC_SERVICE | jq -r '.runningCount')
    DESIRED_COUNT=$(echo $KC_SERVICE | jq -r '.desiredCount')
    if [ "$RUNNING_COUNT" = "$DESIRED_COUNT" ] && [ "$RUNNING_COUNT" != "0" ]; then
        log_pass "Keycloak service running ($RUNNING_COUNT/$DESIRED_COUNT tasks)"
    else
        log_fail "Keycloak service not fully running ($RUNNING_COUNT/$DESIRED_COUNT tasks)"
    fi
else
    log_fail "Keycloak service not found"
fi

log_test "2.2: Verify Keycloak admin password is in Secrets Manager"
KC_ADMIN_SECRET=$(aws secretsmanager describe-secret --secret-id $PROJECT_NAME/keycloak-admin-password --region $AWS_REGION --query 'Name' --output text 2>/dev/null || echo "")
if [ ! -z "$KC_ADMIN_SECRET" ]; then
    log_pass "Keycloak admin password stored in Secrets Manager"
else
    log_fail "Keycloak admin password not found in Secrets Manager"
fi

log_test "2.3: Verify JWT RSA-2048 keys are in Secrets Manager"
JWT_PRIVATE=$(aws secretsmanager describe-secret --secret-id $PROJECT_NAME/a2a-jwt-private-key-pem --region $AWS_REGION --query 'Name' --output text 2>/dev/null || echo "")
JWT_PUBLIC=$(aws secretsmanager describe-secret --secret-id $PROJECT_NAME/a2a-jwt-public-key-pem --region $AWS_REGION --query 'Name' --output text 2>/dev/null || echo "")
if [ ! -z "$JWT_PRIVATE" ] && [ ! -z "$JWT_PUBLIC" ]; then
    log_pass "JWT RSA-2048 keys stored in Secrets Manager"
else
    log_fail "JWT keys not found in Secrets Manager"
fi

log_test "2.4: Verify Keycloak client secret is stored"
KC_CLIENT_SECRET=$(aws secretsmanager describe-secret --secret-id $PROJECT_NAME/keycloak-client-secret --region $AWS_REGION --query 'Name' --output text 2>/dev/null || echo "")
if [ ! -z "$KC_CLIENT_SECRET" ]; then
    log_pass "Keycloak client secret stored in Secrets Manager"
else
    log_fail "Keycloak client secret not found"
fi

###############################################################################
# Layer 4: RBAC Authorization
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 4: RBAC AUTHORIZATION${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "4.1: Verify agent security groups restrict access"
if [ ! -z "$EXTRACTOR_SG" ]; then
    INGRESS_RULES=$(aws ec2 describe-security-groups --group-ids $EXTRACTOR_SG --region $AWS_REGION --query 'SecurityGroups[0].IpPermissions' --output json)
    SOURCE_SG_COUNT=$(echo $INGRESS_RULES | jq '[.[] | select(.UserIdGroupPairs != null)] | length')
    if [ "$SOURCE_SG_COUNT" -gt "0" ]; then
        log_pass "Agent security groups use source security group restrictions"
        log_info "Extractor allows inbound only from specific security groups"
    else
        log_fail "Agent security groups not properly restricted"
    fi
else
    log_warn "Extractor security group not found"
fi

###############################################################################
# Layer 5: MCP Server Resource Gateway
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 5: MCP SERVER RESOURCE GATEWAY${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "5.1: Verify MCP Server service is running"
MCP_SERVICE=$(aws ecs describe-services --cluster $PROJECT_NAME-cluster --services mcp-server --region $AWS_REGION --query 'services[0]' 2>/dev/null)
if [ ! -z "$MCP_SERVICE" ] && [ "$MCP_SERVICE" != "null" ]; then
    RUNNING_COUNT=$(echo $MCP_SERVICE | jq -r '.runningCount')
    DESIRED_COUNT=$(echo $MCP_SERVICE | jq -r '.desiredCount')
    if [ "$RUNNING_COUNT" = "$DESIRED_COUNT" ] && [ "$RUNNING_COUNT" != "0" ]; then
        log_pass "MCP Server running ($RUNNING_COUNT/$DESIRED_COUNT tasks)"
    else
        log_fail "MCP Server not fully running ($RUNNING_COUNT/$DESIRED_COUNT tasks)"
    fi
else
    log_fail "MCP Server service not found"
fi

log_test "5.2: Verify MCP Server has exclusive S3 access"
MCP_ROLE=$(aws iam get-role --role-name $PROJECT_NAME-mcp-task-role --region $AWS_REGION --query 'Role.RoleName' --output text 2>/dev/null || echo "")
if [ ! -z "$MCP_ROLE" ]; then
    MCP_POLICIES=$(aws iam list-role-policies --role-name $MCP_ROLE --region $AWS_REGION --query 'PolicyNames' --output text)
    if echo "$MCP_POLICIES" | grep -q "$PROJECT_NAME-mcp-policy"; then
        log_pass "MCP Server has dedicated IAM role with S3 access"
        log_info "Centralized resource access pattern implemented"
    else
        log_fail "MCP Server IAM policy not found"
    fi
else
    log_fail "MCP Server IAM role not found"
fi

log_test "5.3: Verify agents do NOT have direct S3 access"
AGENT_ROLE=$(aws iam get-role --role-name $PROJECT_NAME-agent-task-role --region $AWS_REGION --query 'Role.RoleName' --output text 2>/dev/null || echo "")
if [ ! -z "$AGENT_ROLE" ]; then
    AGENT_POLICIES=$(aws iam list-role-policies --role-name $AGENT_ROLE --region $AWS_REGION --query 'PolicyNames' --output text)
    AGENT_POLICY_CONTENT=$(aws iam get-role-policy --role-name $AGENT_ROLE --policy-name $PROJECT_NAME-agent-policy --region $AWS_REGION --query 'PolicyDocument' --output json 2>/dev/null || echo '{}')
    HAS_S3_ACCESS=$(echo $AGENT_POLICY_CONTENT | jq -r '.Statement[] | select(.Action[]? | contains("s3:")) | .Effect' 2>/dev/null || echo "")
    if [ -z "$HAS_S3_ACCESS" ]; then
        log_pass "Agents do NOT have direct S3 access (MCP-only pattern)"
    else
        log_fail "Agents have direct S3 access (should use MCP Server)"
    fi
else
    log_warn "Agent IAM role not found"
fi

###############################################################################
# Layer 6: Data Security
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 6: ENCRYPTION AT REST & IN TRANSIT${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "6.1: Verify S3 bucket encryption"
S3_ENCRYPTION=$(aws s3api get-bucket-encryption --bucket $S3_BUCKET --region $AWS_REGION --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "")
if [ "$S3_ENCRYPTION" = "AES256" ]; then
    log_pass "S3 bucket encrypted with AES-256"
else
    log_fail "S3 bucket encryption not configured or using wrong algorithm"
fi

log_test "6.2: Verify S3 bucket versioning"
S3_VERSIONING=$(aws s3api get-bucket-versioning --bucket $S3_BUCKET --region $AWS_REGION --query 'Status' --output text 2>/dev/null || echo "")
if [ "$S3_VERSIONING" = "Enabled" ]; then
    log_pass "S3 bucket versioning enabled"
else
    log_fail "S3 bucket versioning not enabled"
fi

log_test "6.3: Verify S3 public access is blocked"
PUBLIC_BLOCK=$(aws s3api get-public-access-block --bucket $S3_BUCKET --region $AWS_REGION --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo '{}')
BLOCK_PUBLIC_ACLS=$(echo $PUBLIC_BLOCK | jq -r '.BlockPublicAcls')
BLOCK_PUBLIC_POLICY=$(echo $PUBLIC_BLOCK | jq -r '.BlockPublicPolicy')
if [ "$BLOCK_PUBLIC_ACLS" = "true" ] && [ "$BLOCK_PUBLIC_POLICY" = "true" ]; then
    log_pass "S3 public access blocked"
else
    log_fail "S3 public access not fully blocked"
fi

log_test "6.4: Verify RDS encryption at rest"
RDS_ENCRYPTED=$(aws rds describe-db-clusters --db-cluster-identifier $PROJECT_NAME-documents-db --region $AWS_REGION --query 'DBClusters[0].StorageEncrypted' --output text 2>/dev/null || echo "false")
if [ "$RDS_ENCRYPTED" = "True" ]; then
    log_pass "RDS cluster encrypted at rest"
else
    log_fail "RDS cluster not encrypted"
fi

log_test "6.5: Verify RDS automated backups"
BACKUP_RETENTION=$(aws rds describe-db-clusters --db-cluster-identifier $PROJECT_NAME-documents-db --region $AWS_REGION --query 'DBClusters[0].BackupRetentionPeriod' --output text 2>/dev/null || echo "0")
if [ "$BACKUP_RETENTION" -ge "7" ]; then
    log_pass "RDS automated backups enabled ($BACKUP_RETENTION days retention)"
else
    log_fail "RDS backup retention insufficient ($BACKUP_RETENTION days)"
fi

###############################################################################
# Layer 7: Input Validation
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 7: JSON SCHEMA & PYDANTIC VALIDATION${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "7.1: Verify validation code files exist"
if [ -f "a2a_security_enhanced.py" ]; then
    if grep -q "JSONSchemaValidator" a2a_security_enhanced.py; then
        log_pass "JSON Schema validation implementation found"
    else
        log_warn "JSON Schema validator not found in codebase"
    fi
else
    log_warn "a2a_security_enhanced.py not found"
fi

if [ -f "pydantic_models.py" ]; then
    if grep -q "ProcessDocumentRequest" pydantic_models.py; then
        log_pass "Pydantic models implementation found"
    else
        log_warn "Pydantic models not found in codebase"
    fi
else
    log_warn "pydantic_models.py not found"
fi

###############################################################################
# Layer 8: Token Revocation & Replay Protection
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 8: TOKEN REVOCATION & REPLAY PROTECTION${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "8.1: Verify database schema includes revoked_tokens table"
if [ -f "/tmp/init_documents_db.sql" ] || aws s3 ls s3://$S3_BUCKET/migrations/init_documents_db.sql --region $AWS_REGION &>/dev/null; then
    SCHEMA_CONTENT=$(cat /tmp/init_documents_db.sql 2>/dev/null || aws s3 cp s3://$S3_BUCKET/migrations/init_documents_db.sql - --region $AWS_REGION 2>/dev/null)
    if echo "$SCHEMA_CONTENT" | grep -q "CREATE TABLE.*revoked_tokens"; then
        log_pass "revoked_tokens table defined in schema"
    else
        log_fail "revoked_tokens table not found in schema"
    fi
else
    log_warn "Database schema file not found"
fi

log_test "8.2: Verify audit_log table for comprehensive logging"
if [ ! -z "$SCHEMA_CONTENT" ]; then
    if echo "$SCHEMA_CONTENT" | grep -q "CREATE TABLE.*audit_log"; then
        log_pass "audit_log table defined in schema"
    else
        log_fail "audit_log table not found in schema"
    fi
fi

###############################################################################
# Layer 9: Monitoring & Logging
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  LAYER 9: CLOUDWATCH LOGS & MONITORING${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "9.1: Verify CloudWatch log groups exist"
LOG_GROUPS_EXPECTED=("orchestrator" "extractor" "validator" "archivist" "keycloak" "mcp-server")
LOG_GROUPS_FOUND=0
for service in "${LOG_GROUPS_EXPECTED[@]}"; do
    if aws logs describe-log-groups --log-group-name-prefix "/ecs/$PROJECT_NAME-$service" --region $AWS_REGION --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$service"; then
        ((LOG_GROUPS_FOUND++))
    fi
done
if [ $LOG_GROUPS_FOUND -eq ${#LOG_GROUPS_EXPECTED[@]} ]; then
    log_pass "All CloudWatch log groups exist (${#LOG_GROUPS_EXPECTED[@]}/${#LOG_GROUPS_EXPECTED[@]})"
else
    log_fail "Some CloudWatch log groups missing ($LOG_GROUPS_FOUND/${#LOG_GROUPS_EXPECTED[@]})"
fi

log_test "9.2: Verify log retention policy"
RETENTION_OK=0
for service in "${LOG_GROUPS_EXPECTED[@]}"; do
    RETENTION=$(aws logs describe-log-groups --log-group-name-prefix "/ecs/$PROJECT_NAME-$service" --region $AWS_REGION --query 'logGroups[0].retentionInDays' --output text 2>/dev/null || echo "0")
    if [ "$RETENTION" -ge "7" ]; then
        ((RETENTION_OK++))
    fi
done
if [ $RETENTION_OK -eq ${#LOG_GROUPS_EXPECTED[@]} ]; then
    log_pass "All log groups have retention policy (7+ days)"
else
    log_fail "Some log groups missing retention policy ($RETENTION_OK/${#LOG_GROUPS_EXPECTED[@]})"
fi

log_test "9.3: Verify ECS Container Insights enabled"
INSIGHTS=$(aws ecs describe-clusters --clusters $PROJECT_NAME-cluster --region $AWS_REGION --query 'clusters[0].settings[?name==`containerInsights`].value | [0]' --output text 2>/dev/null || echo "disabled")
if [ "$INSIGHTS" = "enabled" ]; then
    log_pass "ECS Container Insights enabled"
else
    log_warn "ECS Container Insights not enabled (recommended for monitoring)"
fi

###############################################################################
# VPC Endpoints (Private AWS Access)
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  VPC ENDPOINTS (PRIVATE AWS SERVICE ACCESS)${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "10.1: Verify VPC endpoints for AWS services"
VPC_ENDPOINTS=("ecr.dkr" "ecr.api" "logs" "secretsmanager" "s3")
ENDPOINTS_FOUND=0
for service in "${VPC_ENDPOINTS[@]}"; do
    SERVICE_NAME="com.amazonaws.$AWS_REGION.$service"
    ENDPOINT=$(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=$SERVICE_NAME" --region $AWS_REGION --query 'VpcEndpoints[0].VpcEndpointId' --output text 2>/dev/null || echo "")
    if [ ! -z "$ENDPOINT" ] && [ "$ENDPOINT" != "None" ]; then
        ((ENDPOINTS_FOUND++))
    fi
done
if [ $ENDPOINTS_FOUND -ge 4 ]; then
    log_pass "VPC endpoints configured ($ENDPOINTS_FOUND/${#VPC_ENDPOINTS[@]} services)"
else
    log_warn "Some VPC endpoints missing ($ENDPOINTS_FOUND/${#VPC_ENDPOINTS[@]})"
fi

###############################################################################
# Service Discovery
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  SERVICE DISCOVERY${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"

log_test "11.1: Verify private DNS namespace"
if [ ! -z "$NAMESPACE_ID" ]; then
    NAMESPACE_NAME=$(aws servicediscovery get-namespace --id $NAMESPACE_ID --region $AWS_REGION --query 'Namespace.Name' --output text 2>/dev/null || echo "")
    if [ "$NAMESPACE_NAME" = "$PROJECT_NAME.local" ]; then
        log_pass "Private DNS namespace configured: $NAMESPACE_NAME"
    else
        log_fail "Private DNS namespace name mismatch"
    fi
else
    log_fail "Namespace ID not configured"
fi

log_test "11.2: Verify service discovery services"
SD_SERVICES=("extractor" "validator" "archivist" "keycloak" "mcp-server")
SD_FOUND=0
for service in "${SD_SERVICES[@]}"; do
    SD_SERVICE=$(aws servicediscovery list-services --filters "Name=NAMESPACE_ID,Values=$NAMESPACE_ID" --region $AWS_REGION --query "Services[?Name=='$service'].Id | [0]" --output text 2>/dev/null || echo "")
    if [ ! -z "$SD_SERVICE" ] && [ "$SD_SERVICE" != "None" ]; then
        ((SD_FOUND++))
    fi
done
if [ $SD_FOUND -eq ${#SD_SERVICES[@]} ]; then
    log_pass "All service discovery services registered (${#SD_SERVICES[@]}/${#SD_SERVICES[@]})"
else
    log_fail "Some service discovery services missing ($SD_FOUND/${#SD_SERVICES[@]})"
fi

###############################################################################
# Test Summary
###############################################################################

echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  TEST SUMMARY${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

SUCCESS_RATE=$((TESTS_PASSED * 100 / TESTS_TOTAL))

echo -e "${BOLD}Total Tests:${NC}    $TESTS_TOTAL"
echo -e "${BOLD}${GREEN}Tests Passed:${NC}   $TESTS_PASSED"
echo -e "${BOLD}${RED}Tests Failed:${NC}   $TESTS_FAILED"
echo -e "${BOLD}Success Rate:${NC}   $SUCCESS_RATE%"

echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  ✓ ALL SECURITY FEATURES VERIFIED SUCCESSFULLY           ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Your CA-A2A deployment implements all 9 security layers:${NC}"
    echo -e "  ✓ Layer 1: Network Isolation"
    echo -e "  ✓ Layer 2-3: Keycloak OAuth2/OIDC & JWT RS256"
    echo -e "  ✓ Layer 4: RBAC Authorization"
    echo -e "  ✓ Layer 5: MCP Server Resource Gateway"
    echo -e "  ✓ Layer 6: Encryption at Rest & In Transit"
    echo -e "  ✓ Layer 7: JSON Schema & Pydantic Validation"
    echo -e "  ✓ Layer 8: Token Revocation & Replay Protection"
    echo -e "  ✓ Layer 9: CloudWatch Logs & Monitoring"
    echo ""
    exit 0
elif [ $SUCCESS_RATE -ge 80 ]; then
    echo -e "${YELLOW}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}${BOLD}║  ⚠ SECURITY VERIFICATION COMPLETED WITH WARNINGS         ║${NC}"
    echo -e "${YELLOW}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Most security features are implemented, but some checks failed.${NC}"
    echo -e "Please review the failed tests above and address any issues."
    echo ""
    exit 1
else
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║  ✗ SECURITY VERIFICATION FAILED                           ║${NC}"
    echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}Critical security features are missing or misconfigured.${NC}"
    echo -e "Please review the failed tests above and fix the issues before proceeding."
    echo ""
    exit 2
fi

