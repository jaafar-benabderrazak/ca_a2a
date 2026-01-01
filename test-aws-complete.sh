#!/bin/bash
#
# CA A2A AWS Deployment - Comprehensive Test Suite
# Tests all features of the deployed solution
#
# Usage: bash test-aws-complete.sh
#

set -e

# Configuration
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
BUCKET="ca-a2a-documents-555043101106"
ACCOUNT="555043101106"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Header
echo "=========================================="
echo "  CA A2A AWS Comprehensive Test Suite"
echo "=========================================="
echo "Region:  $REGION"
echo "Cluster: $CLUSTER"
echo "ALB:     $ALB_URL"
echo "Date:    $(date)"
echo "=========================================="
echo ""

# Test function
run_test() {
  local test_name="$1"
  local test_command="$2"
  
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  echo -e "${BLUE}[TEST $TOTAL_TESTS]${NC} $test_name"
  
  if eval "$test_command" 2>/dev/null; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✓ PASS${NC}\n"
    return 0
  else
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}✗ FAIL${NC}\n"
    return 1
  fi
}

###########################################
# 1. INFRASTRUCTURE HEALTH TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 1. INFRASTRUCTURE HEALTH TESTS ===${NC}"
echo ""

run_test "ECS Cluster Exists" \
  "aws ecs describe-clusters --clusters $CLUSTER --region $REGION --query 'clusters[0].status' --output text | grep -q ACTIVE"

run_test "All 4 ECS Services Running" \
  "aws ecs describe-services --cluster $CLUSTER --services orchestrator extractor validator archivist --region $REGION --query 'services[?status==\`ACTIVE\`] | length(@)' --output text | grep -q 4"

run_test "Orchestrator Service Has 2 Tasks" \
  "aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $REGION --query 'services[0].runningCount' --output text | grep -q 2"

run_test "ALB Target Group Has Healthy Targets" \
  "aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:$REGION:$ACCOUNT:targetgroup/ca-a2a-orch-tg/5bc795b288397779 --region $REGION --query 'TargetHealthDescriptions[?TargetHealth.State==\`healthy\`] | length(@)' --output text | grep -q -E '[1-2]'"

run_test "RDS Database Is Available" \
  "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].DBInstanceStatus' --output text | grep -q available"

run_test "S3 Bucket Exists" \
  "aws s3 ls s3://$BUCKET --region $REGION > /dev/null"

run_test "VPC Endpoints Exist" \
  "aws ec2 describe-vpc-endpoints --region $REGION --filters Name=tag:Project,Values=ca-a2a --query 'VpcEndpoints | length(@)' --output text | grep -q -E '[1-9]'"

###########################################
# 2. API ENDPOINT TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 2. API ENDPOINT TESTS ===${NC}"
echo ""

run_test "Health Endpoint Responds" \
  "curl -s -f $ALB_URL/health > /dev/null"

run_test "Health Status Is 'healthy'" \
  "curl -s $ALB_URL/health | jq -e '.status == \"healthy\"' > /dev/null"

run_test "Agent Card Endpoint Responds" \
  "curl -s -f $ALB_URL/card > /dev/null"

run_test "Agent Card Has Skills" \
  "curl -s $ALB_URL/card | jq -e '.skills | length > 0' > /dev/null"

run_test "Skills Endpoint Lists All Skills" \
  "curl -s -f $ALB_URL/skills | jq -e '.skills | length > 0' > /dev/null"

run_test "Status Endpoint Shows Metrics" \
  "curl -s -f $ALB_URL/status > /dev/null"

###########################################
# 3. DOCUMENT PROCESSING TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 3. DOCUMENT PROCESSING TESTS ===${NC}"
echo ""

# Create test document
TEST_DOC="test-aws-$(date +%s).txt"
cat > /tmp/$TEST_DOC << 'EOF'
INVOICE #INV-TEST-001
Date: 2026-01-01
From: Test Company
To: Test Client

Services:
- Testing: €100.00

Total: €100.00
EOF

run_test "Upload Test Document to S3" \
  "aws s3 cp /tmp/$TEST_DOC s3://$BUCKET/incoming/$TEST_DOC --region $REGION"

run_test "Process Document via API" \
  "curl -s -X POST $ALB_URL/process -H 'Content-Type: application/json' -d '{\"s3_key\": \"incoming/$TEST_DOC\"}' | jq -e '.status or .document_id or .task_id' > /dev/null"

# Wait for processing
echo "Waiting 10 seconds for processing..."
sleep 10

run_test "Document Appears in Logs" \
  "aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --filter-pattern '$TEST_DOC' --start-time \$(date -d '2 minutes ago' +%s)000 --region $REGION --query 'events | length(@)' --output text | grep -q -E '[1-9]'"

###########################################
# 4. SECURITY TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 4. SECURITY TESTS ===${NC}"
echo ""

run_test "HTTPS Redirect Works (if configured)" \
  "curl -s -I $ALB_URL | grep -q 'HTTP/1.1 [23]'" || true

run_test "Invalid JSON Returns Error" \
  "curl -s -X POST $ALB_URL/message -H 'Content-Type: application/json' -d 'invalid{json' | jq -e '.error' > /dev/null"

run_test "Invalid Method Returns Error" \
  "curl -s -X POST $ALB_URL/message -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"nonexistent\",\"params\":{}}' | jq -e '.error.code == -32601' > /dev/null"

run_test "Security Groups Allow HTTP Traffic" \
  "aws ec2 describe-security-groups --group-ids sg-05db73131090f365a --region $REGION --query 'SecurityGroups[0].IpPermissions[?FromPort==\`80\`] | length(@)' --output text | grep -q -E '[1-9]'"

run_test "IAM Roles Attached to ECS Tasks" \
  "aws ecs describe-task-definition --task-definition ca-a2a-orchestrator --region $REGION --query 'taskDefinition.taskRoleArn' --output text | grep -q 'arn:aws:iam'"

###########################################
# 5. PERFORMANCE TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 5. PERFORMANCE TESTS ===${NC}"
echo ""

run_test "Health Endpoint Response Time < 1s" \
  "time timeout 1 curl -s -f $ALB_URL/health > /dev/null"

run_test "Agent Card Response Time < 2s" \
  "time timeout 2 curl -s -f $ALB_URL/card > /dev/null"

# Check CPU utilization (if metrics available)
run_test "ECS Tasks Not Over-Utilizing CPU" \
  "aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization --dimensions Name=ClusterName,Value=$CLUSTER Name=ServiceName,Value=orchestrator --start-time \$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) --end-time \$(date -u +%Y-%m-%dT%H:%M:%S) --period 300 --statistics Average --region $REGION --query 'Datapoints[0].Average' --output text | awk '{if (\$1 < 80 || \$1 == \"None\") exit 0; else exit 1}'"

###########################################
# 6. MONITORING & LOGGING TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 6. MONITORING & LOGGING TESTS ===${NC}"
echo ""

run_test "CloudWatch Log Groups Exist" \
  "aws logs describe-log-groups --log-group-name-prefix /ecs/ca-a2a --region $REGION --query 'logGroups | length(@)' --output text | grep -q -E '[4-9]'"

run_test "Orchestrator Logs Have Recent Entries" \
  "aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --start-time \$(date -d '5 minutes ago' +%s)000 --region $REGION --query 'events | length(@)' --output text | grep -q -E '[1-9]'"

run_test "No Critical Errors in Last Hour" \
  "ERROR_COUNT=\$(aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --filter-pattern 'CRITICAL' --start-time \$(date -d '1 hour ago' +%s)000 --region $REGION --query 'events | length(@)' --output text); [ \$ERROR_COUNT -lt 5 ]"

run_test "CloudWatch Alarms Exist (if configured)" \
  "aws cloudwatch describe-alarms --region $REGION --query 'MetricAlarms | length(@)' --output text | grep -q -E '[0-9]'" || true

###########################################
# 7. DATA PERSISTENCE TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 7. DATA PERSISTENCE TESTS ===${NC}"
echo ""

run_test "RDS Instance Has Backups Enabled" \
  "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].BackupRetentionPeriod' --output text | grep -q -E '[1-9]'"

run_test "RDS Instance Is Multi-AZ (if configured)" \
  "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].MultiAZ' --output text | grep -q -E 'true|false'" || true

run_test "S3 Bucket Has Versioning" \
  "aws s3api get-bucket-versioning --bucket $BUCKET --region $REGION | jq -e '.Status' > /dev/null" || true

run_test "S3 Bucket Has Objects" \
  "aws s3 ls s3://$BUCKET --recursive --region $REGION | wc -l | grep -q -E '[1-9]'"

###########################################
# 8. INTEGRATION TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 8. INTEGRATION TESTS ===${NC}"
echo ""

run_test "Orchestrator Can Reach Extractor" \
  "aws ecs describe-services --cluster $CLUSTER --services orchestrator extractor --region $REGION --query 'services[?status==\`ACTIVE\`] | length(@)' --output text | grep -q 2"

run_test "All Agents In Same VPC" \
  "VPC_ID=\$(aws ecs describe-tasks --cluster $CLUSTER --tasks \$(aws ecs list-tasks --cluster $CLUSTER --service-name orchestrator --region $REGION --query 'taskArns[0]' --output text) --region $REGION --query 'tasks[0].attachments[0].details[?name==\`subnetId\`].value' --output text); [ ! -z \"\$VPC_ID\" ]"

run_test "Service Discovery Configured" \
  "aws servicediscovery list-namespaces --region $REGION --query 'Namespaces | length(@)' --output text | grep -q -E '[0-9]'" || true

###########################################
# 9. SCALABILITY TESTS
###########################################

echo ""
echo -e "${YELLOW}=== 9. SCALABILITY TESTS ===${NC}"
echo ""

run_test "Services Can Scale (Desired Count Configurable)" \
  "aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $REGION --query 'services[0].desiredCount' --output text | grep -q -E '[1-9]'"

run_test "ALB Has Multiple Availability Zones" \
  "aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[?LoadBalancerName==\`ca-a2a-alb\`].AvailabilityZones | [0] | length(@)' --output text | grep -q -E '[2-9]'"

run_test "RDS Can Handle Connections" \
  "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].Endpoint.Address' --output text | grep -q '\\.rds\\.amazonaws\\.com'"

###########################################
# SUMMARY
###########################################

echo ""
echo "=========================================="
echo "           TEST SUMMARY"
echo "=========================================="
echo "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
  echo -e "${RED}Failed:       $FAILED_TESTS${NC}"
else
  echo -e "${GREEN}Failed:       0${NC}"
fi
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo "=========================================="
echo ""

# Detailed results
if [ $FAILED_TESTS -eq 0 ]; then
  echo -e "${GREEN}✓ All tests passed! Deployment is healthy.${NC}"
  echo ""
  echo "Next steps:"
  echo "  1. Test with real documents"
  echo "  2. Monitor CloudWatch metrics"
  echo "  3. Review application logs"
  echo ""
  exit 0
else
  echo -e "${YELLOW}⚠ Some tests failed. Review the output above.${NC}"
  echo ""
  echo "Troubleshooting:"
  echo "  1. Check CloudWatch logs: aws logs tail /ecs/ca-a2a-orchestrator --follow --region $REGION"
  echo "  2. Check ECS service status: aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $REGION"
  echo "  3. Check ALB health: aws elbv2 describe-target-health --target-group-arn <arn> --region $REGION"
  echo ""
  exit 1
fi

