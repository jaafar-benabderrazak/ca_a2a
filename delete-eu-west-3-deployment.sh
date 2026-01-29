#!/bin/bash
###############################################################################
# CA-A2A eu-west-3 Deployment Deletion Script
# This script removes ALL CA-A2A resources deployed in eu-west-3
# Date: January 29, 2026
# WARNING: This is a destructive operation and cannot be undone
###############################################################################

set -e

# Prevent Git Bash on Windows from converting paths
export MSYS_NO_PATHCONV=1

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
ACCOUNT_ID="555043101106"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "${CYAN}$1${NC}"; }

echo ""
log_header "==================================================================="
log_header "CA-A2A EU-WEST-3 DEPLOYMENT DELETION"
log_header "==================================================================="
echo "Region: $REGION"
echo "Account: $ACCOUNT_ID"
echo ""

###############################################################################
# PHASE 1: AUDIT CURRENT RESOURCES
###############################################################################

log_header "=== PHASE 1: AUDITING CURRENT RESOURCES ==="
echo ""

resource_count=0
resources_found=""

log_info "[1/15] Checking ECS Cluster..."
ecs_cluster=$(aws ecs describe-clusters --clusters ${PROJECT_NAME}-cluster --region $REGION --query 'clusters[0].clusterArn' --output text 2>/dev/null || echo "")
if [ ! -z "$ecs_cluster" ] && [ "$ecs_cluster" != "None" ]; then
    echo "  ✓ Found: $ecs_cluster"
    ((resource_count++))
    resources_found="$resources_found\n  - ECS Cluster"
fi

log_info "[2/15] Checking ECS Services..."
if [ ! -z "$ecs_cluster" ] && [ "$ecs_cluster" != "None" ]; then
    ecs_services=$(aws ecs list-services --cluster ${PROJECT_NAME}-cluster --region $REGION --query 'serviceArns' --output json 2>/dev/null | jq -r '.[]' 2>/dev/null || echo "")
    if [ ! -z "$ecs_services" ]; then
        service_count=$(echo "$ecs_services" | grep -c "service" || echo "0")
        if [ $service_count -gt 0 ]; then
            echo "  ✓ Found $service_count services:"
            echo "$ecs_services" | awk -F'/' '{print "    - " $NF}'
            ((resource_count+=$service_count))
            resources_found="$resources_found\n  - $service_count ECS Services"
        fi
    fi
fi

log_info "[3/15] Checking RDS Clusters..."
rds_clusters=$(aws rds describe-db-clusters --region $REGION --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`) || contains(DBClusterIdentifier, `documents-db`) || contains(DBClusterIdentifier, `keycloak`)].DBClusterIdentifier' --output text 2>/dev/null || echo "")
if [ ! -z "$rds_clusters" ]; then
    echo "  ✓ Found RDS clusters: $rds_clusters"
    cluster_count=$(echo "$rds_clusters" | wc -w)
    ((resource_count+=$cluster_count))
    resources_found="$resources_found\n  - $cluster_count RDS Clusters: $rds_clusters"
fi

log_info "[4/15] Checking S3 Buckets..."
s3_buckets=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `ca-a2a`)].Name' --output text 2>/dev/null || echo "")
if [ ! -z "$s3_buckets" ]; then
    echo "  ✓ Found S3 buckets: $s3_buckets"
    bucket_count=$(echo "$s3_buckets" | wc -w)
    ((resource_count+=$bucket_count))
    resources_found="$resources_found\n  - $bucket_count S3 Buckets: $s3_buckets"
fi

log_info "[5/15] Checking Load Balancers..."
albs=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].LoadBalancerArn' --output text 2>/dev/null || echo "")
if [ ! -z "$albs" ]; then
    alb_count=$(echo "$albs" | wc -w)
    echo "  ✓ Found $alb_count ALB(s)"
    ((resource_count+=$alb_count))
    resources_found="$resources_found\n  - $alb_count Application Load Balancer(s)"
fi

log_info "[6/15] Checking Target Groups..."
tgs=$(aws elbv2 describe-target-groups --region $REGION --query 'TargetGroups[?contains(TargetGroupName, `ca-a2a`)].TargetGroupArn' --output text 2>/dev/null || echo "")
if [ ! -z "$tgs" ]; then
    tg_count=$(echo "$tgs" | wc -w)
    echo "  ✓ Found $tg_count Target Group(s)"
    ((resource_count+=$tg_count))
    resources_found="$resources_found\n  - $tg_count Target Groups"
fi

log_info "[7/15] Checking ECR Repositories..."
ecr_repos=$(aws ecr describe-repositories --region $REGION --query 'repositories[?contains(repositoryName, `ca-a2a`)].repositoryName' --output text 2>/dev/null || echo "")
if [ ! -z "$ecr_repos" ]; then
    echo "  ✓ Found ECR repositories: $ecr_repos"
    repo_count=$(echo "$ecr_repos" | wc -w)
    ((resource_count+=$repo_count))
    resources_found="$resources_found\n  - $repo_count ECR Repositories"
fi

log_info "[8/15] Checking VPCs..."
vpcs=$(aws ec2 describe-vpcs --region $REGION --filters "Name=tag:Name,Values=*ca-a2a*" --query 'Vpcs[].VpcId' --output text 2>/dev/null || echo "")
if [ ! -z "$vpcs" ]; then
    echo "  ✓ Found VPCs: $vpcs"
    vpc_count=$(echo "$vpcs" | wc -w)
    ((resource_count+=$vpc_count))
    resources_found="$resources_found\n  - $vpc_count VPC(s)"
fi

log_info "[9/15] Checking CloudWatch Log Groups..."
log_groups=$(aws logs describe-log-groups --region $REGION --log-group-name-prefix "/ecs/ca-a2a" --query 'logGroups[].logGroupName' --output text 2>/dev/null || echo "")
if [ ! -z "$log_groups" ]; then
    log_count=$(echo "$log_groups" | wc -w)
    echo "  ✓ Found $log_count log group(s)"
    ((resource_count+=$log_count))
    resources_found="$resources_found\n  - $log_count CloudWatch Log Groups"
fi

log_info "[10/15] Checking Secrets Manager..."
secrets=$(aws secretsmanager list-secrets --region $REGION --query 'SecretList[?contains(Name, `ca-a2a`)].Name' --output text 2>/dev/null || echo "")
if [ ! -z "$secrets" ]; then
    echo "  ✓ Found secrets: $secrets"
    secret_count=$(echo "$secrets" | wc -w)
    ((resource_count+=$secret_count))
    resources_found="$resources_found\n  - $secret_count Secrets"
fi

log_info "[11/15] Checking IAM Roles..."
iam_roles=$(aws iam list-roles --query 'Roles[?contains(RoleName, `ca-a2a`)].RoleName' --output text 2>/dev/null || echo "")
if [ ! -z "$iam_roles" ]; then
    echo "  ✓ Found IAM roles: $iam_roles"
    role_count=$(echo "$iam_roles" | wc -w)
    ((resource_count+=$role_count))
    resources_found="$resources_found\n  - $role_count IAM Roles"
fi

log_info "[12/15] Checking Service Discovery Namespace..."
namespaces=$(aws servicediscovery list-namespaces --query 'Namespaces[?Name==`ca-a2a.local`].Id' --output text --region $REGION 2>/dev/null || echo "")
if [ ! -z "$namespaces" ]; then
    echo "  ✓ Found service discovery namespace"
    ((resource_count++))
    resources_found="$resources_found\n  - Service Discovery Namespace"
fi

log_info "[13/15] Checking SQS Queues..."
sqs_queues=$(aws sqs list-queues --region $REGION --queue-name-prefix "ca-a2a" --query 'QueueUrls' --output text 2>/dev/null || echo "")
if [ ! -z "$sqs_queues" ]; then
    queue_count=$(echo "$sqs_queues" | wc -w)
    echo "  ✓ Found $queue_count SQS queue(s)"
    ((resource_count+=$queue_count))
    resources_found="$resources_found\n  - $queue_count SQS Queues"
fi

log_info "[14/15] Checking VPC Endpoints..."
vpc_endpoints=$(aws ec2 describe-vpc-endpoints --region $REGION --filters "Name=vpc-id,Values=$vpcs" --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null || echo "")
if [ ! -z "$vpc_endpoints" ]; then
    endpoint_count=$(echo "$vpc_endpoints" | wc -w)
    echo "  ✓ Found $endpoint_count VPC endpoint(s)"
    ((resource_count+=$endpoint_count))
    resources_found="$resources_found\n  - $endpoint_count VPC Endpoints"
fi

log_info "[15/15] Checking Security Groups..."
if [ ! -z "$vpcs" ]; then
    security_groups=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpcs" "Name=group-name,Values=*ca-a2a*" --query 'SecurityGroups[].GroupId' --output text 2>/dev/null || echo "")
    if [ ! -z "$security_groups" ]; then
        sg_count=$(echo "$security_groups" | wc -w)
        echo "  ✓ Found $sg_count security group(s)"
        ((resource_count+=$sg_count))
        resources_found="$resources_found\n  - $sg_count Security Groups"
    fi
fi

echo ""
log_header "=== AUDIT SUMMARY ==="
echo "Total resource groups found: $resource_count"
echo ""

if [ $resource_count -eq 0 ]; then
    log_info "No CA-A2A resources found in eu-west-3. Nothing to delete."
    exit 0
fi

echo -e "${RED}⚠️  WARNING: The following resources will be PERMANENTLY DELETED:${NC}"
echo -e "$resources_found"
echo ""
echo -e "${RED}This operation is IRREVERSIBLE and will delete:${NC}"
echo "  - All running services and containers"
echo "  - All databases and their data"
echo "  - All documents in S3 buckets"
echo "  - All Docker images in ECR"
echo "  - All networking infrastructure"
echo "  - All logs and secrets"
echo ""
echo -e "${YELLOW}Type 'DELETE-EU-WEST-3' to confirm deletion, or Ctrl+C to cancel:${NC}"
read -r confirmation

if [ "$confirmation" != "DELETE-EU-WEST-3" ]; then
    log_error "Deletion cancelled by user."
    exit 1
fi

###############################################################################
# PHASE 2: DELETION
###############################################################################

log_header ""
log_header "=== PHASE 2: DELETING RESOURCES ==="
echo ""

# Step 1: Delete ECS Services
if [ ! -z "$ecs_services" ]; then
    log_info "[Step 1/16] Scaling down and deleting ECS Services..."
    for service in $ecs_services; do
        service_name=$(echo $service | awk -F'/' '{print $NF}')
        echo "  Scaling down $service_name to 0..."
        aws ecs update-service --cluster ${PROJECT_NAME}-cluster --service $service_name --desired-count 0 --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    
    echo "  Waiting 45 seconds for tasks to drain..."
    sleep 45
    
    for service in $ecs_services; do
        service_name=$(echo $service | awk -F'/' '{print $NF}')
        echo "  Deleting service $service_name..."
        aws ecs delete-service --cluster ${PROJECT_NAME}-cluster --service $service_name --force --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ All ECS services deleted"
    sleep 20
fi

# Step 2: Delete ECS Cluster
if [ ! -z "$ecs_cluster" ] && [ "$ecs_cluster" != "None" ]; then
    log_info "[Step 2/16] Deleting ECS Cluster..."
    aws ecs delete-cluster --cluster ${PROJECT_NAME}-cluster --region $REGION 2>&1 | grep -v "An error occurred" || true
    log_info "  ✓ ECS cluster deleted"
fi

# Step 3: Delete Load Balancers
if [ ! -z "$albs" ]; then
    log_info "[Step 3/16] Deleting Load Balancers..."
    for alb in $albs; do
        alb_name=$(aws elbv2 describe-load-balancers --load-balancer-arns $alb --region $REGION --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null || echo "")
        echo "  Deleting ALB: $alb_name..."
        aws elbv2 delete-load-balancer --load-balancer-arn $alb --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  Waiting 75 seconds for ALBs to be deleted..."
    sleep 75
    log_info "  ✓ Load balancers deleted"
fi

# Step 4: Delete Target Groups
if [ ! -z "$tgs" ]; then
    log_info "[Step 4/16] Deleting Target Groups..."
    for tg in $tgs; do
        aws elbv2 delete-target-group --target-group-arn $tg --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ Target groups deleted"
fi

# Step 5: Delete SQS Queues
if [ ! -z "$sqs_queues" ]; then
    log_info "[Step 5/16] Deleting SQS Queues..."
    for queue_url in $sqs_queues; do
        echo "  Deleting queue: $queue_url..."
        aws sqs delete-queue --queue-url $queue_url --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ SQS queues deleted"
fi

# Step 6: Delete RDS Clusters
if [ ! -z "$rds_clusters" ]; then
    log_info "[Step 6/16] Deleting RDS Clusters (this may take several minutes)..."
    for cluster in $rds_clusters; do
        echo "  Processing cluster: $cluster..."
        # Delete instances first
        instances=$(aws rds describe-db-clusters --region $REGION --db-cluster-identifier $cluster --query 'DBClusters[0].DBClusterMembers[].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
        for instance in $instances; do
            echo "    Deleting instance: $instance..."
            aws rds delete-db-instance --db-instance-identifier $instance --skip-final-snapshot --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        sleep 15
        # Delete cluster
        echo "  Deleting cluster: $cluster..."
        aws rds delete-db-cluster --db-cluster-identifier $cluster --skip-final-snapshot --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ RDS clusters deletion initiated"
fi

# Step 7: Empty and Delete S3 Buckets
if [ ! -z "$s3_buckets" ]; then
    log_info "[Step 7/16] Emptying and deleting S3 Buckets..."
    for bucket in $s3_buckets; do
        echo "  Emptying bucket: $bucket..."
        aws s3 rm "s3://$bucket" --recursive --region $REGION 2>&1 | grep -v "An error occurred" || true
        echo "  Deleting bucket: $bucket..."
        aws s3 rb "s3://$bucket" --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ S3 buckets deleted"
fi

# Step 8: Delete ECR Repositories
if [ ! -z "$ecr_repos" ]; then
    log_info "[Step 8/16] Deleting ECR Repositories..."
    for repo in $ecr_repos; do
        echo "  Deleting repository: $repo..."
        aws ecr delete-repository --repository-name $repo --force --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ ECR repositories deleted"
fi

# Step 9: Delete CloudWatch Log Groups
if [ ! -z "$log_groups" ]; then
    log_info "[Step 9/16] Deleting CloudWatch Log Groups..."
    for log_group in $log_groups; do
        aws logs delete-log-group --log-group-name $log_group --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ Log groups deleted"
fi

# Step 10: Delete Secrets
if [ ! -z "$secrets" ]; then
    log_info "[Step 10/16] Deleting Secrets..."
    for secret in $secrets; do
        echo "  Deleting secret: $secret..."
        aws secretsmanager delete-secret --secret-id $secret --force-delete-without-recovery --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ Secrets deleted"
fi

# Step 11: Wait for RDS deletion
log_info "[Step 11/16] Waiting for RDS resources to finish deleting (150s)..."
sleep 150
log_info "  ✓ RDS resources should be deleted or deleting"

# Step 12: Delete Service Discovery
if [ ! -z "$namespaces" ]; then
    log_info "[Step 12/16] Deleting Service Discovery..."
    for namespace_id in $namespaces; do
        echo "  Processing namespace: $namespace_id..."
        services=$(aws servicediscovery list-services --filters "Name=NAMESPACE_ID,Values=$namespace_id" --query 'Services[].Id' --output text --region $REGION 2>/dev/null || echo "")
        for svc in $services; do
            echo "    Deleting service: $svc..."
            aws servicediscovery delete-service --id $svc --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        sleep 15
        echo "  Deleting namespace: $namespace_id..."
        aws servicediscovery delete-namespace --id $namespace_id --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ Service discovery deleted"
fi

# Step 13: Delete VPC Endpoints
if [ ! -z "$vpc_endpoints" ]; then
    log_info "[Step 13/16] Deleting VPC Endpoints..."
    for endpoint in $vpc_endpoints; do
        echo "  Deleting VPC endpoint: $endpoint..."
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $endpoint --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  Waiting 30 seconds for endpoints to be deleted..."
    sleep 30
    log_info "  ✓ VPC endpoints deleted"
fi

# Step 14: Delete VPC Resources
if [ ! -z "$vpcs" ]; then
    log_info "[Step 14/16] Deleting VPC Resources..."
    for vpc_id in $vpcs; do
        echo "  Processing VPC: $vpc_id..."
        
        # Delete NAT Gateways
        nat_gws=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$vpc_id" "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text --region $REGION 2>/dev/null || echo "")
        for nat_gw in $nat_gws; do
            echo "    Deleting NAT Gateway: $nat_gw..."
            eip=$(aws ec2 describe-nat-gateways --nat-gateway-ids $nat_gw --query 'NatGateways[0].NatGatewayAddresses[0].AllocationId' --output text --region $REGION 2>/dev/null || echo "")
            aws ec2 delete-nat-gateway --nat-gateway-id $nat_gw --region $REGION 2>&1 | grep -v "An error occurred" || true
            if [ ! -z "$eip" ] && [ "$eip" != "None" ]; then
                sleep 45
                echo "    Releasing EIP: $eip..."
                aws ec2 release-address --allocation-id $eip --region $REGION 2>&1 | grep -v "An error occurred" || true
            fi
        done
        
        # Delete Security Groups (except default)
        sgs=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region $REGION 2>/dev/null || echo "")
        echo "    Deleting security groups..."
        for sg in $sgs; do
            aws ec2 delete-security-group --group-id $sg --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        
        # Delete Subnets
        subnets=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[].SubnetId' --output text --region $REGION 2>/dev/null || echo "")
        echo "    Deleting subnets..."
        for subnet in $subnets; do
            aws ec2 delete-subnet --subnet-id $subnet --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        
        # Delete Route Tables (except main)
        rts=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text --region $REGION 2>/dev/null || echo "")
        echo "    Deleting route tables..."
        for rt in $rts; do
            aws ec2 delete-route-table --route-table-id $rt --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        
        # Detach and Delete Internet Gateway
        igws=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpc_id" --query 'InternetGateways[].InternetGatewayId' --output text --region $REGION 2>/dev/null || echo "")
        for igw in $igws; do
            echo "    Detaching and deleting Internet Gateway: $igw..."
            aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $vpc_id --region $REGION 2>&1 | grep -v "An error occurred" || true
            aws ec2 delete-internet-gateway --internet-gateway-id $igw --region $REGION 2>&1 | grep -v "An error occurred" || true
        done
        
        # Delete VPC
        echo "  Deleting VPC: $vpc_id..."
        aws ec2 delete-vpc --vpc-id $vpc_id --region $REGION 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ VPC resources deleted"
fi

# Step 15: Delete IAM Roles
if [ ! -z "$iam_roles" ]; then
    log_info "[Step 15/16] Deleting IAM Roles..."
    for role_name in $iam_roles; do
        echo "  Processing role: $role_name..."
        # Detach managed policies
        policies=$(aws iam list-attached-role-policies --role-name $role_name --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
        for policy in $policies; do
            aws iam detach-role-policy --role-name $role_name --policy-arn $policy 2>&1 | grep -v "An error occurred" || true
        done
        
        # Delete inline policies
        inline_policies=$(aws iam list-role-policies --role-name $role_name --query 'PolicyNames' --output text 2>/dev/null || echo "")
        for policy in $inline_policies; do
            aws iam delete-role-policy --role-name $role_name --policy-name $policy 2>&1 | grep -v "An error occurred" || true
        done
        
        # Delete role
        aws iam delete-role --role-name $role_name 2>&1 | grep -v "An error occurred" || true
    done
    log_info "  ✓ IAM roles deleted"
fi

# Step 16: Final verification
log_info "[Step 16/16] Final Verification..."
sleep 10

remaining_clusters=$(aws ecs describe-clusters --clusters ${PROJECT_NAME}-cluster --region $REGION --query 'clusters[0].status' --output text 2>/dev/null || echo "")
remaining_rds=$(aws rds describe-db-clusters --region $REGION --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)].Status' --output text 2>/dev/null || echo "")

if [ -z "$remaining_clusters" ] || [ "$remaining_clusters" == "INACTIVE" ] || [ "$remaining_clusters" == "None" ]; then
    log_info "  ✓ ECS resources cleaned up"
else
    log_warn "  ⚠️  ECS cluster status: $remaining_clusters"
fi

if [ -z "$remaining_rds" ]; then
    log_info "  ✓ RDS resources cleaned up"
else
    log_warn "  ⚠️  Some RDS clusters may still be deleting: $remaining_rds"
fi

echo ""
log_header "==================================================================="
log_header "✅ DELETION COMPLETE"
log_header "==================================================================="
echo ""
log_info "All CA-A2A resources in eu-west-3 have been deleted or are being deleted."
log_info "Some resources like RDS clusters may take additional time to fully delete."
echo ""
log_info "You can verify deletion with:"
echo "  aws ecs describe-clusters --clusters ca-a2a-cluster --region eu-west-3"
echo "  aws rds describe-db-clusters --region eu-west-3"
echo "  aws s3 ls | grep ca-a2a"
echo ""
