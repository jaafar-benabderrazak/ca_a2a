#!/bin/bash
# Tag All CA A2A Deployed Services
# This script applies consistent tags to all AWS resources

set -e

REGION="eu-west-3"
ACCOUNT_ID="555043101106"
CLUSTER="ca-a2a-cluster"

# Define tags
PROJECT="ca-a2a"
ENVIRONMENT="demo"
OWNER="Jaafar-Benabderrazak"
MANAGED_BY="manual"
DEPLOYMENT_DATE=$(date +%Y-%m-%d)
VERSION="v1.0"

echo "============================================================="
echo "  TAGGING ALL CA A2A RESOURCES"
echo "============================================================="
echo ""
echo "Tags to apply:"
echo "  Project: ${PROJECT}"
echo "  Environment: ${ENVIRONMENT}"
echo "  Owner: ${OWNER}"
echo "  ManagedBy: ${MANAGED_BY}"
echo "  DeploymentDate: ${DEPLOYMENT_DATE}"
echo "  Version: ${VERSION}"
echo ""

# ==============================================================
# 1. TAG ECS CLUSTER
# ==============================================================
echo "1. Tagging ECS Cluster..."

CLUSTER_ARN=$(aws ecs describe-clusters --clusters ${CLUSTER} --region ${REGION} --query 'clusters[0].clusterArn' --output text)

aws ecs tag-resource \
  --resource-arn ${CLUSTER_ARN} \
  --region ${REGION} \
  --tags \
    key=Project,value=${PROJECT} \
    key=Environment,value=${ENVIRONMENT} \
    key=Owner,value=${OWNER} \
    key=ManagedBy,value=${MANAGED_BY} \
    key=DeploymentDate,value=${DEPLOYMENT_DATE} \
    key=Version,value=${VERSION}

echo "✓ ECS Cluster tagged"

# ==============================================================
# 2. TAG ECS SERVICES
# ==============================================================
echo ""
echo "2. Tagging ECS Services..."

for service in orchestrator extractor validator archivist mcp-server; do
  echo "   Tagging ${service}..."
  
  SERVICE_ARN=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${service} \
    --region ${REGION} \
    --query 'services[0].serviceArn' \
    --output text)
  
  aws ecs tag-resource \
    --resource-arn ${SERVICE_ARN} \
    --region ${REGION} \
    --tags \
      key=Project,value=${PROJECT} \
      key=Environment,value=${ENVIRONMENT} \
      key=Owner,value=${OWNER} \
      key=ManagedBy,value=${MANAGED_BY} \
      key=DeploymentDate,value=${DEPLOYMENT_DATE} \
      key=Version,value=${VERSION} \
      key=ServiceName,value=${service}
  
  echo "   ✓ ${service} tagged"
done

# ==============================================================
# 3. TAG RDS DATABASE
# ==============================================================
echo ""
echo "3. Tagging RDS Database..."

RDS_ARN=$(aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].DBInstanceArn | [0]' \
  --output text)

if [ ! -z "$RDS_ARN" ] && [ "$RDS_ARN" != "None" ]; then
  aws rds add-tags-to-resource \
    --resource-name ${RDS_ARN} \
    --region ${REGION} \
    --tags \
      Key=Project,Value=${PROJECT} \
      Key=Environment,Value=${ENVIRONMENT} \
      Key=Owner,Value=${OWNER} \
      Key=ManagedBy,Value=${MANAGED_BY} \
      Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
      Key=Version,Value=${VERSION}
  
  echo "✓ RDS Database tagged"
else
  echo "⚠ RDS Database not found"
fi

# ==============================================================
# 4. TAG S3 BUCKET
# ==============================================================
echo ""
echo "4. Tagging S3 Bucket..."

S3_BUCKET="ca-a2a-documents-${ACCOUNT_ID}"

aws s3api put-bucket-tagging \
  --bucket ${S3_BUCKET} \
  --region ${REGION} \
  --tagging "TagSet=[
    {Key=Project,Value=${PROJECT}},
    {Key=Environment,Value=${ENVIRONMENT}},
    {Key=Owner,Value=${OWNER}},
    {Key=ManagedBy,Value=${MANAGED_BY}},
    {Key=DeploymentDate,Value=${DEPLOYMENT_DATE}},
    {Key=Version,Value=${VERSION}}
  ]"

echo "✓ S3 Bucket tagged"

# ==============================================================
# 5. TAG LAMBDA FUNCTION
# ==============================================================
echo ""
echo "5. Tagging Lambda Function..."

LAMBDA_NAME="ca-a2a-s3-processor"
LAMBDA_ARN=$(aws lambda get-function \
  --function-name ${LAMBDA_NAME} \
  --region ${REGION} \
  --query 'Configuration.FunctionArn' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$LAMBDA_ARN" ]; then
  aws lambda tag-resource \
    --resource ${LAMBDA_ARN} \
    --region ${REGION} \
    --tags \
      Project=${PROJECT} \
      Environment=${ENVIRONMENT} \
      Owner=${OWNER} \
      ManagedBy=${MANAGED_BY} \
      DeploymentDate=${DEPLOYMENT_DATE} \
      Version=${VERSION}
  
  echo "✓ Lambda Function tagged"
else
  echo "⚠ Lambda Function not found"
fi

# ==============================================================
# 6. TAG SQS QUEUE
# ==============================================================
echo ""
echo "6. Tagging SQS Queue..."

QUEUE_NAME="ca-a2a-document-uploads"
QUEUE_URL=$(aws sqs get-queue-url \
  --queue-name ${QUEUE_NAME} \
  --region ${REGION} \
  --query 'QueueUrl' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$QUEUE_URL" ]; then
  aws sqs tag-queue \
    --queue-url ${QUEUE_URL} \
    --region ${REGION} \
    --tags \
      Project=${PROJECT} \
      Environment=${ENVIRONMENT} \
      Owner=${OWNER} \
      ManagedBy=${MANAGED_BY} \
      DeploymentDate=${DEPLOYMENT_DATE} \
      Version=${VERSION}
  
  echo "✓ SQS Queue tagged"
else
  echo "⚠ SQS Queue not found"
fi

# ==============================================================
# 7. TAG LOAD BALANCER
# ==============================================================
echo ""
echo "7. Tagging Load Balancer..."

ALB_ARN=$(aws elbv2 describe-load-balancers \
  --region ${REGION} \
  --query "LoadBalancers[?contains(LoadBalancerName,'ca-a2a')].LoadBalancerArn | [0]" \
  --output text)

if [ ! -z "$ALB_ARN" ] && [ "$ALB_ARN" != "None" ]; then
  aws elbv2 add-tags \
    --resource-arns ${ALB_ARN} \
    --region ${REGION} \
    --tags \
      Key=Project,Value=${PROJECT} \
      Key=Environment,Value=${ENVIRONMENT} \
      Key=Owner,Value=${OWNER} \
      Key=ManagedBy,Value=${MANAGED_BY} \
      Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
      Key=Version,Value=${VERSION}
  
  echo "✓ Load Balancer tagged"
else
  echo "⚠ Load Balancer not found"
fi

# ==============================================================
# 8. TAG TARGET GROUPS
# ==============================================================
echo ""
echo "8. Tagging Target Groups..."

TG_ARNS=$(aws elbv2 describe-target-groups \
  --region ${REGION} \
  --query "TargetGroups[?contains(TargetGroupName,'ca-a2a')].TargetGroupArn" \
  --output text)

if [ ! -z "$TG_ARNS" ]; then
  for TG_ARN in $TG_ARNS; do
    TG_NAME=$(echo $TG_ARN | cut -d'/' -f2)
    echo "   Tagging ${TG_NAME}..."
    
    aws elbv2 add-tags \
      --resource-arns ${TG_ARN} \
      --region ${REGION} \
      --tags \
        Key=Project,Value=${PROJECT} \
        Key=Environment,Value=${ENVIRONMENT} \
        Key=Owner,Value=${OWNER} \
        Key=ManagedBy,Value=${MANAGED_BY} \
        Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
        Key=Version,Value=${VERSION}
    
    echo "   ✓ ${TG_NAME} tagged"
  done
else
  echo "⚠ No Target Groups found"
fi

# ==============================================================
# 9. TAG IAM ROLES
# ==============================================================
echo ""
echo "9. Tagging IAM Roles..."

for role in ca-a2a-ecs-execution-role ca-a2a-ecs-task-role ca-a2a-lambda-s3-processor-role; do
  ROLE_EXISTS=$(aws iam get-role --role-name ${role} --query 'Role.RoleName' --output text 2>/dev/null || echo "")
  
  if [ ! -z "$ROLE_EXISTS" ]; then
    echo "   Tagging ${role}..."
    
    aws iam tag-role \
      --role-name ${role} \
      --tags \
        Key=Project,Value=${PROJECT} \
        Key=Environment,Value=${ENVIRONMENT} \
        Key=Owner,Value=${OWNER} \
        Key=ManagedBy,Value=${MANAGED_BY} \
        Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
        Key=Version,Value=${VERSION}
    
    echo "   ✓ ${role} tagged"
  else
    echo "   ⚠ ${role} not found"
  fi
done

# ==============================================================
# 10. TAG CLOUDWATCH LOG GROUPS
# ==============================================================
echo ""
echo "10. Tagging CloudWatch Log Groups..."

LOG_GROUPS=$(aws logs describe-log-groups \
  --region ${REGION} \
  --log-group-name-prefix "/ecs/ca-a2a" \
  --query 'logGroups[*].logGroupName' \
  --output text)

for LOG_GROUP in $LOG_GROUPS; do
  echo "   Tagging ${LOG_GROUP}..."
  
  aws logs tag-log-group \
    --log-group-name ${LOG_GROUP} \
    --region ${REGION} \
    --tags \
      Project=${PROJECT} \
      Environment=${ENVIRONMENT} \
      Owner=${OWNER} \
      ManagedBy=${MANAGED_BY} \
      DeploymentDate=${DEPLOYMENT_DATE} \
      Version=${VERSION}
  
  echo "   ✓ ${LOG_GROUP} tagged"
done

# Tag Lambda log group if exists
LAMBDA_LOG_GROUP="/aws/lambda/ca-a2a-s3-processor"
LOG_GROUP_EXISTS=$(aws logs describe-log-groups \
  --log-group-name-prefix ${LAMBDA_LOG_GROUP} \
  --region ${REGION} \
  --query 'logGroups[0].logGroupName' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$LOG_GROUP_EXISTS" ] && [ "$LOG_GROUP_EXISTS" != "None" ]; then
  echo "   Tagging ${LAMBDA_LOG_GROUP}..."
  
  aws logs tag-log-group \
    --log-group-name ${LAMBDA_LOG_GROUP} \
    --region ${REGION} \
    --tags \
      Project=${PROJECT} \
      Environment=${ENVIRONMENT} \
      Owner=${OWNER} \
      ManagedBy=${MANAGED_BY} \
      DeploymentDate=${DEPLOYMENT_DATE} \
      Version=${VERSION}
  
  echo "   ✓ ${LAMBDA_LOG_GROUP} tagged"
fi

# ==============================================================
# 11. TAG VPC RESOURCES
# ==============================================================
echo ""
echo "11. Tagging VPC Resources..."

# Get VPC ID
VPC_ID=$(aws ec2 describe-vpcs \
  --region ${REGION} \
  --filters "Name=tag:Name,Values=*ca-a2a*" \
  --query 'Vpcs[0].VpcId' \
  --output text 2>/dev/null || \
  aws ec2 describe-vpcs --region ${REGION} --query 'Vpcs[0].VpcId' --output text)

if [ ! -z "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
  echo "   Tagging VPC: ${VPC_ID}..."
  
  aws ec2 create-tags \
    --resources ${VPC_ID} \
    --region ${REGION} \
    --tags \
      Key=Project,Value=${PROJECT} \
      Key=Environment,Value=${ENVIRONMENT} \
      Key=Owner,Value=${OWNER} \
      Key=ManagedBy,Value=${MANAGED_BY} \
      Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
      Key=Version,Value=${VERSION}
  
  echo "   ✓ VPC tagged"
  
  # Tag Subnets
  echo "   Tagging Subnets..."
  SUBNET_IDS=$(aws ec2 describe-subnets \
    --region ${REGION} \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].SubnetId' \
    --output text)
  
  if [ ! -z "$SUBNET_IDS" ]; then
    aws ec2 create-tags \
      --resources $SUBNET_IDS \
      --region ${REGION} \
      --tags \
        Key=Project,Value=${PROJECT} \
        Key=Environment,Value=${ENVIRONMENT} \
        Key=Owner,Value=${OWNER} \
        Key=ManagedBy,Value=${MANAGED_BY} \
        Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
        Key=Version,Value=${VERSION}
    
    echo "   ✓ Subnets tagged"
  fi
  
  # Tag Security Groups
  echo "   Tagging Security Groups..."
  SG_IDS=$(aws ec2 describe-security-groups \
    --region ${REGION} \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
    --output text)
  
  if [ ! -z "$SG_IDS" ]; then
    aws ec2 create-tags \
      --resources $SG_IDS \
      --region ${REGION} \
      --tags \
        Key=Project,Value=${PROJECT} \
        Key=Environment,Value=${ENVIRONMENT} \
        Key=Owner,Value=${OWNER} \
        Key=ManagedBy,Value=${MANAGED_BY} \
        Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
        Key=Version,Value=${VERSION}
    
    echo "   ✓ Security Groups tagged"
  fi
else
  echo "   ⚠ VPC not found"
fi

# ==============================================================
# 12. TAG SECRETS
# ==============================================================
echo ""
echo "12. Tagging Secrets Manager Secrets..."

SECRETS=$(aws secretsmanager list-secrets \
  --region ${REGION} \
  --query 'SecretList[?contains(Name,`ca-a2a`)].ARN' \
  --output text)

if [ ! -z "$SECRETS" ]; then
  for SECRET_ARN in $SECRETS; do
    SECRET_NAME=$(echo $SECRET_ARN | rev | cut -d'/' -f1 | rev | cut -d'-' -f1-3)
    echo "   Tagging ${SECRET_NAME}..."
    
    aws secretsmanager tag-resource \
      --secret-id ${SECRET_ARN} \
      --region ${REGION} \
      --tags \
        Key=Project,Value=${PROJECT} \
        Key=Environment,Value=${ENVIRONMENT} \
        Key=Owner,Value=${OWNER} \
        Key=ManagedBy,Value=${MANAGED_BY} \
        Key=DeploymentDate,Value=${DEPLOYMENT_DATE} \
        Key=Version,Value=${VERSION}
    
    echo "   ✓ ${SECRET_NAME} tagged"
  done
else
  echo "   ⚠ No secrets found"
fi

# ==============================================================
# SUMMARY
# ==============================================================
echo ""
echo "============================================================="
echo "  TAGGING COMPLETE!"
echo "============================================================="
echo ""
echo "Tagged Resources:"
echo "  ✓ ECS Cluster"
echo "  ✓ ECS Services (5)"
echo "  ✓ RDS Database"
echo "  ✓ S3 Bucket"
echo "  ✓ Lambda Function"
echo "  ✓ SQS Queue"
echo "  ✓ Load Balancer"
echo "  ✓ Target Groups"
echo "  ✓ IAM Roles"
echo "  ✓ CloudWatch Log Groups"
echo "  ✓ VPC Resources"
echo "  ✓ Secrets Manager"
echo ""
echo "All resources now tagged with:"
echo "  - Project: ${PROJECT}"
echo "  - Environment: ${ENVIRONMENT}"
echo "  - Owner: ${OWNER}"
echo "  - ManagedBy: ${MANAGED_BY}"
echo "  - DeploymentDate: ${DEPLOYMENT_DATE}"
echo "  - Version: ${VERSION}"
echo ""
echo "You can now:"
echo "  - Track costs by Project tag"
echo "  - Filter resources by Environment"
echo "  - Identify resource ownership"
echo "  - Manage resources by deployment date"
echo ""

