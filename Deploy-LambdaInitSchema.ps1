# Deploy Lambda Function to Initialize Database Schema
# Run this PowerShell script

$ErrorActionPreference = "Stop"

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "  DEPLOY LAMBDA TO INITIALIZE SCHEMA" -ForegroundColor Green
Write-Host "=========================================`n" -ForegroundColor Green

# Configuration
$REGION = "eu-west-3"
$PROFILE = "reply-sso"
$FUNCTION_NAME = "ca-a2a-init-schema"
$ROLE_NAME = "ca-a2a-lambda-init-role"

Write-Host "Step 1: Creating IAM role for Lambda..." -ForegroundColor Cyan

# Create trust policy
$TRUST_POLICY = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"@

$TRUST_POLICY | Out-File -FilePath "$env:TEMP\trust-policy.json" -Encoding UTF8

# Create role
try {
    $ROLE_ARN = aws iam create-role `
      --role-name $ROLE_NAME `
      --assume-role-policy-document file://$env:TEMP\trust-policy.json `
      --region $REGION `
      --profile $PROFILE `
      --query 'Role.Arn' `
      --output text
    
    Write-Host "✓ Role created: $ROLE_ARN" -ForegroundColor Green
} catch {
    # Role might already exist
    $ROLE_ARN = aws iam get-role `
      --role-name $ROLE_NAME `
      --profile $PROFILE `
      --query 'Role.Arn' `
      --output text
    
    Write-Host "✓ Using existing role: $ROLE_ARN" -ForegroundColor Green
}

# Attach policies
Write-Host "`nStep 2: Attaching policies..." -ForegroundColor Cyan

aws iam attach-role-policy `
  --role-name $ROLE_NAME `
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" `
  --profile $PROFILE 2>$null

aws iam attach-role-policy `
  --role-name $ROLE_NAME `
  --policy-arn "arn:aws:iam::aws:policy/SecretsManagerReadWrite" `
  --profile $PROFILE 2>$null

Write-Host "✓ Policies attached" -ForegroundColor Green

Write-Host "`nStep 3: Waiting for role to propagate..." -ForegroundColor Cyan
Start-Sleep -Seconds 10

Write-Host "`nStep 4: Creating deployment package..." -ForegroundColor Cyan

# Create deployment directory
$DEPLOY_DIR = "$env:TEMP\lambda-deploy"
if (Test-Path $DEPLOY_DIR) {
    Remove-Item -Recurse -Force $DEPLOY_DIR
}
New-Item -ItemType Directory -Path $DEPLOY_DIR | Out-Null

# Copy Lambda function
Copy-Item "lambda-init-schema.py" "$DEPLOY_DIR\lambda_function.py"

# Install asyncpg to deployment directory
Write-Host "Installing asyncpg..." -ForegroundColor Yellow
pip install asyncpg -t $DEPLOY_DIR --quiet

# Create ZIP
Write-Host "Creating ZIP package..." -ForegroundColor Yellow
Push-Location $DEPLOY_DIR
Compress-Archive -Path * -DestinationPath "$env:TEMP\lambda-function.zip" -Force
Pop-Location

Write-Host "✓ Package created" -ForegroundColor Green

Write-Host "`nStep 5: Creating Lambda function..." -ForegroundColor Cyan

# Get VPC subnets (use private subnets where RDS is)
$SUBNET_IDS = aws ec2 describe-subnets `
  --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" "Name=tag:Name,Values=*private*" `
  --region $REGION `
  --profile $PROFILE `
  --query 'Subnets[*].SubnetId' `
  --output text

if ([string]::IsNullOrEmpty($SUBNET_IDS)) {
    Write-Host "No private subnets found, using any subnets..." -ForegroundColor Yellow
    $SUBNET_IDS = aws ec2 describe-subnets `
      --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" `
      --region $REGION `
      --profile $PROFILE `
      --query 'Subnets[0:2].SubnetId' `
      --output text
}

$SUBNETS = ($SUBNET_IDS -split "`t") -join ","
Write-Host "Using subnets: $SUBNETS" -ForegroundColor White

# Get security group
$SG_ID = "sg-047a8f39f9cdcaf4c"  # ECS security group that can reach RDS

Write-Host "Using security group: $SG_ID" -ForegroundColor White

try {
    # Create Lambda function
    $FUNCTION_ARN = aws lambda create-function `
      --function-name $FUNCTION_NAME `
      --runtime python3.9 `
      --role $ROLE_ARN `
      --handler lambda_function.lambda_handler `
      --zip-file "fileb://$env:TEMP\lambda-function.zip" `
      --timeout 60 `
      --memory-size 512 `
      --vpc-config "SubnetIds=$SUBNETS,SecurityGroupIds=$SG_ID" `
      --region $REGION `
      --profile $PROFILE `
      --query 'FunctionArn' `
      --output text
    
    Write-Host "✓ Lambda function created: $FUNCTION_ARN" -ForegroundColor Green
} catch {
    Write-Host "Function might already exist, updating code..." -ForegroundColor Yellow
    
    aws lambda update-function-code `
      --function-name $FUNCTION_NAME `
      --zip-file "fileb://$env:TEMP\lambda-function.zip" `
      --region $REGION `
      --profile $PROFILE | Out-Null
    
    Write-Host "✓ Lambda function updated" -ForegroundColor Green
}

Write-Host "`nStep 6: Waiting for function to be active..." -ForegroundColor Cyan
Start-Sleep -Seconds 15

Write-Host "`nStep 7: Invoking Lambda to initialize schema..." -ForegroundColor Cyan

aws lambda invoke `
  --function-name $FUNCTION_NAME `
  --region $REGION `
  --profile $PROFILE `
  --log-type Tail `
  --query 'LogResult' `
  --output text `
  "$env:TEMP\lambda-response.json" | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) }

Write-Host "`nLambda response:" -ForegroundColor White
Get-Content "$env:TEMP\lambda-response.json" | ConvertFrom-Json | ConvertTo-Json

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "  INITIALIZATION COMPLETE!" -ForegroundColor Green
Write-Host "=========================================`n" -ForegroundColor Green

Write-Host "You can now test the API from CloudShell:" -ForegroundColor Cyan
Write-Host 'curl -s -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \' -ForegroundColor White
Write-Host '  -H "Content-Type: application/json" \' -ForegroundColor White
Write-Host '  -d ''{"jsonrpc": "2.0", "method": "list_pending_documents", "params": {"limit": 5}, "id": 1}'' | jq ''.''' -ForegroundColor White

Write-Host "`nTo clean up the Lambda function after use:" -ForegroundColor Yellow
Write-Host "aws lambda delete-function --function-name $FUNCTION_NAME --region $REGION --profile $PROFILE" -ForegroundColor White

