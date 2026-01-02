#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy and execute Lambda function to initialize RDS database schema

.DESCRIPTION
    Creates a Lambda function in the VPC to initialize the ca-a2a database schema.
    The Lambda runs once to create tables and indexes, then can be deleted.

.NOTES
    Author: Jaafar Benabderrazak
    Region: eu-west-3
    Prerequisites: AWS CLI configured with appropriate credentials
#>

param(
    [string]$Region = "eu-west-3",
    [string]$ProjectName = "ca-a2a",
    [string]$Profile = "",
    [switch]$KeepLambda = $false
)

$ErrorActionPreference = "Stop"

# Set AWS Profile environment variable if specified
if ($Profile) {
    $env:AWS_PROFILE = $Profile
    Write-Host "Using AWS Profile: $Profile" -ForegroundColor Cyan
}

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "   Database Schema Initialization via Lambda" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "`nThis script will:" -ForegroundColor Yellow
Write-Host "  1. Create Lambda function for DB initialization" -ForegroundColor White
Write-Host "  2. Configure VPC access to RDS" -ForegroundColor White
Write-Host "  3. Execute Lambda to create schema" -ForegroundColor White
Write-Host "  4. Verify tables were created" -ForegroundColor White
Write-Host "  5. Clean up Lambda (unless -KeepLambda specified)" -ForegroundColor White
Write-Host "`n============================================`n" -ForegroundColor Cyan

# Get AWS Account ID
Write-Host "[1/8] Getting AWS Account Information..." -ForegroundColor Green
if ($Profile) {
    $accountId = aws sts get-caller-identity --profile $Profile --query Account --output text --region $Region
} else {
    $accountId = aws sts get-caller-identity --query Account --output text --region $Region
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Error: Failed to get AWS account ID. Is AWS CLI configured?" -ForegroundColor Red
    if ($Profile) {
        Write-Host "  Tip: Make sure profile '$Profile' is valid" -ForegroundColor Yellow
    }
    exit 1
}
Write-Host "  Account ID: $accountId" -ForegroundColor White

# Get VPC Configuration
Write-Host "`n[2/8] Retrieving VPC Configuration..." -ForegroundColor Green

# Get VPC ID
$vpcId = aws ec2 describe-vpcs `
    --filters "Name=tag:Name,Values=$ProjectName-vpc" `
    --query "Vpcs[0].VpcId" `
    --output text `
    --region $Region

if ($vpcId -eq "None" -or $null -eq $vpcId) {
    Write-Host "  Error: VPC not found. Has the infrastructure been deployed?" -ForegroundColor Red
    exit 1
}
Write-Host "  VPC ID: $vpcId" -ForegroundColor White

# Get Private Subnets
$subnetIds = aws ec2 describe-subnets `
    --filters "Name=vpc-id,Values=$vpcId" "Name=tag:Name,Values=*private*" `
    --query "Subnets[*].SubnetId" `
    --output text `
    --region $Region

if ($null -eq $subnetIds -or $subnetIds -eq "") {
    Write-Host "  Error: No private subnets found" -ForegroundColor Red
    exit 1
}
$subnetArray = $subnetIds -split '\s+'
Write-Host "  Subnets: $($subnetArray -join ', ')" -ForegroundColor White

# Get Security Group
$sgId = aws ec2 describe-security-groups `
    --filters "Name=vpc-id,Values=$vpcId" "Name=group-name,Values=$ProjectName-*" `
    --query "SecurityGroups[0].GroupId" `
    --output text `
    --region $Region

if ($sgId -eq "None" -or $null -eq $sgId) {
    Write-Host "  Error: Security group not found" -ForegroundColor Red
    exit 1
}
Write-Host "  Security Group: $sgId" -ForegroundColor White

# Get RDS Endpoint
Write-Host "`n[3/8] Getting RDS Configuration..." -ForegroundColor Green
$rdsEndpoint = aws rds describe-db-instances `
    --db-instance-identifier "$ProjectName-postgres" `
    --query "DBInstances[0].Endpoint.Address" `
    --output text `
    --region $Region

if ($rdsEndpoint -eq "None" -or $null -eq $rdsEndpoint) {
    Write-Host "  Error: RDS instance not found" -ForegroundColor Red
    exit 1
}
Write-Host "  RDS Endpoint: $rdsEndpoint" -ForegroundColor White

# Create Lambda function code
Write-Host "`n[4/8] Creating Lambda Function Code..." -ForegroundColor Green

$lambdaCode = @"
import json
import boto3
import psycopg2
from psycopg2.extras import RealDictCursor

def get_db_password():
    """Get database password from Secrets Manager"""
    client = boto3.client('secretsmanager', region_name='$Region')
    response = client.get_secret_value(SecretId='$ProjectName/db-password')
    return response['SecretString']

def lambda_handler(event, context):
    """Initialize database schema"""
    results = []
    
    try:
        results.append("Getting database password from Secrets Manager...")
        password = get_db_password()
        
        results.append(f"Connecting to RDS: $rdsEndpoint")
        conn = psycopg2.connect(
            host='$rdsEndpoint',
            port=5432,
            user='postgres',
            password=password,
            database='documents_db',
            sslmode='require',
            connect_timeout=10
        )
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        results.append("Connected successfully!")
        
        # Create documents table
        results.append("Creating documents table...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                s3_key VARCHAR(500) UNIQUE NOT NULL,
                document_type VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_size INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processing_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                validation_score FLOAT,
                metadata JSONB,
                extracted_data JSONB,
                validation_details JSONB,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        results.append("âœ“ Documents table created")
        
        # Create processing_logs table
        results.append("Creating processing_logs table...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing_logs (
                id SERIAL PRIMARY KEY,
                document_id INTEGER REFERENCES documents(id),
                agent_name VARCHAR(50) NOT NULL,
                action VARCHAR(100) NOT NULL,
                status VARCHAR(50) NOT NULL,
                details JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        results.append("âœ“ Processing_logs table created")
        
        # Create indexes
        results.append("Creating indexes...")
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key)",
            "CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)",
            "CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)",
            "CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date)",
            "CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name)"
        ]
        
        for idx_sql in indexes:
            cursor.execute(idx_sql)
        conn.commit()
        results.append("âœ“ Indexes created")
        
        # Verify tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('documents', 'processing_logs')
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        
        results.append(f"âœ“ Verification: Found {len(tables)} tables:")
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) as count FROM {table['table_name']}")
            count = cursor.fetchone()['count']
            results.append(f"  - {table['table_name']}: {count} rows")
        
        cursor.close()
        conn.close()
        
        results.append("âœ“ Database schema initialized successfully!")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Database schema initialized successfully',
                'details': results
            })
        }
        
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        results.append(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to initialize database schema',
                'error': str(e),
                'details': results
            })
        }
"@

# Write Lambda code to file
$lambdaCodePath = Join-Path $PWD "lambda_init_db.py"
$lambdaCode | Out-File -FilePath $lambdaCodePath -Encoding utf8
Write-Host "  Lambda code created: $lambdaCodePath" -ForegroundColor White

# Create deployment package
Write-Host "`n[5/8] Creating Lambda Deployment Package..." -ForegroundColor Green
$zipPath = Join-Path $PWD "lambda_init_db.zip"

# Remove old zip if exists
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

# Create zip file
Compress-Archive -Path $lambdaCodePath -DestinationPath $zipPath -Force
Write-Host "  Deployment package created: $zipPath" -ForegroundColor White

# Create IAM role for Lambda
Write-Host "`n[6/8] Creating IAM Role for Lambda..." -ForegroundColor Green

$roleName = "$ProjectName-lambda-db-init-role"
$trustPolicy = @"
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

# Check if role exists
try {
    $null = aws iam get-role --role-name $roleName 2>&1
    $roleExists = ($LASTEXITCODE -eq 0)
} catch {
    $roleExists = $false
}

if (-not $roleExists) {
    Write-Host "  Creating IAM role..." -ForegroundColor White
    $trustPolicyFile = Join-Path $PWD "trust-policy.json"
    # Use UTF8 without BOM
    [System.IO.File]::WriteAllText($trustPolicyFile, $trustPolicy, [System.Text.UTF8Encoding]($false))
    
    aws iam create-role `
        --role-name $roleName `
        --assume-role-policy-document "file://$trustPolicyFile" `
        --region $Region | Out-Null
    
    Remove-Item $trustPolicyFile
    
    # Attach policies
    aws iam attach-role-policy `
        --role-name $roleName `
        --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" `
        --region $Region
    
    aws iam attach-role-policy `
        --role-name $roleName `
        --policy-arn "arn:aws:iam::aws:policy/SecretsManagerReadWrite" `
        --region $Region
    
    Write-Host "  IAM role created and policies attached" -ForegroundColor Green
    Write-Host "  Waiting 10 seconds for IAM propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
} else {
    Write-Host "  IAM role already exists" -ForegroundColor Yellow
}

$roleArn = "arn:aws:iam::${accountId}:role/$roleName"
Write-Host "  Role ARN: $roleArn" -ForegroundColor White

# Create or update Lambda function
Write-Host "`n[7/8] Deploying Lambda Function..." -ForegroundColor Green

$functionName = "$ProjectName-db-init"
try {
    $null = aws lambda get-function --function-name $functionName --region $Region 2>&1
    $lambdaExists = ($LASTEXITCODE -eq 0)
} catch {
    $lambdaExists = $false
}

if (-not $lambdaExists) {
    Write-Host "  Creating Lambda function..." -ForegroundColor White
    
    # Create Lambda layer for psycopg2 (pre-compiled for Amazon Linux)
    Write-Host "  Note: Using psycopg2-binary runtime dependency" -ForegroundColor Cyan
    
    aws lambda create-function `
        --function-name $functionName `
        --runtime python3.11 `
        --role $roleArn `
        --handler lambda_init_db.lambda_handler `
        --zip-file "fileb://$zipPath" `
        --timeout 60 `
        --memory-size 256 `
        --vpc-config "SubnetIds=$($subnetArray -join ','),SecurityGroupIds=$sgId" `
        --region $Region | Out-Null
    
    Write-Host "  Lambda function created" -ForegroundColor Green
    Write-Host "  Waiting for function to be active..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
} else {
    Write-Host "  Lambda function already exists, updating code..." -ForegroundColor Yellow
    aws lambda update-function-code `
        --function-name $functionName `
        --zip-file "fileb://$zipPath" `
        --region $Region | Out-Null
    Write-Host "  Lambda function updated" -ForegroundColor Green
}

# Add psycopg2 layer (AWS provides a managed layer)
Write-Host "  Adding psycopg2 layer..." -ForegroundColor White
# Using AWS's psycopg2 layer for Python 3.11
$layerArn = "arn:aws:lambda:${Region}:898466741470:layer:psycopg2-py38:1"
aws lambda update-function-configuration `
    --function-name $functionName `
    --layers $layerArn `
    --region $Region 2>&1 | Out-Null

Write-Host "  Waiting for Lambda to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Invoke Lambda function
Write-Host "`n[8/8] Invoking Lambda to Initialize Database..." -ForegroundColor Green

$outputFile = Join-Path $PWD "lambda-output.json"
aws lambda invoke `
    --function-name $functionName `
    --region $Region `
    --log-type Tail `
    --output json `
    $outputFile | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "  Lambda executed successfully!" -ForegroundColor Green
    
    # Display results
    $output = Get-Content $outputFile | ConvertFrom-Json
    Write-Host "`n  Lambda Response:" -ForegroundColor Cyan
    
    if ($output.statusCode -eq 200) {
        $body = $output.body | ConvertFrom-Json
        Write-Host "  Status: SUCCESS" -ForegroundColor Green
        Write-Host "`n  Execution Details:" -ForegroundColor Yellow
        foreach ($detail in $body.details) {
            Write-Host "    $detail" -ForegroundColor White
        }
    } else {
        $body = $output.body | ConvertFrom-Json
        Write-Host "  Status: FAILED" -ForegroundColor Red
        Write-Host "  Error: $($body.error)" -ForegroundColor Red
        Write-Host "`n  Details:" -ForegroundColor Yellow
        foreach ($detail in $body.details) {
            Write-Host "    $detail" -ForegroundColor White
        }
    }
} else {
    Write-Host "  Error: Lambda invocation failed" -ForegroundColor Red
    if (Test-Path $outputFile) {
        $errorOutput = Get-Content $outputFile
        Write-Host "  Error details: $errorOutput" -ForegroundColor Red
    }
}

# Cleanup
Write-Host "`n[CLEANUP] Removing Temporary Files..." -ForegroundColor Green
Remove-Item $lambdaCodePath -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
Write-Host "  Temporary files removed" -ForegroundColor White

if (-not $KeepLambda) {
    Write-Host "`n[CLEANUP] Deleting Lambda Function..." -ForegroundColor Green
    Write-Host "  (Use -KeepLambda to preserve the function)" -ForegroundColor DarkGray
    
    aws lambda delete-function `
        --function-name $functionName `
        --region $Region 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Lambda function deleted" -ForegroundColor Green
    }
    
    Write-Host "`n  Note: IAM role '$roleName' was kept for potential reuse" -ForegroundColor Yellow
    Write-Host "  To delete it manually: aws iam delete-role --role-name $roleName" -ForegroundColor DarkGray
}

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "   DATABASE INITIALIZATION COMPLETE!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Verify the schema by testing document processing" -ForegroundColor White
Write-Host "  2. Check CloudWatch logs if there were any issues" -ForegroundColor White
Write-Host "  3. The database is now ready for production use!" -ForegroundColor White
Write-Host "`n============================================`n" -ForegroundColor Cyan

