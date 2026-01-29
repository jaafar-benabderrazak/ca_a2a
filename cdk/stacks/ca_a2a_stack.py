"""
CA-A2A Multi-Agent System Stack
Complete infrastructure with security implementation

Features:
- VPC with public/private subnets
- VPC Endpoints for AWS services (better security, no NAT dependency)
- Aurora PostgreSQL for documents
- RDS PostgreSQL for Keycloak
- ECS Fargate cluster
- Application Load Balancer
- Secrets Manager for credentials
- CloudWatch Logs with retention
- S3 bucket with encryption

Conflict Handling:
- Uses CDK-generated unique names where possible
- Supports importing existing resources via context
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Tags,
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_logs as logs,
    aws_iam as iam,
    aws_ecr as ecr,
)
from constructs import Construct
import json


class CaA2aStack(Stack):
    """Main infrastructure stack for CA-A2A Multi-Agent System"""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        project_name: str,
        env_name: str,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.project_name = project_name
        self.env_name = env_name

        # Check for existing resources to import (via context)
        existing_vpc_id = self.node.try_get_context("existing_vpc_id")
        existing_cluster_name = self.node.try_get_context("existing_cluster_name")
        skip_secrets = self.node.try_get_context("skip_secrets") or False
        skip_rds = self.node.try_get_context("skip_rds") or False

        # ═══════════════════════════════════════════════════════════
        # PHASE 1: NETWORK INFRASTRUCTURE
        # ═══════════════════════════════════════════════════════════

        if existing_vpc_id:
            # Import existing VPC
            self.vpc = ec2.Vpc.from_lookup(
                self, "VPC",
                vpc_id=existing_vpc_id
            )
        else:
            # Create new VPC
            self.vpc = ec2.Vpc(
                self,
                "VPC",
                vpc_name=f"{project_name}-vpc",
                ip_addresses=ec2.IpAddresses.cidr("10.1.0.0/16"),
                max_azs=2,
                nat_gateways=1,
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        name="Public",
                        subnet_type=ec2.SubnetType.PUBLIC,
                        cidr_mask=24,
                    ),
                    ec2.SubnetConfiguration(
                        name="Private",
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                        cidr_mask=24,
                    ),
                ],
                enable_dns_hostnames=True,
                enable_dns_support=True,
            )

        # ═══════════════════════════════════════════════════════════
        # PHASE 1.5: VPC ENDPOINTS (for security & reliability)
        # ═══════════════════════════════════════════════════════════

        # Create VPC Endpoint Security Group
        vpc_endpoint_sg = ec2.SecurityGroup(
            self,
            "VpcEndpointSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-vpce-sg",
            description="Security group for VPC endpoints",
            allow_all_outbound=False,
        )
        vpc_endpoint_sg.add_ingress_rule(
            ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            ec2.Port.tcp(443),
            "Allow HTTPS from VPC"
        )

        # ECR API endpoint
        self.vpc.add_interface_endpoint(
            "EcrApiEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[vpc_endpoint_sg],
        )

        # ECR Docker endpoint
        self.vpc.add_interface_endpoint(
            "EcrDkrEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[vpc_endpoint_sg],
        )

        # CloudWatch Logs endpoint
        self.vpc.add_interface_endpoint(
            "LogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[vpc_endpoint_sg],
        )

        # Secrets Manager endpoint
        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[vpc_endpoint_sg],
        )

        # S3 Gateway endpoint (free)
        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        )

        # ═══════════════════════════════════════════════════════════
        # PHASE 2: SECURITY GROUPS
        # ═══════════════════════════════════════════════════════════

        # ALB Security Group
        self.alb_sg = ec2.SecurityGroup(
            self,
            "AlbSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-alb-sg",
            description="ALB security group - public HTTP/HTTPS access",
            allow_all_outbound=True,  # ALB needs to reach targets
        )
        self.alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            "Allow HTTP from anywhere"
        )
        self.alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS from anywhere"
        )

        # ECS Services Security Group (shared for inter-service communication)
        self.ecs_services_sg = ec2.SecurityGroup(
            self,
            "EcsServicesSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-ecs-services-sg",
            description="Shared security group for ECS services",
            allow_all_outbound=True,  # Services need outbound for AWS APIs
        )

        # Allow ALB to reach all ECS services (ports 8000-8080)
        self.ecs_services_sg.add_ingress_rule(
            self.alb_sg,
            ec2.Port.tcp_range(8000, 8080),
            "Allow traffic from ALB"
        )

        # Allow inter-service A2A communication
        self.ecs_services_sg.add_ingress_rule(
            self.ecs_services_sg,
            ec2.Port.tcp_range(8000, 8080),
            "Allow inter-service A2A communication"
        )

        # RDS Security Group
        self.rds_sg = ec2.SecurityGroup(
            self,
            "RdsSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-rds-sg",
            description="RDS security group - database access",
            allow_all_outbound=False,
        )

        # Allow ECS services to access RDS
        self.rds_sg.add_ingress_rule(
            self.ecs_services_sg,
            ec2.Port.tcp(5432),
            "Allow ECS services to access PostgreSQL"
        )

        # ═══════════════════════════════════════════════════════════
        # PHASE 3: SECRETS & ENCRYPTION
        # ═══════════════════════════════════════════════════════════

        if not skip_secrets:
            # Database password (use unique CDK-generated name to avoid conflicts)
            self.db_password = secretsmanager.Secret(
                self,
                "DbPassword",
                # Let CDK generate unique name with suffix
                description=f"Aurora PostgreSQL master password for {project_name}",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    exclude_punctuation=True,
                    password_length=32,
                ),
            )

            # Keycloak DB password
            self.keycloak_db_password = secretsmanager.Secret(
                self,
                "KeycloakDbPassword",
                description=f"Keycloak PostgreSQL password for {project_name}",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    exclude_punctuation=True,
                    password_length=32,
                ),
            )

            # Keycloak admin password
            self.keycloak_admin_password = secretsmanager.Secret(
                self,
                "KeycloakAdminPassword",
                description=f"Keycloak admin console password for {project_name}",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    exclude_punctuation=True,
                    password_length=32,
                ),
            )

        # ═══════════════════════════════════════════════════════════
        # PHASE 4: DATA STORAGE
        # ═══════════════════════════════════════════════════════════

        # S3 Bucket with encryption and versioning
        # Let CDK auto-generate unique bucket name to avoid conflicts
        self.documents_bucket = s3.Bucket(
            self,
            "DocumentsBucket",
            bucket_name=None,  # Auto-generated unique name
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="archive-old-documents",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90),
                        )
                    ],
                    noncurrent_version_expiration=Duration.days(30),
                )
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )

        if not skip_rds:
            # RDS Subnet Group (for private subnets)
            db_subnet_group = rds.SubnetGroup(
                self,
                "DbSubnetGroup",
                description="Subnet group for RDS databases",
                vpc=self.vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            )

            # Aurora PostgreSQL Cluster
            self.aurora_cluster = rds.DatabaseCluster(
                self,
                "AuroraCluster",
                cluster_identifier=f"{project_name}-documents-db",
                engine=rds.DatabaseClusterEngine.aurora_postgres(
                    version=rds.AuroraPostgresEngineVersion.of("15.8", "15")
                ),
                credentials=rds.Credentials.from_password(
                    username="postgres",
                    password=self.db_password.secret_value,
                ) if not skip_secrets else rds.Credentials.from_generated_secret("postgres"),
                default_database_name="documents",
                vpc=self.vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                security_groups=[self.rds_sg],
                subnet_group=db_subnet_group,
                writer=rds.ClusterInstance.provisioned(
                    "Instance1",
                    instance_type=ec2.InstanceType.of(
                        ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM
                    ),
                ),
                backup=rds.BackupProps(retention=Duration.days(7)),
                storage_encrypted=True,
                cloudwatch_logs_exports=["postgresql"],
                cloudwatch_logs_retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=RemovalPolicy.SNAPSHOT,
            )

            # Keycloak PostgreSQL Database
            self.keycloak_db = rds.DatabaseInstance(
                self,
                "KeycloakDatabase",
                instance_identifier=f"{project_name}-keycloak-db",
                engine=rds.DatabaseInstanceEngine.postgres(
                    version=rds.PostgresEngineVersion.of("16.6", "16")
                ),
                credentials=rds.Credentials.from_password(
                    username="postgres",
                    password=self.keycloak_db_password.secret_value,
                ) if not skip_secrets else rds.Credentials.from_generated_secret("postgres"),
                database_name="keycloak",
                vpc=self.vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                security_groups=[self.rds_sg],
                subnet_group=db_subnet_group,
                instance_type=ec2.InstanceType.of(
                    ec2.InstanceClass.T3, ec2.InstanceSize.SMALL
                ),
                allocated_storage=20,
                storage_type=rds.StorageType.GP3,
                backup_retention=Duration.days(7),
                storage_encrypted=True,
                cloudwatch_logs_exports=["postgresql"],
                publicly_accessible=False,
                removal_policy=RemovalPolicy.SNAPSHOT,
            )

        # ═══════════════════════════════════════════════════════════
        # PHASE 5: ECS CLUSTER & ECR REPOSITORIES
        # ═══════════════════════════════════════════════════════════

        if existing_cluster_name:
            self.ecs_cluster = ecs.Cluster.from_cluster_attributes(
                self, "EcsCluster",
                cluster_name=existing_cluster_name,
                vpc=self.vpc,
                security_groups=[self.ecs_services_sg],
            )
        else:
            self.ecs_cluster = ecs.Cluster(
                self,
                "EcsCluster",
                cluster_name=f"{project_name}-cluster",
                vpc=self.vpc,
                container_insights=True,
            )

        # ECR Repositories - import existing ones (they were created manually)
        # Use from_repository_name to reference existing repos without creating new ones
        services = ["orchestrator", "extractor", "validator", "archivist", "mcp-server"]
        self.ecr_repos = {}
        
        for svc in services:
            self.ecr_repos[svc] = ecr.Repository.from_repository_name(
                self,
                f"{svc.title().replace('-', '')}Repo",
                repository_name=f"{project_name}/{svc}",
            )

        # ═══════════════════════════════════════════════════════════
        # PHASE 6: APPLICATION LOAD BALANCER
        # ═══════════════════════════════════════════════════════════

        self.alb = elbv2.ApplicationLoadBalancer(
            self,
            "ApplicationLoadBalancer",
            vpc=self.vpc,
            internet_facing=True,
            load_balancer_name=f"{project_name}-alb",
            security_group=self.alb_sg,
        )

        # HTTP Listener
        http_listener = self.alb.add_listener(
            "HttpListener",
            port=80,
            open=True,
        )

        # Default action - health check response
        http_listener.add_action(
            "DefaultAction",
            action=elbv2.ListenerAction.fixed_response(
                status_code=200,
                content_type="application/json",
                message_body='{"status":"healthy","service":"ca-a2a-alb"}'
            ),
        )

        # ═══════════════════════════════════════════════════════════
        # PHASE 7: CLOUDWATCH LOG GROUPS
        # ═══════════════════════════════════════════════════════════

        log_services = [
            "orchestrator", "extractor", "validator",
            "archivist", "keycloak", "mcp-server"
        ]

        self.log_groups = {}
        for svc in log_services:
            self.log_groups[svc] = logs.LogGroup(
                self,
                f"{svc.title().replace('-', '')}Logs",
                log_group_name=f"/ecs/{project_name}/{svc}",
                retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=RemovalPolicy.DESTROY,
            )

        # ═══════════════════════════════════════════════════════════
        # PHASE 8: IAM ROLES
        # ═══════════════════════════════════════════════════════════

        # ECS Task Execution Role
        self.task_execution_role = iam.Role(
            self,
            "EcsTaskExecutionRole",
            role_name=f"{project_name}-ecs-task-execution-role",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                ),
            ],
        )

        # Allow reading secrets
        self.task_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                resources=[f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:{project_name}/*"],
            )
        )

        # ECS Task Role (for application permissions)
        self.task_role = iam.Role(
            self,
            "EcsTaskRole",
            role_name=f"{project_name}-ecs-task-role",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )

        # Allow S3 access
        self.documents_bucket.grant_read_write(self.task_role)

        # Allow CloudWatch Logs
        self.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/ecs/{project_name}/*"],
            )
        )

        # ═══════════════════════════════════════════════════════════
        # OUTPUTS
        # ═══════════════════════════════════════════════════════════

        CfnOutput(self, "VpcId", value=self.vpc.vpc_id, description="VPC ID")
        CfnOutput(self, "AlbDnsName", value=self.alb.load_balancer_dns_name, description="ALB DNS Name")
        CfnOutput(self, "AlbArn", value=self.alb.load_balancer_arn, description="ALB ARN")
        CfnOutput(self, "EcsClusterName", value=self.ecs_cluster.cluster_name, description="ECS Cluster Name")
        CfnOutput(self, "EcsClusterArn", value=self.ecs_cluster.cluster_arn, description="ECS Cluster ARN")
        CfnOutput(self, "EcsServicesSecurityGroupId", value=self.ecs_services_sg.security_group_id, description="ECS Services SG ID")
        CfnOutput(self, "DocumentsBucketName", value=self.documents_bucket.bucket_name, description="S3 Bucket Name")
        CfnOutput(self, "TaskExecutionRoleArn", value=self.task_execution_role.role_arn, description="Task Execution Role ARN")
        CfnOutput(self, "TaskRoleArn", value=self.task_role.role_arn, description="Task Role ARN")

        if not skip_rds:
            CfnOutput(self, "AuroraClusterEndpoint", value=self.aurora_cluster.cluster_endpoint.hostname, description="Aurora Endpoint")
            CfnOutput(self, "KeycloakDbEndpoint", value=self.keycloak_db.db_instance_endpoint_address, description="Keycloak DB Endpoint")

        if not skip_secrets:
            CfnOutput(self, "DbPasswordSecretArn", value=self.db_password.secret_arn, description="DB Password Secret ARN")
            CfnOutput(self, "KeycloakAdminPasswordSecretArn", value=self.keycloak_admin_password.secret_arn, description="Keycloak Admin Secret ARN")

        # ECR Repository URIs (imported existing repos)
        CfnOutput(self, "EcrRepoPrefix", value=f"{self.account}.dkr.ecr.{self.region}.amazonaws.com/{project_name}", description="ECR Repository URI Prefix")

        # Apply tags to all resources
        Tags.of(self).add("Project", project_name)
        Tags.of(self).add("Environment", env_name)
        Tags.of(self).add("ManagedBy", "aws-cdk")
        Tags.of(self).add("Owner", "Jaafar-Benabderrazak")
