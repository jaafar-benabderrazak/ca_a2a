"""
CA-A2A Multi-Agent System Stack
Complete infrastructure with security implementation
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticloadbalancingv2 as elbv2,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_logs as logs,
    aws_iam as iam,
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

        # ═══════════════════════════════════════════════════════════
        # PHASE 1: NETWORK INFRASTRUCTURE
        # ═══════════════════════════════════════════════════════════
        
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
        # PHASE 2: SECURITY GROUPS
        # ═══════════════════════════════════════════════════════════

        # ALB Security Group
        self.alb_sg = ec2.SecurityGroup(
            self,
            "AlbSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-alb-sg",
            description="ALB security group - public HTTP/HTTPS access",
            allow_all_outbound=False,
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

        # ECS Service Security Groups (with egress hardening)
        self.orchestrator_sg = self._create_service_sg("orchestrator", 8001)
        self.extractor_sg = self._create_service_sg("extractor", 8002)
        self.validator_sg = self._create_service_sg("validator", 8003)
        self.archivist_sg = self._create_service_sg("archivist", 8004)
        self.keycloak_sg = self._create_service_sg("keycloak", 8080)
        self.mcp_server_sg = self._create_service_sg("mcp-server", 8000)

        # RDS Security Group
        self.rds_sg = ec2.SecurityGroup(
            self,
            "RdsSecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{project_name}-rds-sg",
            description="RDS security group - database access",
            allow_all_outbound=False,
        )
        
        # Allow MCP Server and Keycloak to access RDS
        self.rds_sg.add_ingress_rule(
            self.mcp_server_sg,
            ec2.Port.tcp(5432),
            "Allow MCP Server to access PostgreSQL"
        )
        self.rds_sg.add_ingress_rule(
            self.keycloak_sg,
            ec2.Port.tcp(5432),
            "Allow Keycloak to access PostgreSQL"
        )

        # ═══════════════════════════════════════════════════════════
        # PHASE 3: SECRETS & ENCRYPTION
        # ═══════════════════════════════════════════════════════════

        # Database password
        self.db_password = secretsmanager.Secret(
            self,
            "DbPassword",
            secret_name=f"{project_name}/db-password",
            description="Aurora PostgreSQL master password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=32,
            ),
        )

        # Keycloak DB password
        self.keycloak_db_password = secretsmanager.Secret(
            self,
            "KeycloakDbPassword",
            secret_name=f"{project_name}/keycloak-db-password",
            description="Keycloak PostgreSQL password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=32,
            ),
        )

        # Keycloak admin password
        self.keycloak_admin_password = secretsmanager.Secret(
            self,
            "KeycloakAdminPassword",
            secret_name=f"{project_name}/keycloak-admin-password",
            description="Keycloak admin console password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=32,
            ),
        )

        # JWT keys and client API keys will be generated by custom resources
        # or manually after initial deployment

        # ═══════════════════════════════════════════════════════════
        # PHASE 4: DATA STORAGE
        # ═══════════════════════════════════════════════════════════

        # S3 Bucket with encryption and versioning
        self.documents_bucket = s3.Bucket(
            self,
            "DocumentsBucket",
            bucket_name=f"{project_name}-documents-{self.account}",
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

        # RDS Subnet Group (for private subnets)
        db_subnet_group = rds.SubnetGroup(
            self,
            "DbSubnetGroup",
            description="Subnet group for RDS databases",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            subnet_group_name=f"{project_name}-db-subnet",
        )

        # Aurora PostgreSQL Cluster
        self.aurora_cluster = rds.DatabaseCluster(
            self,
            "AuroraCluster",
            cluster_identifier=f"{project_name}-documents-db",
            engine=rds.DatabaseClusterEngine.aurora_postgres(
                version=rds.AuroraPostgresEngineVersion.of("15.4", "15")
            ),
            credentials=rds.Credentials.from_password(
                username="postgres",
                password=self.db_password.secret_value,
            ),
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
        )

        # Keycloak PostgreSQL Database
        self.keycloak_db = rds.DatabaseInstance(
            self,
            "KeycloakDatabase",
            instance_identifier=f"{project_name}-keycloak-db",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.of("16.4", "16")
            ),
            credentials=rds.Credentials.from_password(
                username="postgres",
                password=self.keycloak_db_password.secret_value,
            ),
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
        # PHASE 5: ECS CLUSTER
        # ═══════════════════════════════════════════════════════════

        self.ecs_cluster = ecs.Cluster(
            self,
            "EcsCluster",
            cluster_name=f"{project_name}-cluster",
            vpc=self.vpc,
            container_insights=True,
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

        # HTTP Listener (will redirect to HTTPS in production)
        http_listener = self.alb.add_listener(
            "HttpListener",
            port=80,
            open=True,
        )

        # Default target group (will be overridden by services)
        http_listener.add_action(
            "DefaultAction",
            action=elbv2.ListenerAction.fixed_response(
                status_code=200,
                content_type="text/plain",
                message_body="CA-A2A Multi-Agent System - Healthy"
            ),
        )

        # ═══════════════════════════════════════════════════════════
        # PHASE 7: CLOUDWATCH LOG GROUPS
        # ═══════════════════════════════════════════════════════════

        self.orchestrator_logs = logs.LogGroup(
            self,
            "OrchestratorLogs",
            log_group_name=f"/ecs/{project_name}-orchestrator",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.extractor_logs = logs.LogGroup(
            self,
            "ExtractorLogs",
            log_group_name=f"/ecs/{project_name}-extractor",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.validator_logs = logs.LogGroup(
            self,
            "ValidatorLogs",
            log_group_name=f"/ecs/{project_name}-validator",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.archivist_logs = logs.LogGroup(
            self,
            "ArchivistLogs",
            log_group_name=f"/ecs/{project_name}-archivist",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.keycloak_logs = logs.LogGroup(
            self,
            "KeycloakLogs",
            log_group_name=f"/ecs/{project_name}-keycloak",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.mcp_server_logs = logs.LogGroup(
            self,
            "McpServerLogs",
            log_group_name=f"/ecs/{project_name}-mcp-server",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ═══════════════════════════════════════════════════════════
        # OUTPUTS
        # ═══════════════════════════════════════════════════════════

        CfnOutput(
            self,
            "VpcId",
            value=self.vpc.vpc_id,
            description="VPC ID",
        )

        CfnOutput(
            self,
            "AlbDnsName",
            value=self.alb.load_balancer_dns_name,
            description="Application Load Balancer DNS Name",
        )

        CfnOutput(
            self,
            "AuroraClusterEndpoint",
            value=self.aurora_cluster.cluster_endpoint.hostname,
            description="Aurora PostgreSQL Cluster Endpoint",
        )

        CfnOutput(
            self,
            "KeycloakDbEndpoint",
            value=self.keycloak_db.db_instance_endpoint_address,
            description="Keycloak PostgreSQL Database Endpoint",
        )

        CfnOutput(
            self,
            "DocumentsBucketName",
            value=self.documents_bucket.bucket_name,
            description="S3 Documents Bucket Name",
        )

        CfnOutput(
            self,
            "EcsClusterName",
            value=self.ecs_cluster.cluster_name,
            description="ECS Cluster Name",
        )

    def _create_service_sg(
        self, service_name: str, port: int
    ) -> ec2.SecurityGroup:
        """
        Create a security group for an ECS service with egress hardening
        """
        sg = ec2.SecurityGroup(
            self,
            f"{service_name.title()}SecurityGroup",
            vpc=self.vpc,
            security_group_name=f"{self.project_name}-{service_name}-sg",
            description=f"{service_name} ECS security group",
            allow_all_outbound=False,
        )

        # Allow inbound from ALB
        sg.add_ingress_rule(
            self.alb_sg,
            ec2.Port.tcp(port),
            f"Allow traffic from ALB to {service_name}"
        )

        # Egress hardening - only allow necessary outbound
        # HTTPS for AWS services (VPC endpoints)
        sg.add_egress_rule(
            ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            ec2.Port.tcp(443),
            "HTTPS for AWS services"
        )

        # DNS
        sg.add_egress_rule(
            ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            ec2.Port.udp(53),
            "DNS"
        )
        sg.add_egress_rule(
            ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            ec2.Port.tcp(53),
            "DNS TCP"
        )

        # PostgreSQL (for database access)
        sg.add_egress_rule(
            ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            ec2.Port.tcp(5432),
            "PostgreSQL"
        )

        return sg

