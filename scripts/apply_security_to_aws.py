"""
Apply CA-A2A security hardening to an existing AWS deployment.

What this script does (idempotent where possible):
- Creates Secrets Manager secrets for A2A JWT keys + external client API key
- Creates per-agent security groups and tightens ingress/egress
- Registers new ECS task definition revisions with:
  - named portMapping ("http") required by Service Connect
  - security env vars + secrets
- Updates ECS services to:
  - attach per-agent SGs
  - enable Service Connect (and TLS if SERVICE_CONNECT_TLS_* env vars are provided)
  - force new deployment

Usage (PowerShell):
  python scripts/apply_security_to_aws.py --profile reply-sso --region eu-west-3 --project ca-a2a --cluster ca-a2a-cluster
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple


def sh(cmd: List[str], *, check: bool = True) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}\n{p.stdout}")
    return (p.stdout or "").strip()


def aws(cmd: List[str], *, profile: str, region: str, check: bool = True) -> str:
    return sh(["aws", *cmd, "--profile", profile, "--region", region], check=check)


def aws_json(cmd: List[str], *, profile: str, region: str) -> Any:
    out = aws([*cmd, "--output", "json"], profile=profile, region=region)
    return json.loads(out) if out else {}


def ensure_secret(name: str, value: str, *, profile: str, region: str) -> None:
    # create or update
    try:
        aws(["secretsmanager", "create-secret", "--name", name, "--secret-string", value], profile=profile, region=region)
    except Exception:
        aws(["secretsmanager", "update-secret", "--secret-id", name, "--secret-string", value], profile=profile, region=region)


def random_api_key(length: int = 48) -> str:
    # URL-safe-ish key
    raw = secrets.token_urlsafe(64)
    return raw.replace("-", "").replace("_", "")[:length]


def rsa_keypair_pem() -> Tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def ensure_security_secrets(project: str, *, profile: str, region: str) -> Dict[str, str]:
    private_pem, public_pem = rsa_keypair_pem()
    api_key = random_api_key()
    api_keys_json = json.dumps({"external_client": api_key})

    ensure_secret(f"{project}/a2a-jwt-private-key-pem", private_pem, profile=profile, region=region)
    ensure_secret(f"{project}/a2a-jwt-public-key-pem", public_pem, profile=profile, region=region)
    ensure_secret(f"{project}/a2a-client-api-keys-json", api_keys_json, profile=profile, region=region)
    return {"client_api_key": api_key}


def ensure_sg(name: str, desc: str, vpc_id: str, *, profile: str, region: str) -> str:
    # Return SG id
    existing = aws_json(
        ["ec2", "describe-security-groups", "--filters", f"Name=group-name,Values={name}", "--query", "SecurityGroups[0].GroupId"],
        profile=profile,
        region=region,
    )
    if isinstance(existing, str) and existing.startswith("sg-"):
        return existing

    out = aws_json(
        [
            "ec2",
            "create-security-group",
            "--group-name",
            name,
            "--description",
            desc,
            "--vpc-id",
            vpc_id,
        ],
        profile=profile,
        region=region,
    )
    return out["GroupId"]


def sg_allow_ingress(sg: str, proto: str, port: int, source_sg: str, *, profile: str, region: str) -> None:
    aws(
        [
            "ec2",
            "authorize-security-group-ingress",
            "--group-id",
            sg,
            "--protocol",
            proto,
            "--port",
            str(port),
            "--source-group",
            source_sg,
        ],
        profile=profile,
        region=region,
        check=False,
    )


def sg_allow_ingress_cidr(sg: str, proto: str, port: int, cidr: str, *, profile: str, region: str) -> None:
    aws(
        [
            "ec2",
            "authorize-security-group-ingress",
            "--group-id",
            sg,
            "--protocol",
            proto,
            "--port",
            str(port),
            "--cidr",
            cidr,
        ],
        profile=profile,
        region=region,
        check=False,
    )


def sg_revoke_allow_all_egress(sg: str, *, profile: str, region: str) -> None:
    aws(
        [
            "ec2",
            "revoke-security-group-egress",
            "--group-id",
            sg,
            "--ip-permissions",
            '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]',
        ],
        profile=profile,
        region=region,
        check=False,
    )


def sg_allow_egress_cidr(sg: str, proto: str, port: int, cidr: str, *, profile: str, region: str) -> None:
    aws(
        [
            "ec2",
            "authorize-security-group-egress",
            "--group-id",
            sg,
            "--protocol",
            proto,
            "--port",
            str(port),
            "--cidr",
            cidr,
        ],
        profile=profile,
        region=region,
        check=False,
    )


def apply_security_groups(project: str, vpc_id: str, vpc_cidr: str, alb_sg: str, rds_sg: str, *, profile: str, region: str) -> Dict[str, str]:
    orch_sg = ensure_sg(f"{project}-orchestrator-sg", "Orchestrator SG", vpc_id, profile=profile, region=region)
    ext_sg = ensure_sg(f"{project}-extractor-sg", "Extractor SG", vpc_id, profile=profile, region=region)
    val_sg = ensure_sg(f"{project}-validator-sg", "Validator SG", vpc_id, profile=profile, region=region)
    arc_sg = ensure_sg(f"{project}-archivist-sg", "Archivist SG", vpc_id, profile=profile, region=region)

    # Ingress least privilege
    sg_allow_ingress(orch_sg, "tcp", 8001, alb_sg, profile=profile, region=region)
    sg_allow_ingress(ext_sg, "tcp", 8002, orch_sg, profile=profile, region=region)
    sg_allow_ingress(val_sg, "tcp", 8003, orch_sg, profile=profile, region=region)
    sg_allow_ingress(arc_sg, "tcp", 8004, orch_sg, profile=profile, region=region)

    # RDS ingress
    for sg_id in [orch_sg, ext_sg, val_sg, arc_sg]:
        sg_allow_ingress(rds_sg, "tcp", 5432, sg_id, profile=profile, region=region)

    # Egress tightening (best-effort)
    for sg_id in [orch_sg, ext_sg, val_sg, arc_sg]:
        sg_revoke_allow_all_egress(sg_id, profile=profile, region=region)
        # HTTPS + DNS + Postgres inside VPC
        sg_allow_egress_cidr(sg_id, "tcp", 443, vpc_cidr, profile=profile, region=region)
        sg_allow_egress_cidr(sg_id, "udp", 53, vpc_cidr, profile=profile, region=region)
        sg_allow_egress_cidr(sg_id, "tcp", 53, vpc_cidr, profile=profile, region=region)
        sg_allow_egress_cidr(sg_id, "tcp", 5432, vpc_cidr, profile=profile, region=region)

    # Orchestrator outbound to agents
    sg_allow_egress_cidr(orch_sg, "tcp", 8002, vpc_cidr, profile=profile, region=region)
    sg_allow_egress_cidr(orch_sg, "tcp", 8003, vpc_cidr, profile=profile, region=region)
    sg_allow_egress_cidr(orch_sg, "tcp", 8004, vpc_cidr, profile=profile, region=region)

    return {"orchestrator": orch_sg, "extractor": ext_sg, "validator": val_sg, "archivist": arc_sg}


def taskdef_arn(service_name: str, *, profile: str, region: str, cluster: str) -> str:
    return aws(
        [
            "ecs",
            "describe-services",
            "--cluster",
            cluster,
            "--services",
            service_name,
            "--query",
            "services[0].taskDefinition",
            "--output",
            "text",
        ],
        profile=profile,
        region=region,
    )


def register_taskdef_with_security(
    *,
    base_taskdef_arn: str,
    project: str,
    region: str,
    account_id: str,
    service: str,
    rds_endpoint: str,
    s3_bucket: str,
    require_auth: bool,
    profile: str,
) -> str:
    td = aws_json(["ecs", "describe-task-definition", "--task-definition", base_taskdef_arn], profile=profile, region=region)["taskDefinition"]

    # Remove read-only keys before register
    for k in [
        "taskDefinitionArn",
        "revision",
        "status",
        "requiresAttributes",
        "compatibilities",
        "registeredAt",
        "registeredBy",
    ]:
        td.pop(k, None)

    # Ensure portMapping has name "http"
    for c in td.get("containerDefinitions", []):
        if c.get("portMappings"):
            for pm in c["portMappings"]:
                pm.setdefault("name", "http")

        # Ensure A2A env
        env = {e["name"]: e["value"] for e in c.get("environment", []) if "name" in e and "value" in e}
        env.setdefault("A2A_REQUIRE_AUTH", "true" if require_auth else "false")
        env.setdefault("A2A_JWT_ISSUER", "ca-a2a")
        env.setdefault("A2A_JWT_ALG", "RS256")
        # Make rate limit demo-friendly on orchestrator
        if service == "orchestrator":
            env.setdefault("A2A_RATE_LIMIT_PER_MINUTE", "5")
        c["environment"] = [{"name": k, "value": str(v)} for k, v in env.items()]

        # RBAC
        if service == "orchestrator":
            rbac = {"allow": {"external_client": ["process_document", "process_batch", "get_task_status", "list_pending_documents", "discover_agents", "get_agent_registry"]}, "deny": {}}
        else:
            rbac = {"allow": {"orchestrator": ["*"]}, "deny": {}}
        # Inject/update RBAC JSON
        env["A2A_RBAC_POLICY_JSON"] = json.dumps(rbac, separators=(",", ":"))
        c["environment"] = [{"name": k, "value": str(v)} for k, v in env.items()]

        # Secrets: ensure public key is available to all; private+api keys only for orchestrator
        secrets_list = c.get("secrets", [])
        existing_secret_names = {s["name"] for s in secrets_list if "name" in s}

        def add_secret(env_name: str, secret_name: str):
            if env_name in existing_secret_names:
                return
            secrets_list.append(
                {
                    "name": env_name,
                    "valueFrom": f"arn:aws:secretsmanager:{region}:{account_id}:secret:{project}/{secret_name}",
                }
            )

        add_secret("A2A_JWT_PUBLIC_KEY_PEM", "a2a-jwt-public-key-pem")
        if service == "orchestrator":
            add_secret("A2A_JWT_PRIVATE_KEY_PEM", "a2a-jwt-private-key-pem")
            add_secret("A2A_API_KEYS_JSON", "a2a-client-api-keys-json")

        c["secrets"] = secrets_list

        # If orchestrator, update internal agent hostnames to Service Connect namespace to avoid Cloud Map conflicts.
        # Example: extractor.a2a (instead of extractor.local)
        if service == "orchestrator":
            ns = os.getenv("SERVICE_CONNECT_NAMESPACE", "a2a")
            for k in ["EXTRACTOR_HOST", "VALIDATOR_HOST", "ARCHIVIST_HOST"]:
                if k in env:
                    base = str(env[k]).split(".")[0]
                    env[k] = f"{base}.{ns}"
            c["environment"] = [{"name": k, "value": str(v)} for k, v in env.items()]

    # Register
    out = aws_json(["ecs", "register-task-definition", "--cli-input-json", json.dumps(td)], profile=profile, region=region)
    return out["taskDefinition"]["taskDefinitionArn"]


def update_service(
    *,
    cluster: str,
    service: str,
    taskdef_arn: str,
    subnets: List[str],
    sgs: List[str],
    enable_service_connect: bool,
    region: str,
    profile: str,
    tls_pca_arn: str | None,
    tls_kms_arn: str | None,
    role_arn_for_tls: str | None,
    port: int,
) -> None:
    sc_cfg: Dict[str, Any] | None = None
    if enable_service_connect:
        sc_service: Dict[str, Any] = {
            "portName": "http",
            "discoveryName": service,
            "clientAliases": [{"port": port, "dnsName": service}],
        }
        if tls_pca_arn and tls_kms_arn and role_arn_for_tls:
            sc_service["tls"] = {
                "issuerCertificateAuthority": {"awsPcaAuthorityArn": tls_pca_arn},
                "kmsKey": tls_kms_arn,
                "roleArn": role_arn_for_tls,
            }
        sc_cfg = {"enabled": True, "namespace": os.getenv("SERVICE_CONNECT_NAMESPACE", "a2a"), "services": [sc_service]}

    cmd = [
        "ecs",
        "update-service",
        "--cluster",
        cluster,
        "--service",
        service,
        "--task-definition",
        taskdef_arn,
        "--network-configuration",
        "awsvpcConfiguration={subnets=[%s],securityGroups=[%s],assignPublicIp=DISABLED}"
        % (",".join(subnets), ",".join(sgs)),
        "--force-new-deployment",
    ]
    if sc_cfg:
        cmd += ["--service-connect-configuration", json.dumps(sc_cfg, separators=(",", ":"))]

    aws(cmd, profile=profile, region=region)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--region", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--cluster", required=True)
    ap.add_argument("--vpc-id", default=None)
    ap.add_argument("--vpc-cidr", default="10.0.0.0/16")
    ap.add_argument("--alb-sg", default=None)
    ap.add_argument("--rds-sg", default=None)
    ap.add_argument("--private-subnets", nargs="+", default=None)
    ap.add_argument("--rds-endpoint", default=None)
    ap.add_argument("--s3-bucket", default=None)
    ap.add_argument("--require-auth", action="store_true", default=True)
    args = ap.parse_args()

    # Resolve basics from ca-a2a-config.env if present
    env_file = Path("ca-a2a-config.env")
    if env_file.exists():
        txt = env_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        kv = {}
        for line in txt:
            if line.startswith("export ") and "=" in line:
                k, v = line[len("export ") :].split("=", 1)
                kv[k.strip()] = v.strip().strip('"')
        args.vpc_id = args.vpc_id or kv.get("VPC_ID")
        args.alb_sg = args.alb_sg or kv.get("ALB_SG")
        args.rds_sg = args.rds_sg or kv.get("RDS_SG")
        args.private_subnets = args.private_subnets or [kv.get("PRIVATE_SUBNET_1"), kv.get("PRIVATE_SUBNET_2")]
        args.rds_endpoint = args.rds_endpoint or kv.get("RDS_ENDPOINT")
        args.s3_bucket = args.s3_bucket or kv.get("S3_BUCKET")

    if not (args.vpc_id and args.alb_sg and args.rds_sg and args.private_subnets and args.rds_endpoint and args.s3_bucket):
        raise SystemExit("Missing required inputs. Provide ca-a2a-config.env or pass --vpc-id/--alb-sg/--rds-sg/--private-subnets/--rds-endpoint/--s3-bucket.")

    # Account id
    ident = aws_json(["sts", "get-caller-identity"], profile=args.profile, region=args.region)
    account_id = ident["Account"]

    # Ensure a dedicated Cloud Map namespace for Service Connect to avoid conflicts with the existing "local" namespace
    # used by classic service discovery.
    sc_namespace = os.getenv("SERVICE_CONNECT_NAMESPACE", "a2a")
    namespaces = aws_json(["servicediscovery", "list-namespaces"], profile=args.profile, region=args.region).get("Namespaces", [])
    if not any(ns.get("Name") == sc_namespace for ns in namespaces):
        aws_json(
            [
                "servicediscovery",
                "create-private-dns-namespace",
                "--name",
                sc_namespace,
                "--vpc",
                args.vpc_id,
                "--description",
                f"{args.project} Service Connect namespace",
            ],
            profile=args.profile,
            region=args.region,
        )
        time.sleep(10)

    # Security secrets
    sec = ensure_security_secrets(args.project, profile=args.profile, region=args.region)

    # Security groups
    sg_map = apply_security_groups(
        args.project, args.vpc_id, args.vpc_cidr, args.alb_sg, args.rds_sg, profile=args.profile, region=args.region
    )

    # Optional Service Connect TLS values from local env (if you created PCA/KMS externally)
    tls_pca = os.getenv("SERVICE_CONNECT_TLS_PCA_ARN") or None
    tls_kms = os.getenv("SERVICE_CONNECT_TLS_KMS_KEY_ARN") or None
    role_arn = f"arn:aws:iam::{account_id}:role/{args.project}-ecs-task-role"

    # Task definitions + service updates
    ports = {"orchestrator": 8001, "extractor": 8002, "validator": 8003, "archivist": 8004}
    for svc in ["orchestrator", "extractor", "validator", "archivist"]:
        base_td = taskdef_arn(svc, profile=args.profile, region=args.region, cluster=args.cluster)
        new_td = register_taskdef_with_security(
            base_taskdef_arn=base_td,
            project=args.project,
            region=args.region,
            account_id=account_id,
            service=svc,
            rds_endpoint=args.rds_endpoint,
            s3_bucket=args.s3_bucket,
            require_auth=args.require_auth,
            profile=args.profile,
        )
        update_service(
            cluster=args.cluster,
            service=svc,
            taskdef_arn=new_td,
            subnets=[s for s in args.private_subnets if s],
            sgs=[sg_map[svc]],
            enable_service_connect=True,
            region=args.region,
            profile=args.profile,
            tls_pca_arn=tls_pca,
            tls_kms_arn=tls_kms,
            role_arn_for_tls=role_arn,
            port=ports[svc],
        )

    # Write summary for later demo PDF
    summary = {
        "account_id": account_id,
        "region": args.region,
        "cluster": args.cluster,
        "project": args.project,
        "alb_sg": args.alb_sg,
        "rds_sg": args.rds_sg,
        "agent_sgs": sg_map,
        "client_api_key": sec["client_api_key"],
        "service_connect_tls": {"pca": tls_pca, "kms": tls_kms},
    }
    Path("security-deploy-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("OK: applied security hardening. Summary: security-deploy-summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

