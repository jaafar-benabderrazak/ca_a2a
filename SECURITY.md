# Security (CA-A2A)

This document describes the **defense-in-depth** security controls implemented for CA-A2A.

For **step-by-step demo commands** and **captured outputs**, see `DEMO_SECURITY_EVIDENCE.md`.

## Threat model (summary)

- **External abuse** against the public entrypoint (ALB → orchestrator): auth bypass, method abuse, payload/DoS.
- **Internal lateral movement** between agents: forged calls, replay, unauthorized method invocation.
- **Data risks**: secret leakage, unsafe serialization, and DB integrity issues.

## Controls implemented

### Network controls (AWS)

- **Private subnets** for all ECS tasks; only the ALB is internet-facing.
- **Security Groups**: least-privilege ingress between ALB ↔ orchestrator and agent ↔ agent traffic.
- **VPC endpoints / NAT** for controlled egress to AWS services (ECR, Secrets Manager, CloudWatch, S3).

### Application-layer controls (A2A)

- **Authentication**
  - External clients: `X-API-Key`
  - Agent-to-agent: short-lived **JWT** (request-bound)
- **Authorization (RBAC)**: method allow-list by principal (`A2A_RBAC_POLICY_JSON`)
- **Replay protection**: JWT `jti` cache with TTL
- **Rate limiting**: per-principal sliding window
- **Payload size limit**: aiohttp `client_max_size`
- **Capability disclosure minimization**: `/card` and `/skills` can be **RBAC-filtered**

### Data safety / integrity

- **PostgreSQL JSONB safety**: sanitization of `NaN/Inf` → `null` for JSONB compatibility
- **Secrets**: stored in AWS Secrets Manager (no hardcoded credentials)

## Evidence and verification

- Demo + security test evidence: `DEMO_SECURITY_EVIDENCE.md`
- Local unit tests: `pytest -q` (see same evidence doc for current pass count)
