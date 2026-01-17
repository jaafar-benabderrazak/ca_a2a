# CA-A2A Threat Model & Defenses

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## Threat Categories & Defenses

### Authentication Threats
- **Token Theft** → Token Binding (RFC 8473)
- **Forged Tokens** → RS256 signature verification
- **Expired Tokens** → JWT `exp` claim validation
- **Brute Force** → Rate limiting

### Authorization Threats
- **Privilege Escalation** → RBAC enforcement
- **Horizontal Access** → Principal-based filtering
- **Role Manipulation** → Signed JWT (tamper-proof)

### Network Threats
- **MITM** → TLS 1.2+ encryption
- **DDoS** → AWS Shield + Rate limiting
- **Port Scanning** → Security Groups

### Data Threats
- **Data at Rest** → AES-256 encryption
- **SQL Injection** → Parameterized queries
- **Path Traversal** → Regex validation

### Application Threats
- **Replay Attacks** → JWT jti tracking
- **Message Tampering** → Body hash binding
- **DoS** → Rate limiting (300 req/min)
- **Timing Attacks** → Constant-time comparison

---

## STRIDE Analysis

| Threat | Mitigation |
|--------|------------|
| **Spoofing** | RS256 signature + Token Binding |
| **Tampering** | Body hash binding |
| **Repudiation** | Audit logs (CloudWatch) |
| **Information Disclosure** | TLS + AES-256 |
| **Denial of Service** | Rate limiting + Circuit breaker |
| **Elevation of Privilege** | RBAC enforcement |

---

**Related:** [Security Layers](SECURITY_LAYERS_DEFENSE_IN_DEPTH.md), [Security Operations](SECURITY_OPERATIONS.md)
