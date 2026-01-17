# Sécurité Réseau CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Architecture VPC

**CIDR :** 10.0.0.0/16  
**Région :** eu-west-3 (Paris)  
**Zones de Disponibilité :** 2 (eu-west-3a, eu-west-3b)

### Sous-réseaux

| Sous-réseau | CIDR | Type | Objectif |
|-------------|------|------|----------|
| Public 1 | 10.0.1.0/24 | Public | ALB, NAT Gateway (AZ-a) |
| Public 2 | 10.0.2.0/24 | Public | ALB, NAT Gateway (AZ-b) |
| Privé 1 | 10.0.11.0/24 | Privé | Agents ECS (AZ-a) |
| Privé 2 | 10.0.12.0/24 | Privé | Agents ECS (AZ-b) |

---

## Security Groups

### ALB Security Group
- **Entrant :** 0.0.0.0/0:443 (HTTPS), 0.0.0.0/0:80 (redirection HTTP)
- **Sortant :** Orchestrateur SG:8001

### Orchestrateur Security Group
- **Entrant :** ALB SG:8001
- **Sortant :** Extracteur:8002, Validateur:8003, Archiviste:8004, Keycloak:8080, MCP:8000

### Security Groups Agents (Extracteur/Validateur/Archiviste)
- **Entrant :** Orchestrateur SG (ports respectifs)
- **Sortant :** Keycloak:8080, MCP:8000

### Keycloak Security Group
- **Entrant :** Tous les SG agents:8080
- **Sortant :** RDS:5432

### Serveur MCP Security Group
- **Entrant :** Tous les SG agents:8000
- **Sortant :** RDS:5432, 0.0.0.0/0:443 (S3)

### RDS Security Group
- **Entrant :** Keycloak SG:5432, MCP SG:5432
- **Sortant :** DENY (pas de sortie nécessaire)

---

## Isolation Réseau

✅ **Sous-réseaux Privés Uniquement :** Pas d'IP publiques pour les agents  
✅ **NAT Gateway :** Accès internet sortant uniquement  
✅ **VPC Endpoints :** S3, Secrets Manager, CloudWatch (pas de routage internet)  
✅ **Découverte de Services :** AWS Cloud Map (*.ca-a2a.local)

---

**Lié :** [Architecture Système](ARCHITECTURE_SYSTEME.md), [Couches de Sécurité](COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md)
