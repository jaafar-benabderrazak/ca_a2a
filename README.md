# CA-A2A - Pipeline de Traitement Intelligent de Documents

**Architecture Multi-Agents avec Protocoles A2A et MCP**

[![AWS](https://img.shields.io/badge/AWS-ECS%20%7C%20RDS%20%7C%20S3-orange)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Fargate-blue)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15.7-blue)](https://www.postgresql.org/)

---

## Vue d'Ensemble

Système de traitement automatisé de documents utilisant une architecture multi-agents déployée sur AWS ECS. Le système orchestre l'extraction, la validation et l'archivage de documents via des protocoles standardisés (A2A et MCP).

### Fonctionnalités Principales

- **Extraction Automatique:** Traitement de PDF, texte, CSV
- **Validation Intelligente:** Contrôle de qualité et conformité
- **Archivage Sécurisé:** Stockage S3 avec traçabilité
- **Orchestration:** Coordination des agents via protocole A2A
- **Accès Unifié:** MCP pour S3 et PostgreSQL
- **API REST:** Interface JSON-RPC 2.0
- **Sécurité Production:** TLS/mTLS, RBAC, Rate Limiting, HMAC, Zero-Trust

### Demo & Présentation

** Guides de Démonstration:**

** Démonstration Narrative (2 heures) - RECOMMANDÉ:**
- **[DEMO_HISTOIRE_2H.md](./DEMO_HISTOIRE_2H.md)** 🇫🇷 **NOUVEAU !** - Démonstration basée sur une histoire captivante
 - **Scénario**: La facture mystérieuse de ACME Corporation
 - **Format**: 7 actes suivant le cycle de vie complet d'un document
 - **Contenu**: 15+ diagrammes Mermaid détaillés, 30+ références à l'article de recherche
 - **Durée**: 2 heures de présentation structurée
 - **Public**: Stakeholders techniques et métier
 - **Points forts**: Explications en contexte, démos interactives, scénarios d'attaque

** Guides de Démonstration Complets:**
- **[COMPLETE_DEMO_GUIDE.md](./COMPLETE_DEMO_GUIDE.md)** 🇬🇧 (English) - Complete demonstration guide with all features and security testing
- **[GUIDE_DEMO_COMPLET.md](./GUIDE_DEMO_COMPLET.md)** 🇫🇷 (Français) - Guide de démonstration complet avec toutes les fonctionnalités et tests de sécurité

**Contenu des Guides Complets:**
- **70/70 tests réussis** (100% success rate)
- Architecture complète avec 10+ diagrammes Mermaid détaillés
- 20 scénarios de tests de sécurité (Authentication, HMAC, Replay Prevention, Rate Limiting, Zero-Trust, Anomaly Detection, RBAC, Audit Logging)
- 19 tests fonctionnels (Document processing, Multi-agent collaboration, MCP operations)
- 10 tests de performance (Latency, Throughput, Resource utilization)
- Commandes PowerShell et bash prêtes à l'emploi pour AWS
- Référence complète au document de recherche "Securing Agent-to-Agent (A2A) Communications Across Domains.pdf"
- Validation des 5 modèles de menaces: MITM, Data Tampering, Replay Attacks, Unauthorized Access, Identity Spoofing
- Conformité OWASP API Security Top 10 & NIST Cybersecurity Framework
- Tests pipeline de bout en bout avec métriques de performance
- Observabilité complète avec CloudWatch dashboards, alarmes et analyse de logs

**▶️ Lancement rapide de la démo:**
```powershell
# Vérifier l'infrastructure AWS (77% tests réussis)
.\test-aws-complete.ps1 -Profile AWSAdministratorAccess-555043101106

# Consulter les guides:
# Démonstration narrative (2h): DEMO_HISTOIRE_2H.md
# Guide complet anglais: COMPLETE_DEMO_GUIDE.md
# Guide complet français: GUIDE_DEMO_COMPLET.md
```

### ️ Architecture

```
Internet → ALB → Orchestrator → [Extractor, Validator, Archivist]
 ↓ ↓ ↓ ↓
 MCP Server ←──────┴─────────┴──────────┘
 ↓
 [S3, PostgreSQL]
```

**Protocoles:**
- **A2A (Agent-to-Agent):** Communication inter-agents JSON-RPC 2.0
- **MCP (Model Context Protocol):** Accès unifié aux ressources (S3, DB)
 - ** Architecture Serveur MCP Centralisé** ([Guide de Migration](./MCP_MIGRATION_GUIDE.md))
 - **Serveur HTTP**: Port 8000, API REST pour accès distribué
 - **Sélection Automatique**: stdio (local) ou HTTP (AWS) selon l'environnement
 - **Resources**: S3 bucket, PostgreSQL database
 - **Tools**: 8 tools (S3 ops, DB queries, schema init, document management)
 - **Deploy Local**: `docker-compose up mcp-server`
 - **Deploy AWS**: `.\Deploy-MCPServer.ps1` puis `.\Update-AgentsWithMCP.ps1`

---

## État du Déploiement

| Composant | Statut | Détails |
|-----------|--------|---------|
| Infrastructure AWS | Déployée | VPC, Subnets, Security Groups |
| ECS Services | Running | 5 services (orchestrator, extractor, validator, archivist, mcp-server) |
| Application Load Balancer | Active | Accessible publiquement |
| RDS PostgreSQL | Active | Instance active, schéma initialisé |
| S3 Bucket | Actif | `ca-a2a-documents` |
| MCP Server | ️ Running | Port 8000, 2 tasks (health check issues) |
| VPC Endpoints | Configurés | ECR, Logs, SM, S3 |
| CloudWatch Logs | Actif | 5 log groups |
| **Test Suite** | **77%** | **23/30 tests passed** |

** Pour plus de détails, voir:** [ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)

---

## Quick Start

### 1️⃣ Tester l'API

```bash
# URL de l'ALB
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# (If A2A auth is enabled) API key for /message
# - With deploy scripts, you can source it from the generated env file:
# source /tmp/ca-a2a-config.env
# export A2A_API_KEY="$A2A_CLIENT_API_KEY"
export A2A_API_KEY="${A2A_API_KEY:-}"

# Health check
curl -s "$ALB_URL/health" | jq '.'

# Obtenir la carte de l'agent (compétences disponibles)
curl -s "$ALB_URL/card" | jq '.'

# Lister les documents en attente
curl -s -X POST "$ALB_URL/message" \
 ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
 -H "Content-Type: application/json" \
 -d '{
 "jsonrpc": "2.0",
 "method": "list_pending_documents",
 "params": {"limit": 10},
 "id": 1
 }' | jq '.'
```

### 2️⃣ Traiter un Document

```bash
# 1. Uploader un fichier
echo "Invoice #12345 - Total: $500" > test.txt
aws s3 cp test.txt s3://ca-a2a-documents/uploads/ --region eu-west-3

# 2. Lancer le traitement
curl -s -X POST "$ALB_URL/message" \
 ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
 -H "Content-Type: application/json" \
 -d '{
 "jsonrpc": "2.0",
 "method": "process_document",
 "params": {
 "s3_key": "uploads/test.txt",
 "document_type": "invoice"
 },
 "id": 2
 }' | jq '.'

# 3. Vérifier le statut
curl -s -X POST "$ALB_URL/message" \
 ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
 -H "Content-Type: application/json" \
 -d '{
 "jsonrpc": "2.0",
 "method": "check_status",
 "params": {"task_id": "TASK_ID_ICI"},
 "id": 3
 }' | jq '.'
```

---

## Documentation

### Documents Essentiels
1. **[ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)** - État complet du projet avec plan d'action 🇫🇷
2. **[AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md)** - Architecture technique détaillée
3. **[API_TESTING_GUIDE.md](./API_TESTING_GUIDE.md)** - Guide de test de l'API
4. **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Résolution de problèmes

### Scripts Utiles
- **`e2e-test-suite.sh`** - Suite de tests end-to-end
- **`scripts/deploy-aws-infrastructure.ps1`** - Déploiement automatisé
- **`demo/setup-demo.ps1`** - Configuration de la démo

---

## ️ Architecture Technique

### Agents

| Agent | Rôle | Port | Compétences |
|-------|------|------|-------------|
| **Orchestrator** | Coordination | 8001 | process_document, check_status, list_documents |
| **Extractor** | Extraction | 8002 | extract_text, extract_pdf, extract_csv |
| **Validator** | Validation | 8003 | validate_structure, validate_content |
| **Archivist** | Archivage | 8004 | archive_document, retrieve_document |

### Infrastructure AWS

```
VPC (10.0.0.0/16)
├── Public Subnets (ALB + IGW)
├── Private Subnets (ECS Tasks)
│ ├── Orchestrator (2 tasks)
│ ├── Extractor (2 tasks)
│ ├── Validator (2 tasks)
│ └── Archivist (2 tasks)
├── Database Subnet (RDS PostgreSQL)
└── VPC Endpoints (ECR, Logs, SM, S3)
```

**Région:** eu-west-3 (Paris) 
**Compte:** 555043101106

---

## Développement Local

### Prérequis
- Python 3.9+
- Docker & Docker Compose
- AWS CLI configuré

### Installation

```bash
# 1. Cloner le repo
git clone <repo-url>
cd ca_a2a

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer l'environnement
cp ca-a2a-config.env .env
# Éditer .env avec vos credentials

# 4. Démarrer PostgreSQL local
docker-compose up postgres -d

# 5. Initialiser la base de données
python init_db.py init

# 6. Lancer les agents
python run_agents.py
```

---

## Tests

### Démonstration Sécurité (Recommandé)
```powershell
# Demo complète avec tous les scénarios de sécurité
.\scripts\run_demo_scenarios.ps1

# Mode rapide (sans rate limiting ni pipeline)
.\scripts\run_demo_scenarios.ps1 -QuickMode
```

**Documentation**: [DEMO_PRESENTATION_GUIDE.md](./DEMO_PRESENTATION_GUIDE.md)

### Test Unitaires
```bash
pytest
```

### Test End-to-End
```bash
# Dans CloudShell AWS
./e2e-test-suite.sh
```

### Test API Manuel
Voir [API_TESTING_GUIDE.md](./API_TESTING_GUIDE.md)

### Résultats de Tests
- [E2E_TEST_REPORT_20260101.md](./E2E_TEST_REPORT_20260101.md) - Tests end-to-end complets
- [TEST_RESULTS.md](./TEST_RESULTS.md) - Tests unitaires et d'intégration

### 🆕 Test MCP Server
```powershell
# Démarrer le serveur MCP
.\mcp_deploy.ps1 start

# Tester la connexion et les outils
.\mcp_deploy.ps1 test

# Ou utiliser le script Python de tests
python test_mcp_server.py
```

**Documentation**: [MCP_SERVER_GUIDE.md](./MCP_SERVER_GUIDE.md)

---

## MCP Server (Model Context Protocol)

### Qu'est-ce que MCP?

Le **Model Context Protocol** est un standard ouvert permettant aux agents AI d'accéder de manière unifiée à des ressources externes (S3, bases de données, APIs, etc.).

### Architecture MCP

```
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Orchestrator │ │ Extractor │ │ Archivist │
│ (MCP Client) │ │ (MCP Client) │ │ (MCP Client) │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
 │ │ │
 └─────────────────────┼─────────────────────┘
 │ MCP Protocol
 ┌────────▼─────────┐
 │ MCP Server │
 │ • 2 Resources │
 │ • 7 Tools │
 │ • Circuit Break │
 └────────┬─────────┘
 ┌─────────────┴─────────────┐
 │ │
 ┌───▼───┐ ┌────▼─────┐
 │ S3 │ │PostgreSQL│
 └───────┘ └──────────┘
```

### Resources MCP (2)

1. **S3 Bucket**: `s3://ca-a2a-documents-555043101106/`
2. **PostgreSQL DB**: `postgres://.../documents_db`

### Tools MCP (7)

- **S3**: `s3_list_objects`, `s3_get_object`, `s3_put_object`
- **PostgreSQL**: `postgres_query`, `postgres_execute`
- **High-Level**: `document_store`, `document_list`

### Quick Start MCP

```powershell
# 1. Démarrer le serveur
.\mcp_deploy.ps1 start

# 2. Vérifier le statut
.\mcp_deploy.ps1 status

# 3. Tester les outils
.\mcp_deploy.ps1 test

# 4. Voir les logs
Get-Content mcp_server.log -Wait -Tail 20
```

### Utilisation dans les Agents

```python
# Option 1: Utiliser le client MCP (nouveau)
from mcp_client import MCPContext

async with MCPContext() as mcp:
 objects = await mcp.s3.list_objects(prefix="incoming/")
 docs = await mcp.postgres.list_documents(status="pending")

# Option 2: Accès direct (existant)
from mcp_protocol import MCPContext

async with MCPContext() as mcp:
 objects = await mcp.s3.list_objects(prefix="incoming/")
 docs = await mcp.postgres.fetch_all("SELECT * FROM documents")
```

**Interface compatible**: Le client MCP utilise la même interface que l'accès direct!

### Quand Utiliser MCP Server?

 **Utiliser MCP Server** quand:
- Plusieurs agents partagent les mêmes ressources
- Monitoring/logging centralisé requis
- Interopérabilité avec d'autres outils MCP nécessaire
- Gestion de pool de connexions importante

 **Utiliser Accès Direct** quand:
- Ultra-faible latence requise (< 1ms)
- Agent unique, pas de partage de ressources
- Déploiement simple (pas de gestion de serveur)

**Documentation complète**: [MCP_SERVER_GUIDE.md](./MCP_SERVER_GUIDE.md)

---

## Déploiement AWS

### Déploiement Complet

```powershell
# PowerShell
cd scripts
.\deploy-aws-infrastructure.ps1
```

### Mise à Jour des Services

```bash
# Rebuild images
docker build -t orchestrator -f Dockerfile.orchestrator .
docker tag orchestrator 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest
docker push 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest

# Force redeploy
aws ecs update-service \
 --cluster ca-a2a-cluster \
 --service orchestrator \
 --force-new-deployment \
 --region eu-west-3
```

---

## Monitoring

### Logs CloudWatch
```bash
# Orchestrator
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# Extractor
aws logs tail /ecs/ca-a2a-extractor --follow --region eu-west-3
```

### Métriques ECS
```bash
# Statut des services
aws ecs describe-services \
 --cluster ca-a2a-cluster \
 --services orchestrator extractor validator archivist \
 --region eu-west-3
```

### Health Checks
```bash
curl -s http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

---

## API Reference

### Endpoints

#### Health Check
```http
GET /health
```

#### Agent Card
```http
GET /card
```

#### Process Document (JSON-RPC)
```http
POST /message
Content-Type: application/json

{
 "jsonrpc": "2.0",
 "method": "process_document",
 "params": {
 "s3_key": "uploads/document.pdf",
 "document_type": "invoice"
 },
 "id": 1
}
```

**Méthodes disponibles:**
- `process_document` - Traiter un document complet
- `check_status` - Vérifier le statut d'une tâche
- `list_pending_documents` - Lister les documents en attente
- `get_agent_registry` - Obtenir la liste des agents disponibles

---

## ️ Configuration

### Variables d'Environnement

```bash
# Base de données
POSTGRES_HOST=ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<from-secrets-manager>
POSTGRES_DB=documents_db

# AWS
AWS_REGION=eu-west-3
S3_BUCKET=ca-a2a-documents

# Agents (pour dev local)
ORCHESTRATOR_HOST=localhost
ORCHESTRATOR_PORT=8001
```

---

## Troubleshooting

### Problème: API retourne "relation does not exist"
**Solution:** Initialiser le schéma de la base de données
```bash
# Voir ETAT_DU_PROJET.md section "Plan d'Action Prioritaire"
```

### Problème: ECS tasks ne démarrent pas
**Solution:** Vérifier les logs CloudWatch
```bash
aws logs tail /ecs/ca-a2a-orchestrator --since 30m --region eu-west-3
```

### Problème: ALB timeout
**Solution:** Vérifier que les targets sont healthy
```bash
aws elbv2 describe-target-health \
 --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
 --region eu-west-3
```

**Plus de solutions:** [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)

---

## Documentation

### Core Documentation

- **[README.md](./README.md)** - Vous êtes ici
- **[COMPLETE_DEMO_GUIDE.md](./COMPLETE_DEMO_GUIDE.md)** 🇬🇧 - Complete demonstration guide (70/70 tests, all features)
- **[GUIDE_DEMO_COMPLET.md](./GUIDE_DEMO_COMPLET.md)** 🇫🇷 - Guide de démonstration complet (version française)
- **[Securing Agent-to-Agent (A2A) Communications Across Domains.pdf](./Securing%20Agent-to-Agent%20(A2A)%20Communications%20Across%20Domains.pdf)** - Research paper reference

### Security Documentation

- **[SECURITY_GUIDE.md](./SECURITY_GUIDE.md)** - Complete security implementation guide
- **[SECURITY_IMPLEMENTATION.md](./SECURITY_IMPLEMENTATION.md)** - Detailed security implementation

### MCP Server Documentation

- **[MCP_SERVER_GUIDE.md](./MCP_SERVER_GUIDE.md)** - MCP server architecture and usage
- **[MCP_MIGRATION_GUIDE.md](./MCP_MIGRATION_GUIDE.md)** - Migration guide from library to server

### ️ AWS & Infrastructure

- **[AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md)** - AWS infrastructure architecture
- **[SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md)** - System-level architecture
- **[ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)** 🇫🇷 - État actuel du projet (French)
- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Common issues and solutions

---

## Support

- **Documentation Complète:** [ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)
- **Guide de Démo:** [demo/DEMO_GUIDE.md](./demo/DEMO_GUIDE.md)
- **Contact:** j.benabderrazak@reply.com

---

## Licence

Propriétaire - Reply S.p.A.

---

**Dernière mise à jour:** 18 Décembre 2025
