# 🤖 CA-A2A - Pipeline de Traitement Intelligent de Documents

**Architecture Multi-Agents avec Protocoles A2A et MCP**

[![AWS](https://img.shields.io/badge/AWS-ECS%20%7C%20RDS%20%7C%20S3-orange)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Fargate-blue)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15.7-blue)](https://www.postgresql.org/)

---

## 📋 Vue d'Ensemble

Système de traitement automatisé de documents utilisant une architecture multi-agents déployée sur AWS ECS. Le système orchestre l'extraction, la validation et l'archivage de documents via des protocoles standardisés (A2A et MCP).

### 🎯 Fonctionnalités Principales

- ✅ **Extraction Automatique:** Traitement de PDF, texte, CSV
- ✅ **Validation Intelligente:** Contrôle de qualité et conformité
- ✅ **Archivage Sécurisé:** Stockage S3 avec traçabilité
- ✅ **Orchestration:** Coordination des agents via protocole A2A
- ✅ **Accès Unifié:** MCP pour S3 et PostgreSQL
- ✅ **API REST:** Interface JSON-RPC 2.0

### 🏗️ Architecture

```
Internet → ALB → Orchestrator → [Extractor, Validator, Archivist]
                      ↓
                 [S3, PostgreSQL]
```

**Protocoles:**
- **A2A (Agent-to-Agent):** Communication inter-agents JSON-RPC 2.0
- **MCP (Model Context Protocol):** Accès unifié aux ressources (S3, DB)

---

## 📊 État du Déploiement

| Composant | Statut | Détails |
|-----------|--------|---------|
| Infrastructure AWS | ✅ Déployée | VPC, Subnets, Security Groups |
| ECS Services | ✅ Running | 4 services (8 tasks total) |
| Application Load Balancer | ✅ Active | Accessible publiquement |
| RDS PostgreSQL | ⚠️ Partiellement | Instance active, schéma à init |
| S3 Bucket | ✅ Actif | `ca-a2a-documents` |
| VPC Endpoints | ✅ Configurés | ECR, Logs, SM, S3 |
| CloudWatch Logs | ✅ Actif | 4 log groups |

**📄 Pour plus de détails, voir:** [ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)

---

## 🚀 Quick Start

### 1️⃣ Tester l'API

```bash
# URL de l'ALB
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Health check
curl -s "$ALB_URL/health" | jq '.'

# Obtenir la carte de l'agent (compétences disponibles)
curl -s "$ALB_URL/card" | jq '.'

# Lister les documents en attente
curl -s -X POST "$ALB_URL/message" \
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
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "check_status",
    "params": {"task_id": "TASK_ID_ICI"},
    "id": 3
  }' | jq '.'
```

---

## 📚 Documentation

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

## 🏗️ Architecture Technique

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
│   ├── Orchestrator (2 tasks)
│   ├── Extractor (2 tasks)
│   ├── Validator (2 tasks)
│   └── Archivist (2 tasks)
├── Database Subnet (RDS PostgreSQL)
└── VPC Endpoints (ECR, Logs, SM, S3)
```

**Région:** eu-west-3 (Paris)  
**Compte:** 555043101106

---

## 🔧 Développement Local

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

## 🧪 Tests

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

---

## 📦 Déploiement AWS

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

## 🔍 Monitoring

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

## 📝 API Reference

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

## 🛠️ Configuration

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

## 🐛 Troubleshooting

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

## 📞 Support

- **Documentation Complète:** [ETAT_DU_PROJET.md](./ETAT_DU_PROJET.md)
- **Guide de Démo:** [demo/DEMO_GUIDE.md](./demo/DEMO_GUIDE.md)
- **Contact:** j.benabderrazak@reply.com

---

## 📄 Licence

Propriétaire - Reply S.p.A.

---

**Dernière mise à jour:** 18 Décembre 2025
