# Pipeline Documentaire Intelligent Multi-Agents - Documentation Complète

## 📚 Table des Matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [API Reference](#api-reference)
5. [Agent Cards & Skills](#agent-cards--skills)
6. [Best Practices A2A](#best-practices-a2a)
7. [Déploiement AWS](#déploiement-aws)

---

## Vue d'ensemble

Un système de traitement documentaire distribué basé sur une architecture multi-agents autonomes, utilisant les protocoles A2A (Agent-to-Agent) et MCP (Model Context Protocol).

### 🏗️ Composants Principaux

- **4 Agents Spécialisés** : Orchestrateur, Extracteur, Validateur, Archiviste
- **Protocoles** : A2A (JSON-RPC 2.0), MCP (S3 + PostgreSQL)
- **Agent Cards** : Auto-description et découverte des capacités
- **Best Practices** : Retry, circuit breakers, idempotency, structured logging

---

## Architecture

### Flux de Traitement

```
Client → Orchestrator → Extractor → Validator → Archivist
             ↓            ↓                        ↓
          Tracking      S3 (MCP)             PostgreSQL (MCP)
```

### Agents

| Agent | Port | Responsabilités |
|-------|------|-----------------|
| **Orchestrateur** | 8001 | Coordination du pipeline, gestion des tâches |
| **Extracteur** | 8002 | Extraction PDF/CSV depuis S3 |
| **Validateur** | 8003 | Validation et scoring (0-100) |
| **Archiviste** | 8004 | Persistence PostgreSQL avec audit |

### Protocoles

#### A2A (Agent-to-Agent) - JSON-RPC 2.0
- Communication inter-agents asynchrone
- Format standardisé pour requêtes/réponses
- Gestion des erreurs et timeouts
- Support des notifications

#### MCP (Model Context Protocol)
- Interface unifiée pour S3 et PostgreSQL
- Gestion des connexions et pools
- Opérations asynchrones
- Retry logic et circuit breakers

### Schéma de Base de Données

```sql
-- Table documents
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    s3_key VARCHAR(500) UNIQUE NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    validation_score FLOAT,
    metadata JSONB,
    extracted_data JSONB,
    validation_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table processing_logs
CREATE TABLE processing_logs (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    agent_name VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Installation

### Prérequis

- Python 3.9+
- PostgreSQL 12+
- Accès AWS S3

### Configuration

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos credentials

# 3. Initialiser la base de données
createdb documents_db
python init_db.py init

# 4. Démarrer tous les agents
python run_agents.py
```

### Variables d'Environnement

```env
# AWS
AWS_ACCESS_KEY_ID=votre_access_key
AWS_SECRET_ACCESS_KEY=votre_secret_key
S3_BUCKET_NAME=votre-bucket

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_DB=documents_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=votre_password
```

### Utilisation

```bash
# Traiter un document
python client.py process "documents/rapport.pdf"

# Traiter un lot
python client.py batch --prefix "documents/" --extension ".pdf"

# Vérifier le statut
python client.py status <task_id>

# Vérifier la santé
python client.py health
```

---

## API Reference

### Tous les Agents

#### GET /health
Vérification de santé avec statut des dépendances
```json
{
  "status": "healthy|degraded|unhealthy",
  "agent": "AgentName",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "dependencies": {...}
}
```

#### GET /status
Statut et métriques de performance
```json
{
  "agent": "AgentName",
  "status": "running",
  "performance": {
    "metrics_by_skill": {...}
  }
}
```

#### GET /card
Carte complète de l'agent avec toutes ses capacités

#### GET /skills
Liste des compétences de l'agent

### Orchestrator (http://localhost:8001)

#### POST /message - Méthodes A2A

**process_document**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "process_document",
  "params": {
    "s3_key": "documents/rapport.pdf",
    "priority": "normal"
  }
}
```

**process_batch**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "process_batch",
  "params": {
    "prefix": "documents/2024/",
    "file_extension": ".pdf"
  }
}
```

**get_task_status**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "get_task_status",
  "params": {
    "task_id": "uuid"
  }
}
```

**discover_agents** ✨
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "discover_agents",
  "params": {}
}
```

### Extractor (http://localhost:8002)

**extract_document**
- Extrait les données d'un document PDF ou CSV
- Retourne: extracted_data, metadata, document_type

### Validator (http://localhost:8003)

**validate_document**
- Valide un document avec règles configurables
- Retourne: score (0-100), status, details

Statuts:
- excellent (90-100)
- good (75-89)
- acceptable (60-74)
- poor (40-59)
- failed (0-39)

### Archivist (http://localhost:8004)

**archive_document**
- Archive un document dans PostgreSQL
- Support de l'idempotency (safe retry)

**search_documents**
- Recherche avancée avec filtres
- Pagination support

**get_document_stats**
- Statistiques globales

---

## Agent Cards & Skills

### Qu'est-ce qu'une Agent Card ?

Chaque agent se décrit lui-même avec :
- Identité (nom, version, description)
- Compétences (skills) avec schémas JSON
- Ressources requises (CPU, mémoire)
- Dépendances (services, bibliothèques)

### Structure d'une Agent Card

```json
{
  "agent_id": "extractor-12345",
  "name": "Extractor",
  "version": "1.0.0",
  "description": "Extracts structured data from PDF and CSV documents",
  "endpoint": "http://extractor.local:8002",
  "skills": [
    {
      "skill_id": "extract_document",
      "name": "Document Extraction",
      "method": "extract_document",
      "input_schema": {...},
      "output_schema": {...},
      "avg_processing_time_ms": 2500
    }
  ],
  "resources": {
    "memory_mb": 1024,
    "cpu_cores": 1.0
  },
  "dependencies": {
    "services": ["s3"],
    "libraries": ["PyPDF2", "pdfplumber"]
  }
}
```

### Découverte d'Agents

```bash
# Découvrir tous les agents
python discover_agents.py

# Obtenir la carte d'un agent
curl http://localhost:8002/card | jq

# Obtenir le registre des agents
curl -X POST http://localhost:8001/message -d '{
  "jsonrpc": "2.0",
  "method": "get_agent_registry",
  "params": {}
}'
```

### Skills par Agent

**Orchestrator** (6 skills)
1. process_document - Traitement de document
2. process_batch - Traitement par lot
3. get_task_status - Statut des tâches
4. list_pending_documents - Liste des documents en attente
5. discover_agents - Découverte des agents
6. get_agent_registry - Registre des agents

**Extractor** (5 skills)
1. extract_document - Extraction principale
2. pdf_text_extraction - Extraction de texte PDF
3. pdf_table_extraction - Extraction de tableaux PDF
4. csv_parsing - Parsing CSV avec statistiques
5. list_supported_formats - Formats supportés

**Validator** (6 skills)
1. validate_document - Validation principale
2. data_completeness_check - Vérification de complétude
3. data_format_validation - Validation de format
4. data_quality_assessment - Évaluation de qualité
5. data_consistency_check - Vérification de cohérence
6. get_validation_rules - Règles de validation

**Archivist** (6 skills)
1. archive_document - Archivage
2. get_document - Récupération
3. update_document_status - Mise à jour de statut
4. search_documents - Recherche avancée
5. get_document_stats - Statistiques
6. audit_logging - Journal d'audit

---

## Best Practices A2A

### 1. JSON Schema Validation ✅

Tous les skills définissent des schémas d'entrée/sortie :
```python
AgentSkill(
    skill_id='extract_document',
    input_schema={
        'type': 'object',
        'required': ['s3_key'],
        'properties': {
            's3_key': {'type': 'string'}
        }
    }
)
```

### 2. Retry Logic avec Exponential Backoff ✅

```python
await retry_with_backoff(
    func=my_operation,
    max_retries=3,
    base_delay=1.0  # 1s, 2s, 4s
)
```

### 3. Circuit Breaker Pattern ✅

```python
CircuitBreaker(
    failure_threshold=5,      # Open après 5 échecs
    recovery_timeout=60,      # Test de récupération après 60s
    expected_exception=ClientError
)
```

### 4. Idempotency Support ✅

```python
# Opérations d'écriture sûres à réessayer
idempotency_key = generate_idempotency_key('archive', params)
cached = idempotency_store.get(idempotency_key)
if cached:
    return cached
```

### 5. Structured Logging ✅

```json
{
  "timestamp": "2025-12-13T...",
  "agent": "Extractor",
  "method": "extract_document",
  "correlation_id": "2025-12-13-a1b2c3d4",
  "duration_ms": 2500,
  "success": true
}
```

### 6. Correlation IDs ✅

```bash
# Traçage des requêtes de bout en bout
curl -H "X-Correlation-ID: test-123" \
  -X POST http://localhost:8001/message \
  -d '{"jsonrpc":"2.0","method":"process_document",...}'
```

### 7. Timeout Protection ✅

```python
@timeout_decorator(30.0)  # 30s timeout
async def get_object(key: str):
    # Opération S3
```

### 8. Enhanced Health Checks ✅

Les checks incluent maintenant le statut des dépendances :
- S3 bucket accessible
- PostgreSQL connecté
- Retour HTTP 200 (healthy) ou 503 (degraded)

### 9. Performance Monitoring ✅

```json
{
  "extract_document": {
    "total_requests": 1000,
    "successful_requests": 980,
    "avg_duration_ms": 2500,
    "success_rate": 0.98
  }
}
```

---

## Déploiement AWS

### Architecture Recommandée (ECS Fargate)

```
AWS Cloud
├── VPC
│   ├── Public Subnet (ALB)
│   └── Private Subnet
│       ├── Orchestrator (8001)
│       ├── Extractor (8002)
│       ├── Validator (8003)
│       └── Archivist (8004)
├── RDS PostgreSQL
├── S3 Bucket
├── Cloud Map (Service Discovery)
└── CloudWatch (Logs & Metrics)
```

### Déploiement Rapide avec AWS Copilot

```bash
# Installation
brew install aws/tap/copilot-cli

# Initialisation
cd ca_a2a
copilot app init ca-a2a

# Déployer les services
copilot svc init --name orchestrator --svc-type "Load Balanced Web Service"
copilot svc init --name extractor --svc-type "Backend Service"
copilot svc init --name validator --svc-type "Backend Service"
copilot svc init --name archivist --svc-type "Backend Service"

# Déployer
copilot deploy --all
```

### Service Discovery avec Cloud Map

Avantages :
- Découverte automatique des agents
- Résolution DNS (extractor.local, validator.local)
- Health checks intégrés
- Pas de configuration manuelle

### Monitoring CloudWatch

**Métriques à suivre :**
- Latence par skill (p50, p95, p99)
- Taux d'erreur par agent
- État des circuit breakers
- Taux de succès idempotency cache
- Utilisation CPU/Mémoire

**Requêtes CloudWatch Logs Insights :**
```sql
-- Tracer une requête de bout en bout
fields @timestamp, agent, method, duration_ms
| filter correlation_id = "2025-12-13-a1b2c3d4"
| sort @timestamp asc

-- Latence moyenne par skill
fields method, avg(duration_ms) as avg_latency
| filter agent = "Extractor"
| stats avg(duration_ms) by method
```

### Estimation des Coûts (us-east-1)

| Service | Configuration | Coût Mensuel |
|---------|--------------|--------------|
| ECS Fargate (4 tasks) | 0.5 vCPU, 1GB RAM | $30 |
| RDS PostgreSQL | db.t3.medium | $50 |
| Application Load Balancer | 1 ALB | $20 |
| S3 Storage | 100GB | $5 |
| CloudWatch | 10GB logs | $5 |
| Data Transfer | 50GB | $5 |
| **Total** | | **~$115/mois** |

### Optimisation des Coûts

1. **Fargate Spot** pour les environnements non-critiques (70% d'économies)
2. **RDS Reserved Instances** (40% d'économies sur 1 an)
3. **S3 Lifecycle Policies** vers Glacier après 90 jours
4. **CloudWatch Log Retention** à 7 jours pour dev/test
5. **Auto-scaling** pour réduire la capacité hors heures de pointe

### Sécurité

**IAM Roles :**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::ca-a2a-documents/*"
  }]
}
```

**Secrets Manager :**
```bash
# Stocker les credentials
aws secretsmanager create-secret \
  --name ca-a2a/postgres-password \
  --secret-string "your-secure-password"
```

**Network Security :**
- VPC privée pour les agents
- ALB publique avec HTTPS
- Security groups restreints
- VPC Endpoints pour S3 (pas de trafic internet)

### Production Checklist

- [ ] Multi-AZ deployment pour haute disponibilité
- [ ] RDS Multi-AZ avec backups automatiques
- [ ] SSL/TLS sur ALB avec certificat ACM
- [ ] Secrets Manager pour tous les credentials
- [ ] CloudWatch alarms configurés
- [ ] Auto-scaling basé sur CPU/mémoire
- [ ] Health checks configurés (grace period 60s)
- [ ] Container Insights activé
- [ ] VPC Flow Logs activés
- [ ] AWS Backup configuré

---

## Troubleshooting

### Agent ne démarre pas
```bash
# Vérifier les ports
netstat -ano | findstr "8001 8002 8003 8004"

# Voir les logs
tail -f agents.log
```

### Erreur S3
```bash
# Tester les credentials
aws s3 ls s3://your-bucket/

# Vérifier les permissions IAM
aws iam get-user
```

### Erreur PostgreSQL
```bash
# Tester la connexion
psql -h localhost -U postgres -d documents_db

# Réinitialiser
python init_db.py reset
```

### Performance Issues
```bash
# Vérifier les métriques
curl http://localhost:8002/status | jq '.performance'

# Voir les logs de performance
grep "duration_ms" agents.log | sort -t: -k3 -n | tail
```

---

## Support

### Documentation
- Code source : `ca_a2a/`
- Scripts utilitaires : `client.py`, `run_agents.py`, `discover_agents.py`
- Tests : `test_pipeline.py`, `examples.py`

### Liens Utiles
- **A2A Protocol** : https://a2a-protocol.org/
- **JSON Schema** : https://json-schema.org/
- **AWS ECS Best Practices** : https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/

---

**Version** : 1.0.0  
**Dernière mise à jour** : Décembre 2025  
**Statut** : ✅ Production Ready
