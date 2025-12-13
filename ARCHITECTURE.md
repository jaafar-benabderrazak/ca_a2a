# Architecture Technique - Pipeline Documentaire Multi-Agents

## Vue d'ensemble

Ce document décrit l'architecture technique du pipeline documentaire intelligent basé sur une architecture multi-agents.

## Composants Principaux

### 1. Protocole A2A (Agent-to-Agent Communication)

**Fichier**: `a2a_protocol.py`

#### Caractéristiques
- Implémentation complète de JSON-RPC 2.0
- Communication asynchrone entre agents
- Gestion des requêtes, réponses, erreurs et notifications
- Système de timeout et retry

#### Classes principales

**A2AMessage**
- Structure de message JSON-RPC 2.0
- Support des requêtes, réponses, erreurs, notifications
- Sérialisation/désérialisation JSON

**A2AProtocol**
- Gestionnaire de protocole
- Enregistrement des handlers pour méthodes
- Gestion des requêtes pendantes
- Routing des messages

#### Format de message

```json
{
  "jsonrpc": "2.0",
  "id": "uuid",
  "method": "method_name",
  "params": {...}
}
```

### 2. Protocole MCP (Model Context Protocol)

**Fichier**: `mcp_protocol.py`

#### S3Resource
- Interface asynchrone pour AWS S3
- Opérations : list, get, put, metadata
- Gestion des erreurs S3
- Support des streaming et pagination

#### PostgreSQLResource
- Pool de connexions asynchrone (asyncpg)
- Opérations : execute, fetch, transaction
- Initialisation automatique du schéma
- Support des requêtes préparées

#### MCPContext
- Context manager pour ressources
- Gestion automatique du cycle de vie
- Initialisation et cleanup coordonné

### 3. BaseAgent

**Fichier**: `base_agent.py`

Classe abstraite fournissant :
- Serveur HTTP (aiohttp)
- Gestion du protocole A2A
- Endpoints standards (/message, /health, /status)
- Lifecycle management (start, stop, run)
- Signal handling pour shutdown gracieux

### 4. Agents Spécialisés

#### Orchestrator Agent
**Port**: 8001  
**Responsabilités**:
- Coordination du pipeline
- Gestion des tâches (création, suivi, erreurs)
- Communication avec tous les autres agents
- Agrégation des résultats

**Méthodes A2A**:
- `process_document` - Lance le traitement d'un document
- `process_batch` - Traite un lot de documents
- `get_task_status` - Obtient le statut d'une tâche
- `list_pending_documents` - Liste les documents en attente

#### Extractor Agent
**Port**: 8002  
**Responsabilités**:
- Téléchargement depuis S3
- Extraction PDF (texte + tableaux)
- Parsing CSV avec inférence de types
- Génération de métadonnées

**Librairies**:
- PyPDF2 : Extraction texte et métadonnées PDF
- pdfplumber : Extraction de tableaux
- pandas : Parsing CSV avancé

**Méthodes A2A**:
- `extract_document` - Extrait les données d'un document
- `list_supported_formats` - Liste les formats supportés

#### Validator Agent
**Port**: 8003  
**Responsabilités**:
- Application de règles de validation
- Calcul de scores pondérés
- Génération de rapports de validation

**Règles de validation**:
- DataCompletenessRule : Vérifie la présence des champs requis
- DataFormatRule : Valide les formats avec regex
- DataQualityRule : Évalue la qualité des données
- DataConsistencyRule : Vérifie la cohérence

**Méthodes A2A**:
- `validate_document` - Valide un document
- `get_validation_rules` - Liste les règles disponibles

#### Archivist Agent
**Port**: 8004  
**Responsabilités**:
- Persistence dans PostgreSQL
- Gestion des métadonnées
- Journalisation (audit logs)
- Recherche et statistiques

**Méthodes A2A**:
- `archive_document` - Archive un document
- `get_document` - Récupère un document
- `update_document_status` - Met à jour le statut
- `search_documents` - Recherche des documents
- `get_document_stats` - Statistiques globales

## Flux de Traitement

### 1. Initialisation
```
Client → POST /message → Orchestrator
  Method: process_document
  Params: { s3_key, priority }
```

### 2. Extraction
```
Orchestrator → POST /message → Extractor
  Method: extract_document
  Params: { s3_key }
  
Extractor:
  1. Télécharge depuis S3 (MCP)
  2. Détecte le type (PDF/CSV)
  3. Extrait les données
  4. Retourne { extracted_data, metadata }
```

### 3. Validation
```
Orchestrator → POST /message → Validator
  Method: validate_document
  Params: { s3_key, extracted_data, document_type }
  
Validator:
  1. Sélectionne les règles appropriées
  2. Applique chaque règle
  3. Calcule le score pondéré
  4. Retourne { score, status, details }
```

### 4. Archivage
```
Orchestrator → POST /message → Archivist
  Method: archive_document
  Params: { s3_key, extracted_data, validation_score, ... }
  
Archivist:
  1. Insère/met à jour dans PostgreSQL (MCP)
  2. Log l'action
  3. Retourne { document_id, status }
```

### 5. Réponse Finale
```
Orchestrator → Client
  Result: { task_id, status, document_id }
```

## Schéma de Base de Données

### Table: documents
```sql
CREATE TABLE documents (
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
);
```

**Index**:
- `idx_documents_s3_key` sur s3_key
- `idx_documents_status` sur status
- `idx_documents_type` sur document_type
- `idx_documents_date` sur processing_date

### Table: processing_logs
```sql
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

**Index**:
- `idx_logs_document_id` sur document_id
- `idx_logs_agent` sur agent_name

## Gestion des Erreurs

### Codes d'erreur JSON-RPC

**Standards**:
- -32700 : Parse error
- -32600 : Invalid request
- -32601 : Method not found
- -32602 : Invalid params
- -32603 : Internal error

**Personnalisés**:
- -32001 : Extraction error
- -32002 : Validation error
- -32003 : Persistence error
- -32004 : S3 error
- -32005 : Database error

### Stratégie de retry
- Orchestrator : 3 tentatives avec backoff exponentiel
- MCP operations : Retry automatique sur erreurs transitoires
- Timeout : 30s par défaut pour les requêtes inter-agents

## Scalabilité

### Horizontal Scaling
- Chaque agent peut être déployé en plusieurs instances
- Load balancing via reverse proxy (nginx/haproxy)
- Session affinity non requise (stateless)

### Vertical Scaling
- Pool de connexions PostgreSQL ajustable
- Concurrence async (asyncio)
- Streaming pour gros fichiers

### Performance
- Traitement asynchrone end-to-end
- Pool de connexions réutilisables
- Pagination pour requêtes bulk
- Index base de données optimisés

## Sécurité

### Authentication
- À implémenter : JWT tokens
- API keys pour clients
- mTLS pour communication inter-agents

### Authorization
- IAM roles AWS avec permissions minimales
- PostgreSQL : row-level security
- Validation des paramètres d'entrée

### Audit
- Tous les événements loggés
- Table processing_logs pour traçabilité
- Horodatage de toutes les opérations

## Monitoring

### Métriques
- `/health` : Liveness probe
- `/status` : Métriques agent-spécifiques
- Logs structurés (JSON)

### Observabilité
- Intégration Prometheus (à venir)
- Distributed tracing (OpenTelemetry)
- Dashboards Grafana

## Déploiement

### Docker
```dockerfile
FROM python:3.9-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
WORKDIR /app
CMD ["python", "orchestrator_agent.py"]
```

### Kubernetes
- Déploiement : 1 deployment par agent
- Service : ClusterIP pour communication interne
- Ingress : Exposition de l'orchestrateur
- ConfigMap : Configuration
- Secret : Credentials

### Cloud-Native
- AWS ECS/Fargate
- AWS RDS for PostgreSQL
- AWS S3 (existant)
- AWS CloudWatch Logs

