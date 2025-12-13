# INDEX - Pipeline Documentaire Intelligent Multi-Agents

## 📁 Structure du Projet

```
ca_a2a/
│
├── 🔧 CORE PROTOCOLS
│   ├── a2a_protocol.py          # JSON-RPC 2.0 Agent-to-Agent Protocol
│   └── mcp_protocol.py          # Model Context Protocol (S3 + PostgreSQL)
│
├── 🤖 AGENTS
│   ├── base_agent.py            # Classe de base pour tous les agents
│   ├── orchestrator_agent.py    # Agent Orchestrateur (Port 8001)
│   ├── extractor_agent.py       # Agent Extracteur (Port 8002)
│   ├── validator_agent.py       # Agent Validateur (Port 8003)
│   └── archivist_agent.py       # Agent Archiviste (Port 8004)
│
├── 🛠️ UTILITIES
│   ├── config.py                # Configuration centralisée
│   ├── run_agents.py            # Lance tous les agents
│   ├── client.py                # Client CLI pour interagir avec le système
│   ├── init_db.py               # Utilitaire de gestion de la base de données
│   ├── examples.py              # 5 exemples d'utilisation complets
│   ├── diagram.py               # Diagramme ASCII de l'architecture
│   └── setup.py                 # Script d'installation automatique
│
├── 🧪 TESTS
│   └── test_pipeline.py         # Suite de tests pytest
│
├── 📚 DOCUMENTATION
│   ├── README.md                # Documentation principale
│   ├── QUICKSTART.md            # Guide de démarrage rapide
│   ├── ARCHITECTURE.md          # Architecture technique détaillée
│   ├── API.md                   # Référence API complète
│   ├── PROJECT_SUMMARY.md       # Résumé du projet
│   └── INDEX.md                 # Ce fichier
│
├── 🐳 DEPLOYMENT
│   ├── Dockerfile               # Image Docker pour les agents
│   ├── docker-compose.yml       # Stack Docker complète
│   └── .gitignore              # Fichiers à ignorer
│
└── 📦 CONFIGURATION
    └── requirements.txt         # Dépendances Python

```

---

## 🚀 Démarrage Rapide

### Installation Automatique
```bash
python setup.py
```

### Installation Manuelle
```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer
cp .env.example .env
# Éditer .env avec vos credentials

# 3. Initialiser la base
createdb documents_db
python init_db.py init

# 4. Démarrer
python run_agents.py
```

### Avec Docker
```bash
docker-compose up
```

---

## 📖 Documentation - Guide de Lecture

### Pour Commencer
1. **README.md** - Vue d'ensemble et guide complet
2. **QUICKSTART.md** - Démarrage en 5 minutes
3. **PROJECT_SUMMARY.md** - Résumé exécutif

### Pour Développer
1. **ARCHITECTURE.md** - Architecture technique détaillée
2. **API.md** - Référence API complète
3. **diagram.py** - Visualisation de l'architecture

### Pour Utiliser
1. **client.py** - Interface CLI
2. **examples.py** - Exemples pratiques
3. **test_pipeline.py** - Tests unitaires

---

## 🔑 Composants Principaux

### Protocoles

| Fichier | Description | Lignes |
|---------|-------------|--------|
| `a2a_protocol.py` | Communication inter-agents JSON-RPC 2.0 | ~450 |
| `mcp_protocol.py` | Accès S3 et PostgreSQL | ~450 |

### Agents

| Agent | Port | Fichier | Rôle | Lignes |
|-------|------|---------|------|--------|
| Orchestrator | 8001 | `orchestrator_agent.py` | Coordination du pipeline | ~550 |
| Extractor | 8002 | `extractor_agent.py` | Extraction PDF/CSV depuis S3 | ~500 |
| Validator | 8003 | `validator_agent.py` | Validation et scoring | ~600 |
| Archivist | 8004 | `archivist_agent.py` | Persistence PostgreSQL | ~550 |
| Base | - | `base_agent.py` | Classe commune | ~250 |

### Utilitaires

| Fichier | Description | Usage |
|---------|-------------|-------|
| `client.py` | Client CLI | `python client.py <command>` |
| `run_agents.py` | Lance tous les agents | `python run_agents.py` |
| `init_db.py` | Gestion DB | `python init_db.py init|check|reset` |
| `examples.py` | 5 exemples | `python examples.py` |
| `diagram.py` | Affiche l'architecture | `python diagram.py` |
| `setup.py` | Installation auto | `python setup.py` |

---

## 📡 Endpoints API

### Orchestrator (http://localhost:8001)

| Endpoint | Type | Description |
|----------|------|-------------|
| `/message` | POST | Envoie un message A2A |
| `/health` | GET | Santé de l'agent |
| `/status` | GET | Statut détaillé |

**Méthodes A2A**:
- `process_document(s3_key, priority?)` - Traiter un document
- `process_batch(prefix?, extension?)` - Traiter un lot
- `get_task_status(task_id)` - Statut d'une tâche
- `list_pending_documents(limit?)` - Liste des documents

### Extractor (http://localhost:8002)
- `extract_document(s3_key)` - Extraire un document
- `list_supported_formats()` - Formats supportés

### Validator (http://localhost:8003)
- `validate_document(s3_key, extracted_data, type)` - Valider
- `get_validation_rules(type?)` - Liste des règles

### Archivist (http://localhost:8004)
- `archive_document(...)` - Archiver
- `get_document(id|s3_key)` - Récupérer
- `update_document_status(id, status)` - Mettre à jour
- `search_documents(filters?)` - Rechercher
- `get_document_stats()` - Statistiques

---

## 🎯 Use Cases

### Traiter un Document
```bash
python client.py process "documents/rapport.pdf"
```

### Traiter un Lot
```bash
python client.py batch --prefix "documents/2024/" --extension ".pdf"
```

### Vérifier le Statut
```bash
python client.py status <task_id>
```

### Rechercher des Documents
```python
# Via API directe
import asyncio
import aiohttp

async def search():
    message = {
        'jsonrpc': '2.0',
        'id': '1',
        'method': 'search_documents',
        'params': {'status': 'validated', 'min_score': 80}
    }
    async with aiohttp.ClientSession() as session:
        async with session.post('http://localhost:8004/message', json=message) as resp:
            return await resp.json()

asyncio.run(search())
```

---

## 🔍 Schéma de Base de Données

### Table: documents
- `id` (SERIAL PRIMARY KEY)
- `s3_key` (VARCHAR UNIQUE)
- `document_type` (VARCHAR) - 'pdf' | 'csv'
- `file_name` (VARCHAR)
- `status` (VARCHAR) - 'pending' | 'processing' | 'validated' | etc.
- `validation_score` (FLOAT) - 0-100
- `extracted_data` (JSONB)
- `validation_details` (JSONB)
- `metadata` (JSONB)
- `processing_date` (TIMESTAMP)

### Table: processing_logs
- `id` (SERIAL PRIMARY KEY)
- `document_id` (INTEGER REFERENCES documents)
- `agent_name` (VARCHAR)
- `action` (VARCHAR)
- `status` (VARCHAR)
- `details` (JSONB)
- `timestamp` (TIMESTAMP)

---

## 🧪 Tests

```bash
# Lancer tous les tests
pytest test_pipeline.py -v

# Tests spécifiques
pytest test_pipeline.py::TestA2AProtocol -v
pytest test_pipeline.py::TestValidationRules -v
```

---

## 🐳 Docker

### Build
```bash
docker build -t pipeline-agent .
```

### Run avec Docker Compose
```bash
# Démarrer
docker-compose up

# Démarrer en arrière-plan
docker-compose up -d

# Voir les logs
docker-compose logs -f

# Arrêter
docker-compose down
```

---

## 🔧 Configuration

### Variables d'Environnement (.env)

**AWS**:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`
- `S3_BUCKET_NAME`

**PostgreSQL**:
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`

**Agents**:
- `ORCHESTRATOR_HOST` / `ORCHESTRATOR_PORT` (default: localhost:8001)
- `EXTRACTOR_HOST` / `EXTRACTOR_PORT` (default: localhost:8002)
- `VALIDATOR_HOST` / `VALIDATOR_PORT` (default: localhost:8003)
- `ARCHIVIST_HOST` / `ARCHIVIST_PORT` (default: localhost:8004)

---

## 📊 Validation

### Règles
- **DataCompletenessRule** - Champs requis présents
- **DataFormatRule** - Format valide (regex)
- **DataQualityRule** - Qualité des données
- **DataConsistencyRule** - Cohérence

### Scores
- 90-100: Excellent ✅
- 75-89: Bon ✓
- 60-74: Acceptable ⚠️
- 40-59: Faible ⚠️
- 0-39: Échec ❌

---

## 🐛 Dépannage

### Agents ne démarrent pas
```bash
# Vérifier les ports
netstat -ano | findstr "8001 8002 8003 8004"

# Logs
tail -f agents.log
```

### Erreur S3
```bash
# Vérifier credentials
aws s3 ls s3://your-bucket/
```

### Erreur PostgreSQL
```bash
# Vérifier connexion
psql -h localhost -U postgres -d documents_db

# Réinitialiser
python init_db.py reset
```

---

## 📞 Support

1. **Documentation**: Lire README.md, QUICKSTART.md, ARCHITECTURE.md
2. **Logs**: Consulter `agents.log`
3. **Tests**: Lancer `pytest test_pipeline.py -v`
4. **Exemples**: Exécuter `python examples.py`
5. **Santé**: `python client.py health`

---

## 🎓 Technologies

- **Python 3.9+** - Langage
- **asyncio** - Programmation asynchrone
- **aiohttp** - Serveur HTTP async
- **asyncpg** - PostgreSQL async
- **aioboto3** - AWS S3 async
- **PyPDF2/pdfplumber** - PDF
- **pandas** - CSV/Données
- **pytest** - Tests

---

## 📝 Licence

MIT License

---

## ✨ Statistiques

- **Total de fichiers**: 23
- **Total de lignes de code**: ~7,050
- **Total de lignes de documentation**: ~2,500
- **Agents**: 4
- **Protocoles**: 2
- **Tests**: 20+
- **Formats supportés**: PDF, CSV
- **Règles de validation**: 4 types

---

**Statut**: ✅ Production-Ready

**Dernière mise à jour**: 2024

---

