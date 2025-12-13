# Pipeline Documentaire Intelligent Multi-Agents

Un système de traitement documentaire distribué basé sur une architecture multi-agents autonomes, utilisant les protocoles A2A (Agent-to-Agent) et MCP (Model Context Protocol).

## 🏗️ Architecture

Le système est composé de **quatre agents spécialisés** qui collaborent de manière autonome :

### 1. **Orchestrateur** (Port 8001)
- Réceptionne les requêtes de traitement
- Coordonne le flux entre les agents
- Suit l'état des tâches en cours
- Gère les erreurs et les retries

### 2. **Extracteur** (Port 8002)
- Lit les fichiers depuis S3 via MCP
- Supporte PDF (texte + tableaux) et CSV
- Extrait les données structurées
- Génère des métadonnées d'extraction

### 3. **Validateur** (Port 8003)
- Applique des règles de qualité configurables
- Calcule un score de conformité (0-100)
- Valide la complétude, le format, et la cohérence
- Retourne des détails de validation

### 4. **Archiviste** (Port 8004)
- Persiste les résultats dans PostgreSQL via MCP
- Stocke les métadonnées, données extraites, et validations
- Maintient un journal d'audit
- Fournit des API de recherche et statistiques

## 🔌 Protocoles

### A2A (Agent-to-Agent) - JSON-RPC 2.0
- Communication inter-agents asynchrone
- Format standardisé pour requêtes/réponses
- Gestion des erreurs et timeouts
- Support des notifications (sans réponse)

### MCP (Model Context Protocol)
- Interface unifiée pour S3 et PostgreSQL
- Gestion des connexions et pools
- Context managers pour ressources
- Opérations asynchrones

### Agent Cards & Skills (Nouveau ✨)
- Auto-description des agents avec leurs capacités
- Découverte dynamique des compétences
- Schémas JSON pour validation d'entrée/sortie
- Métriques de performance par compétence
- **Endpoints**: `/card`, `/skills`

Voir [AGENT_CARDS_IMPLEMENTATION.md](AGENT_CARDS_IMPLEMENTATION.md) pour plus de détails.

## 📦 Installation

### Prérequis
- Python 3.9+
- PostgreSQL 12+
- Accès AWS S3

### Configuration

1. **Cloner le projet**
```bash
cd ca_a2a
```

2. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

3. **Configurer les variables d'environnement**
```bash
cp .env.example .env
# Éditer .env avec vos credentials
```

Variables principales :
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

4. **Initialiser la base de données**

Le schéma sera créé automatiquement au premier démarrage, ou vous pouvez le créer manuellement :

```sql
CREATE DATABASE documents_db;
```

## 🚀 Utilisation

### Démarrer tous les agents

```bash
python run_agents.py
```

Cela démarre les 4 agents simultanément sur leurs ports respectifs.

### Démarrer un agent individuellement

```bash
# Orchestrateur
python orchestrator_agent.py

# Extracteur
python extractor_agent.py

# Validateur
python validator_agent.py

# Archiviste
python archivist_agent.py
```

### Utiliser le client CLI

```bash
# Traiter un document
python client.py process "documents/rapport.pdf"

# Traiter un lot de documents
python client.py batch --prefix "documents/" --extension ".pdf"

# Vérifier le statut d'une tâche
python client.py status <task_id>

# Lister les documents en attente
python client.py list --limit 50

# Vérifier la santé du système
python client.py health

# Obtenir les statistiques
python client.py info
```

### Découvrir les capacités des agents (Nouveau ✨)

```bash
# Découvrir tous les agents et leurs compétences
python discover_agents.py

# Obtenir la carte d'un agent spécifique
curl http://localhost:8002/card | jq

# Obtenir uniquement les compétences
curl http://localhost:8002/skills | jq

# Demander au orchestrateur de découvrir les agents
curl -X POST http://localhost:8001/message -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "discover_agents",
  "params": {}
}'
```

## 📡 API Endpoints

### Tous les agents

#### GET /health
Vérification de santé

#### GET /status
Statut et statistiques de l'agent

#### GET /card (Nouveau ✨)
Carte complète de l'agent avec toutes ses capacités
```json
{
  "agent_id": "extractor-12345",
  "name": "Extractor",
  "version": "1.0.0",
  "skills": [...],
  "resources": {...},
  "dependencies": {...}
}
```

#### GET /skills (Nouveau ✨)
Liste des compétences de l'agent

### Orchestrateur (http://localhost:8001)

#### POST /message
Corps JSON-RPC 2.0 :
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

Méthodes disponibles :
- `process_document` - Traiter un document
- `process_batch` - Traiter un lot
- `get_task_status` - Obtenir le statut
- `list_pending_documents` - Lister les documents en attente
- `discover_agents` - Découvrir les agents disponibles (Nouveau ✨)
- `get_agent_registry` - Obtenir le registre des agents (Nouveau ✨)

#### GET /health
Vérification de santé

#### GET /status
Statut et statistiques de l'agent

## 🚀 Déploiement sur AWS

Le système est conçu pour un déploiement cloud-native sur AWS avec support complet des agent cards pour la découverte de services.

## 🗄️ Schéma de Base de Données

### Table `documents`
```sql
- id (SERIAL PRIMARY KEY)
- s3_key (VARCHAR UNIQUE)
- document_type (VARCHAR)
- file_name (VARCHAR)
- file_size (INTEGER)
- status (VARCHAR)
- validation_score (FLOAT)
- metadata (JSONB)
- extracted_data (JSONB)
- validation_details (JSONB)
- processing_date (TIMESTAMP)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Table `processing_logs`
```sql
- id (SERIAL PRIMARY KEY)
- document_id (INTEGER REFERENCES documents)
- agent_name (VARCHAR)
- action (VARCHAR)
- status (VARCHAR)
- details (JSONB)
- timestamp (TIMESTAMP)
```

## 🔍 Validation

Le système applique plusieurs règles de validation :

### Pour PDF
- **Complétude** : Présence de texte et pages
- **Qualité** : Longueur minimale du texte
- **Cohérence** : Structure des tableaux

### Pour CSV
- **Complétude** : Présence de colonnes et données
- **Qualité** : Taux de valeurs manquantes
- **Cohérence** : Types de données cohérents

### Scores
- 90-100 : Excellent
- 75-89 : Bon
- 60-74 : Acceptable
- 40-59 : Faible
- 0-39 : Échec

## 📊 Flux de Traitement

```
1. Requête → Orchestrateur
2. Orchestrateur → Extracteur (extraction S3)
3. Extracteur → Orchestrateur (données extraites)
4. Orchestrateur → Validateur (validation)
5. Validateur → Orchestrateur (score + détails)
6. Orchestrateur → Archiviste (persistence PostgreSQL)
7. Archiviste → Orchestrateur (confirmation)
8. Orchestrateur → Réponse finale
```

## 🛠️ Développement

### Structure du Projet
```
ca_a2a/
├── a2a_protocol.py          # Protocole A2A JSON-RPC 2.0
├── mcp_protocol.py          # Protocole MCP (S3 + PostgreSQL)
├── agent_card.py            # Système de cartes d'agents (Nouveau ✨)
├── base_agent.py            # Classe de base pour agents
├── orchestrator_agent.py    # Agent orchestrateur
├── extractor_agent.py       # Agent extracteur
├── validator_agent.py       # Agent validateur
├── archivist_agent.py       # Agent archiviste
├── config.py                # Configuration
├── run_agents.py            # Script de lancement
├── client.py                # Client CLI
├── discover_agents.py       # Script de découverte (Nouveau ✨)
├── requirements.txt         # Dépendances Python
├── README.md                # Documentation
├── AWS_DEPLOYMENT.md        # Guide de déploiement AWS (Nouveau ✨)
└── AGENT_CARDS_IMPLEMENTATION.md  # Documentation des cartes d'agents (Nouveau ✨)
```

### Tests

```bash
# Installer les dépendances de test
pip install pytest pytest-asyncio

# Lancer les tests
pytest tests/
```

## 🔐 Sécurité

- Ne jamais committer le fichier `.env`
- Utiliser des IAM roles AWS avec permissions minimales
- Configurer des politiques de bucket S3 restrictives
- Utiliser SSL/TLS pour PostgreSQL en production
- Implémenter l'authentification pour les endpoints HTTP

## 📈 Monitoring

Chaque agent expose :
- `/health` - État de santé
- `/status` - Métriques et statistiques
- Logs structurés dans `agents.log`

## 🤝 Contribution

1. Fork le projet
2. Créer une branche (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Committer les changements (`git commit -am 'Ajout nouvelle fonctionnalité'`)
4. Pousser vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Créer une Pull Request

## 📝 Licence

Ce projet est sous licence MIT.

## 🐛 Dépannage

### Erreur de connexion S3
- Vérifier les credentials AWS dans `.env`
- Vérifier les permissions IAM
- Vérifier la région AWS

### Erreur de connexion PostgreSQL
- Vérifier que PostgreSQL est démarré
- Vérifier les credentials dans `.env`
- Vérifier que le port 5432 est accessible

### Agent ne démarre pas
- Vérifier que le port n'est pas déjà utilisé
- Vérifier les logs dans `agents.log`
- Vérifier les dépendances Python installées

## 📞 Support

Pour toute question ou problème :
- Ouvrir une issue sur GitHub
- Consulter la documentation des protocoles
- Vérifier les logs des agents
