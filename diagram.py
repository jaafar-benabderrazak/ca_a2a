"""
Visual ASCII diagram of the pipeline architecture
"""

ARCHITECTURE_DIAGRAM = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                 PIPELINE DOCUMENTAIRE INTELLIGENT MULTI-AGENTS               ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                    │
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                   │
│  │ CLI Client   │   │ HTTP Client  │   │ Python API   │                   │
│  │ (client.py)  │   │              │   │              │                   │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                   │
│         │                   │                   │                           │
│         └───────────────────┴───────────────────┘                           │
│                             │                                                │
└─────────────────────────────┼────────────────────────────────────────────────┘
                              │ HTTP/JSON-RPC 2.0
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ORCHESTRATOR AGENT                                  │
│                           (Port 8001)                                        │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────┐        │
│  │  • Reçoit les requêtes de traitement                           │        │
│  │  • Coordonne le flux entre agents                              │        │
│  │  • Gère les tâches et leur statut                             │        │
│  │  • Agrège les résultats                                        │        │
│  └────────────────────────────────────────────────────────────────┘        │
│                                                                              │
│  Méthodes A2A: process_document, process_batch, get_task_status            │
└──────┬───────────────────────┬───────────────────────┬──────────────────────┘
       │ A2A Protocol          │ A2A Protocol          │ A2A Protocol
       │ (JSON-RPC 2.0)        │ (JSON-RPC 2.0)        │ (JSON-RPC 2.0)
       ▼                       ▼                       ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────────┐
│  EXTRACTOR   │      │  VALIDATOR   │      │    ARCHIVIST     │
│  (Port 8002) │      │  (Port 8003) │      │   (Port 8004)    │
├──────────────┤      ├──────────────┤      ├──────────────────┤
│              │      │              │      │                  │
│ • Lit S3     │      │ • Applique   │      │ • Persiste dans  │
│   via MCP    │      │   règles de  │      │   PostgreSQL     │
│              │      │   validation │      │   via MCP        │
│ • Extrait:   │      │              │      │                  │
│   - PDF      │      │ • Calcule    │      │ • Gère les       │
│     (texte,  │      │   score de   │      │   métadonnées    │
│      tables) │      │   conformité │      │                  │
│   - CSV      │      │   (0-100)    │      │ • Journal        │
│     (données │      │              │      │   d'audit        │
│      + stats)│      │ • Retourne   │      │                  │
│              │      │   détails    │      │ • Recherche      │
│              │      │              │      │   & stats        │
└──────┬───────┘      └──────────────┘      └────────┬─────────┘
       │                                               │
       │ MCP Protocol                                  │ MCP Protocol
       ▼                                               ▼
┌──────────────────────┐                    ┌─────────────────────┐
│                      │                    │                     │
│    AWS S3 BUCKET     │                    │   POSTGRESQL DB     │
│                      │                    │                     │
│  ┌────────────────┐  │                    │  ┌───────────────┐ │
│  │ Documents/     │  │                    │  │ documents     │ │
│  │  - PDFs        │  │                    │  │ (table)       │ │
│  │  - CSVs        │  │                    │  ├───────────────┤ │
│  │  - Metadata    │  │                    │  │ - id          │ │
│  └────────────────┘  │                    │  │ - s3_key      │ │
│                      │                    │  │ - type        │ │
│  Operations:         │                    │  │ - status      │ │
│  • list_objects      │                    │  │ - score       │ │
│  • get_object        │                    │  │ - data (JSON) │ │
│  • get_metadata      │                    │  └───────────────┘ │
│  • put_object        │                    │                     │
│                      │                    │  ┌───────────────┐ │
└──────────────────────┘                    │  │ process_logs  │ │
                                            │  │ (audit trail) │ │
                                            │  └───────────────┘ │
                                            └─────────────────────┘

═══════════════════════════════════════════════════════════════════════════════

FLUX DE TRAITEMENT:

1. Client → Orchestrator: process_document(s3_key)
   └─> Créé task_id, démarre pipeline asynchrone

2. Orchestrator → Extractor: extract_document(s3_key)
   └─> Extractor télécharge de S3, extrait données
   └─> Retourne: extracted_data + metadata

3. Orchestrator → Validator: validate_document(extracted_data, type)
   └─> Validator applique règles de validation
   └─> Retourne: score + status + détails

4. Orchestrator → Archivist: archive_document(données, score, validation)
   └─> Archivist persiste dans PostgreSQL
   └─> Log l'action pour audit
   └─> Retourne: document_id + status

5. Orchestrator → Client: task completed
   └─> Retourne: status, stages, document_id

═══════════════════════════════════════════════════════════════════════════════

PROTOCOLES:

┌─────────────────────────────────────────────────────────────────┐
│ A2A PROTOCOL (Agent-to-Agent)                                   │
├─────────────────────────────────────────────────────────────────┤
│ • Format: JSON-RPC 2.0                                          │
│ • Transport: HTTP POST /message                                 │
│ • Asynchrone avec gestion des pending requests                  │
│ • Support: requêtes, réponses, erreurs, notifications          │
│                                                                  │
│ Structure de message:                                           │
│ {                                                                │
│   "jsonrpc": "2.0",                                             │
│   "id": "uuid",                                                 │
│   "method": "method_name",                                      │
│   "params": {...}                                               │
│ }                                                                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ MCP PROTOCOL (Model Context Protocol)                           │
├─────────────────────────────────────────────────────────────────┤
│ • Interface unifiée pour ressources externes                    │
│ • Implémentations:                                              │
│   - S3Resource: accès AWS S3                                    │
│   - PostgreSQLResource: accès base de données                   │
│ • Context managers pour gestion du cycle de vie                 │
│ • Opérations asynchrones (asyncio)                             │
│ • Pool de connexions pour PostgreSQL                           │
└─────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════

VALIDATION:

┌──────────────────────┬─────────────────────────────────────────────┐
│ RÈGLE                │ DESCRIPTION                                 │
├──────────────────────┼─────────────────────────────────────────────┤
│ DataCompleteness     │ Vérifie présence des champs requis         │
│ DataFormat           │ Valide format avec regex                    │
│ DataQuality          │ Évalue qualité (longueur, valeurs manq.)   │
│ DataConsistency      │ Vérifie cohérence des données              │
└──────────────────────┴─────────────────────────────────────────────┘

Score final = Σ(score_règle × poids) / Σ(poids)

Statuts:
 • 90-100: Excellent ✅
 • 75-89:  Bon ✓
 • 60-74:  Acceptable ⚠️
 • 40-59:  Faible ⚠️
 • 0-39:   Échec ❌

═══════════════════════════════════════════════════════════════════════════════
"""

def print_architecture():
    """Print the architecture diagram"""
    import sys
    import io
    
    # Ensure UTF-8 encoding for Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    
    print(ARCHITECTURE_DIAGRAM)

if __name__ == '__main__':
    print_architecture()

