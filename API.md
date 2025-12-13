# API Reference - Pipeline Documentaire Multi-Agents

## Orchestrator Agent

**Base URL**: `http://localhost:8001`

### Endpoints HTTP

#### POST /message
Envoie un message A2A à l'orchestrateur.

**Headers**:
```
Content-Type: application/json
```

**Body** (JSON-RPC 2.0):
```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "method": "method_name",
  "params": {...}
}
```

#### GET /health
Vérifie la santé de l'agent.

**Response**:
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "timestamp": 1234567890.123
}
```

#### GET /status
Obtient le statut détaillé de l'agent.

**Response**:
```json
{
  "agent": "Orchestrator",
  "host": "localhost",
  "port": 8001,
  "status": "running",
  "active_tasks": 5,
  "completed_tasks": 123,
  "failed_tasks": 2,
  "total_tasks": 130
}
```

### Méthodes A2A

#### process_document

Traite un document depuis S3.

**Params**:
```json
{
  "s3_key": "documents/rapport.pdf",
  "priority": "normal"
}
```

**Result**:
```json
{
  "task_id": "uuid",
  "s3_key": "documents/rapport.pdf",
  "status": "processing",
  "message": "Document processing started"
}
```

#### process_batch

Traite un lot de documents.

**Params**:
```json
{
  "prefix": "documents/2024/",
  "file_extension": ".pdf"
}
```

**Result**:
```json
{
  "batch_id": "uuid",
  "total_documents": 25,
  "task_ids": ["uuid1", "uuid2", ...],
  "status": "processing",
  "message": "Batch processing started for 25 documents"
}
```

#### get_task_status

Obtient le statut d'une tâche.

**Params**:
```json
{
  "task_id": "uuid"
}
```

**Result**:
```json
{
  "task_id": "uuid",
  "s3_key": "documents/rapport.pdf",
  "status": "completed",
  "started_at": "2024-01-01T10:00:00",
  "completed_at": "2024-01-01T10:01:30",
  "current_stage": "completed",
  "stages": {
    "extraction": {
      "status": "completed",
      "result": {...},
      "completed_at": "2024-01-01T10:00:45"
    },
    "validation": {
      "status": "completed",
      "result": {...},
      "completed_at": "2024-01-01T10:01:15"
    },
    "archiving": {
      "status": "completed",
      "result": {...},
      "completed_at": "2024-01-01T10:01:30"
    }
  },
  "document_id": 123
}
```

#### list_pending_documents

Liste les documents en attente.

**Params**:
```json
{
  "limit": 50
}
```

**Result**:
```json
{
  "count": 25,
  "documents": [
    {
      "id": 123,
      "s3_key": "documents/rapport.pdf",
      "document_type": "pdf",
      "file_name": "rapport.pdf",
      "status": "processing",
      "processing_date": "2024-01-01T10:00:00"
    },
    ...
  ]
}
```

---

## Extractor Agent

**Base URL**: `http://localhost:8002`

### Méthodes A2A

#### extract_document

Extrait les données d'un document.

**Params**:
```json
{
  "s3_key": "documents/rapport.pdf"
}
```

**Result (PDF)**:
```json
{
  "s3_key": "documents/rapport.pdf",
  "document_type": "pdf",
  "file_name": "rapport.pdf",
  "file_size": 1024000,
  "extracted_data": {
    "pages": [
      {
        "page_number": 1,
        "text": "...",
        "char_count": 1500
      }
    ],
    "tables": [
      {
        "page": 2,
        "table_index": 0,
        "headers": ["Col1", "Col2"],
        "rows": [["val1", "val2"], ...],
        "row_count": 10,
        "column_count": 2
      }
    ],
    "metadata": {
      "title": "Rapport",
      "author": "...",
      "creation_date": "..."
    },
    "total_pages": 5,
    "text_content": "..."
  },
  "metadata": {
    "content_type": "application/pdf",
    "extraction_timestamp": "2024-01-01T10:00:00",
    "s3_last_modified": "2024-01-01T09:00:00"
  },
  "extraction_status": "success"
}
```

**Result (CSV)**:
```json
{
  "s3_key": "documents/data.csv",
  "document_type": "csv",
  "file_name": "data.csv",
  "file_size": 50000,
  "extracted_data": {
    "row_count": 100,
    "column_count": 5,
    "columns": ["col1", "col2", "col3", "col4", "col5"],
    "column_types": {
      "col1": "int64",
      "col2": "float64",
      "col3": "object"
    },
    "data": [
      {"col1": 1, "col2": 1.5, "col3": "text"},
      ...
    ],
    "summary_statistics": {
      "col1": {
        "mean": 50.5,
        "median": 50.0,
        "min": 1,
        "max": 100,
        "std": 28.9,
        "missing_count": 0
      }
    },
    "missing_values": {
      "col1": 0,
      "col2": 5,
      "col3": 2
    }
  },
  "metadata": {...},
  "extraction_status": "success"
}
```

#### list_supported_formats

Liste les formats supportés.

**Params**: `{}`

**Result**:
```json
{
  "supported_formats": [".pdf", ".csv"],
  "format_descriptions": {
    ".pdf": "PDF documents (text and table extraction)",
    ".csv": "CSV files (structured data with type inference)"
  }
}
```

---

## Validator Agent

**Base URL**: `http://localhost:8003`

### Méthodes A2A

#### validate_document

Valide un document extrait.

**Params**:
```json
{
  "s3_key": "documents/rapport.pdf",
  "extracted_data": {...},
  "document_type": "pdf"
}
```

**Result**:
```json
{
  "s3_key": "documents/rapport.pdf",
  "document_type": "pdf",
  "score": 87.5,
  "status": "good",
  "all_rules_passed": false,
  "validation_timestamp": "2024-01-01T10:01:00",
  "details": {
    "rules_evaluated": 3,
    "rules_passed": 2,
    "rules_failed": 1,
    "results": [
      {
        "rule": "Data Completeness",
        "passed": true,
        "score": 100.0,
        "weight": 1.5,
        "message": "All required fields present and non-empty"
      },
      {
        "rule": "Data Quality",
        "passed": true,
        "score": 90.0,
        "weight": 1.2,
        "message": "Data quality acceptable"
      },
      {
        "rule": "Data Consistency",
        "passed": false,
        "score": 70.0,
        "weight": 1.0,
        "message": "Table has 2 inconsistent rows"
      }
    ]
  }
}
```

**Status Values**:
- `excellent`: Score >= 90
- `good`: Score >= 75
- `acceptable`: Score >= 60
- `poor`: Score >= 40
- `failed`: Score < 40

#### get_validation_rules

Liste les règles de validation.

**Params**:
```json
{
  "document_type": "pdf"
}
```

**Result**:
```json
{
  "document_type": "pdf",
  "rules": [
    {
      "name": "Data Completeness",
      "weight": 1.5
    },
    {
      "name": "Data Quality",
      "weight": 1.2
    },
    {
      "name": "Data Consistency",
      "weight": 1.0
    }
  ]
}
```

---

## Archivist Agent

**Base URL**: `http://localhost:8004`

### Méthodes A2A

#### archive_document

Archive un document dans PostgreSQL.

**Params**:
```json
{
  "s3_key": "documents/rapport.pdf",
  "document_type": "pdf",
  "extracted_data": {...},
  "validation_score": 87.5,
  "validation_details": {...},
  "metadata": {...}
}
```

**Result**:
```json
{
  "document_id": 123,
  "s3_key": "documents/rapport.pdf",
  "status": "validated",
  "action": "created",
  "validation_score": 87.5,
  "archived_at": "2024-01-01T10:01:30"
}
```

**Status Values**:
- `validated`: Score >= 75
- `validated_with_warnings`: Score >= 60
- `validation_failed`: Score < 60
- `processed`: No validation score

**Action Values**:
- `created`: Nouveau document
- `updated`: Document existant mis à jour

#### get_document

Récupère un document.

**Params**:
```json
{
  "document_id": 123
}
```
ou
```json
{
  "s3_key": "documents/rapport.pdf"
}
```

**Result**:
```json
{
  "id": 123,
  "s3_key": "documents/rapport.pdf",
  "document_type": "pdf",
  "file_name": "rapport.pdf",
  "file_size": 1024000,
  "upload_date": "2024-01-01T09:00:00",
  "processing_date": "2024-01-01T10:00:00",
  "status": "validated",
  "validation_score": 87.5,
  "metadata": {...},
  "extracted_data": {...},
  "validation_details": {...},
  "error_message": null,
  "created_at": "2024-01-01T10:01:30",
  "updated_at": "2024-01-01T10:01:30"
}
```

#### update_document_status

Met à jour le statut d'un document.

**Params**:
```json
{
  "document_id": 123,
  "status": "archived",
  "error_message": "Optional error message"
}
```

**Result**:
```json
{
  "document_id": 123,
  "status": "archived",
  "updated_at": "2024-01-01T11:00:00"
}
```

#### search_documents

Recherche des documents.

**Params**:
```json
{
  "status": "validated",
  "document_type": "pdf",
  "min_score": 80.0,
  "limit": 50,
  "offset": 0
}
```

**Result**:
```json
{
  "documents": [
    {
      "id": 123,
      "s3_key": "documents/rapport.pdf",
      "document_type": "pdf",
      "file_name": "rapport.pdf",
      "file_size": 1024000,
      "status": "validated",
      "validation_score": 87.5,
      "processing_date": "2024-01-01T10:00:00",
      "created_at": "2024-01-01T10:01:30"
    },
    ...
  ],
  "total_count": 250,
  "limit": 50,
  "offset": 0
}
```

#### get_document_stats

Obtient les statistiques globales.

**Params**: `{}`

**Result**:
```json
{
  "total_documents": 500,
  "recent_activity_24h": 25,
  "average_validation_score": 82.5,
  "by_status": {
    "validated": 350,
    "validated_with_warnings": 100,
    "validation_failed": 30,
    "processing": 15,
    "pending": 5
  },
  "by_type": {
    "pdf": 300,
    "csv": 200
  }
}
```

---

## Codes d'Erreur

### JSON-RPC Standard

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | JSON invalide |
| -32600 | Invalid request | Requête invalide |
| -32601 | Method not found | Méthode inconnue |
| -32602 | Invalid params | Paramètres invalides |
| -32603 | Internal error | Erreur interne |

### Codes Personnalisés

| Code | Message | Description |
|------|---------|-------------|
| -32001 | Extraction error | Erreur d'extraction |
| -32002 | Validation error | Erreur de validation |
| -32003 | Persistence error | Erreur de persistence |
| -32004 | S3 error | Erreur S3 |
| -32005 | Database error | Erreur base de données |

### Format d'Erreur

```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": -32001,
    "message": "Extraction error: PDF extraction error: ...",
    "data": {
      "additional": "context"
    }
  }
}
```

