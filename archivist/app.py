"""
Archivist Agent
Persists processed documents and validation results to PostgreSQL
"""
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
import json

from base_agent import BaseAgent
from a2a_protocol import ErrorCodes
from mcp_context_auto import get_mcp_context
from config import AGENTS_CONFIG
from agent_card import AgentSkill, ResourceRequirements, AgentDependencies
from utils import generate_idempotency_key


class ArchivistAgent(BaseAgent):
    """
    Archivist agent that persists documents to PostgreSQL:
    - Stores document metadata and extracted data
    - Records validation results and scores
    - Maintains processing logs for audit trail
    """
    
    def __init__(self):
        config = AGENTS_CONFIG['archivist']
        super().__init__(
            'Archivist',
            config['host'],
            config['port'],
            version='1.0.0',
            description='Persists processed documents and validation results to PostgreSQL with audit logging'
        )
        
        self.mcp: MCPContext = None
        
        # Set resource requirements and dependencies
        if self.agent_card:
            self.agent_card.resources = ResourceRequirements(
                memory_mb=512,
                cpu_cores=0.5,
                storage_required=True,
                network_required=True
            )
            self.agent_card.dependencies = AgentDependencies(
                services=['postgres'],
                libraries=['asyncpg', 'psycopg2-binary']
            )
            self.agent_card.tags = ['persistence', 'database', 'postgresql', 'archiving', 'audit']
    
    def _register_handlers(self):
        """Register message handlers"""
        self.protocol.register_handler('archive_document', self.handle_archive_document)
        self.protocol.register_handler('get_document', self.handle_get_document)
        self.protocol.register_handler('update_document_status', self.handle_update_document_status)
        self.protocol.register_handler('search_documents', self.handle_search_documents)
        self.protocol.register_handler('get_document_stats', self.handle_get_document_stats)
    
    def _define_skills(self):
        """Define archivist agent skills"""
        return [
            AgentSkill(
                skill_id='archive_document',
                name='Archive Document',
                description='Archive processed document with extracted data and validation results to PostgreSQL',
                method='archive_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {'type': 'string', 'description': 'S3 key of the document'},
                        'document_type': {'type': 'string', 'description': 'Type of document'},
                        'extracted_data': {'type': 'object', 'description': 'Extracted data'},
                        'validation_score': {'type': 'number', 'description': 'Validation score'},
                        'validation_details': {'type': 'object', 'description': 'Validation details'},
                        'metadata': {'type': 'object', 'description': 'Document metadata'}
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'document_id': {'type': 'integer'},
                        's3_key': {'type': 'string'},
                        'status': {'type': 'string'},
                        'action': {'type': 'string', 'enum': ['created', 'updated']},
                        'validation_score': {'type': 'number'},
                        'archived_at': {'type': 'string'}
                    }
                },
                tags=['persistence', 'archive', 'database', 'core'],
                avg_processing_time_ms=300
            ),
            AgentSkill(
                skill_id='get_document',
                name='Get Document',
                description='Retrieve a document by ID or S3 key from the database',
                method='get_document',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'document_id': {'type': 'integer', 'description': 'Document ID'},
                        's3_key': {'type': 'string', 'description': 'S3 key'}
                    },
                    'oneOf': [
                        {'required': ['document_id']},
                        {'required': ['s3_key']}
                    ]
                },
                output_schema={
                    'type': 'object',
                    'description': 'Complete document record with all fields'
                },
                tags=['retrieval', 'database', 'query'],
                avg_processing_time_ms=100
            ),
            AgentSkill(
                skill_id='update_document_status',
                name='Update Document Status',
                description='Update the status of a document in the database',
                method='update_document_status',
                input_schema={
                    'type': 'object',
                    'required': ['document_id', 'status'],
                    'properties': {
                        'document_id': {'type': 'integer'},
                        'status': {'type': 'string'},
                        'error_message': {'type': 'string', 'description': 'Optional error message'}
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'document_id': {'type': 'integer'},
                        'status': {'type': 'string'},
                        'updated_at': {'type': 'string'}
                    }
                },
                tags=['update', 'status', 'database'],
                avg_processing_time_ms=150
            ),
            AgentSkill(
                skill_id='search_documents',
                name='Search Documents',
                description='Search documents with filters (status, type, score) and pagination',
                method='search_documents',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'status': {'type': 'string', 'description': 'Filter by status'},
                        'document_type': {'type': 'string', 'description': 'Filter by document type'},
                        'min_score': {'type': 'number', 'description': 'Minimum validation score'},
                        'limit': {'type': 'integer', 'default': 50, 'description': 'Results limit'},
                        'offset': {'type': 'integer', 'default': 0, 'description': 'Results offset'}
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'documents': {'type': 'array'},
                        'total_count': {'type': 'integer'},
                        'limit': {'type': 'integer'},
                        'offset': {'type': 'integer'}
                    }
                },
                tags=['search', 'query', 'database', 'pagination'],
                avg_processing_time_ms=200
            ),
            AgentSkill(
                skill_id='get_document_stats',
                name='Get Document Statistics',
                description='Get comprehensive statistics about document processing (counts, averages, activity)',
                method='get_document_stats',
                input_schema={'type': 'object'},
                output_schema={
                    'type': 'object',
                    'properties': {
                        'total_documents': {'type': 'integer'},
                        'recent_activity_24h': {'type': 'integer'},
                        'average_validation_score': {'type': 'number'},
                        'by_status': {'type': 'object'},
                        'by_type': {'type': 'object'}
                    }
                },
                tags=['statistics', 'analytics', 'metrics', 'reporting'],
                avg_processing_time_ms=300
            ),
            AgentSkill(
                skill_id='audit_logging',
                name='Audit Logging',
                description='Maintain processing logs for audit trail and compliance',
                method='archive_document',
                input_schema={
                    'type': 'object',
                    'description': 'Automatically logs all archiving operations'
                },
                tags=['audit', 'logging', 'compliance', 'tracking'],
                avg_processing_time_ms=50
            )
        ]
    
    async def initialize(self):
        """Initialize MCP context"""
        self.mcp = get_mcp_context()
        await self.mcp.__aenter__()
        
        # Initialize database schema - make this resilient to failures
        # Schema might already be initialized or MCP server might be slow
        try:
            await asyncio.wait_for(
                self.mcp.postgres.initialize_schema(), 
                timeout=90.0
            )
            self.logger.info("Database schema initialized successfully")
        except asyncio.TimeoutError:
            self.logger.warning("Schema initialization timed out - schema may already be initialized, continuing...")
        except Exception as e:
            self.logger.warning(f"Schema initialization failed: {e} - continuing anyway as schema may already exist")
        
        self.logger.info("Archivist initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.mcp:
            await self.mcp.__aexit__(None, None, None)
        self.logger.info("Archivist cleanup completed")
    
    async def handle_archive_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Archive a processed document to PostgreSQL
        Implements idempotency: same params won't create duplicate entries
        Params: {
            "s3_key": "path/to/document",
            "document_type": "pdf|csv",
            "extracted_data": {...},
            "validation_score": 85.5,
            "validation_details": {...},
            "metadata": {...}
        }
        """
        s3_key = params.get('s3_key')
        document_type = params.get('document_type')
        extracted_data = params.get('extracted_data', {})
        validation_score = params.get('validation_score')
        validation_details = params.get('validation_details', {})
        metadata = params.get('metadata', {})
        
        if not s3_key:
            raise ValueError("Missing required parameter: s3_key")
        
        # Generate idempotency key
        idempotency_key = generate_idempotency_key('archive_document', {'s3_key': s3_key})
        
        # Check if already processed (idempotency)
        cached_result = self.idempotency_store.get(idempotency_key)
        if cached_result:
            self.logger.info(f"Returning cached result for {s3_key} (idempotent)")
            return cached_result
        
        self.logger.info(f"Archiving document: {s3_key}")
        
        try:
            # Extract file info
            file_name = s3_key.split('/')[-1]
            file_size = metadata.get('file_size', 0)
            
            # Determine status based on validation score
            if validation_score is None:
                status = 'processed'
            elif validation_score >= 75:
                status = 'validated'
            elif validation_score >= 60:
                status = 'validated_with_warnings'
            else:
                status = 'validation_failed'
            
            # Check if document already exists
            existing_doc = await self.mcp.postgres.fetch_one(
                "SELECT id, status FROM documents WHERE s3_key = $1",
                s3_key
            )
            
            if existing_doc:
                # Update existing document
                document_id = existing_doc['id']
                
                await self.mcp.postgres.execute(
                    """
                    UPDATE documents SET
                        document_type = $1,
                        file_name = $2,
                        file_size = $3,
                        processing_date = $4,
                        status = $5,
                        validation_score = $6,
                        metadata = $7,
                        extracted_data = $8,
                        validation_details = $9,
                        updated_at = $10
                    WHERE id = $11
                    """,
                    document_type,
                    file_name,
                    file_size,
                    datetime.now(),
                    status,
                    validation_score,
                    json.dumps(metadata),
                    json.dumps(extracted_data),
                    json.dumps(validation_details),
                    datetime.now(),
                    document_id
                )
                
                self.logger.info(f"Updated existing document: id={document_id}")
                action = 'updated'
                
            else:
                # Insert new document
                document_id = await self.mcp.postgres.fetch_value(
                    """
                    INSERT INTO documents (
                        s3_key, document_type, file_name, file_size,
                        processing_date, status, validation_score,
                        metadata, extracted_data, validation_details
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING id
                    """,
                    s3_key,
                    document_type,
                    file_name,
                    file_size,
                    datetime.now(),
                    status,
                    validation_score,
                    json.dumps(metadata),
                    json.dumps(extracted_data),
                    json.dumps(validation_details)
                )
                
                self.logger.info(f"Inserted new document: id={document_id}")
                action = 'created'
            
            # Log the archiving action
            await self._log_action(
                document_id,
                'archive_document',
                'success',
                {
                    'validation_score': validation_score,
                    'status': status,
                    'action': action
                }
            )
            
            result = {
                'document_id': document_id,
                's3_key': s3_key,
                'status': status,
                'action': action,
                'validation_score': validation_score,
                'archived_at': datetime.now().isoformat()
            }
            
            # Cache result for idempotency
            self.idempotency_store.set(idempotency_key, result)
            
            self.logger.info(f"Successfully archived document: id={document_id}, status={status}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to archive document: {str(e)}")
            raise Exception(f"Archiving error: {str(e)}")
    
    async def handle_get_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve a document by ID or S3 key
        Params: {
            "document_id": 123 (optional),
            "s3_key": "path/to/document" (optional)
        }
        """
        document_id = params.get('document_id')
        s3_key = params.get('s3_key')
        
        if not document_id and not s3_key:
            raise ValueError("Either document_id or s3_key is required")
        
        if document_id:
            query = "SELECT * FROM documents WHERE id = $1"
            document = await self.mcp.postgres.fetch_one(query, document_id)
        else:
            query = "SELECT * FROM documents WHERE s3_key = $1"
            document = await self.mcp.postgres.fetch_one(query, s3_key)
        
        if not document:
            raise ValueError(f"Document not found")
        
        # Parse JSON fields
        if document.get('metadata'):
            document['metadata'] = json.loads(document['metadata'])
        if document.get('extracted_data'):
            document['extracted_data'] = json.loads(document['extracted_data'])
        if document.get('validation_details'):
            document['validation_details'] = json.loads(document['validation_details'])
        
        # Convert datetime to ISO format
        for field in ['upload_date', 'processing_date', 'created_at', 'updated_at']:
            if document.get(field):
                document[field] = document[field].isoformat()
        
        return document
    
    async def handle_update_document_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update document status
        Params: {
            "document_id": 123,
            "status": "archived",
            "error_message": "..." (optional)
        }
        """
        document_id = params.get('document_id')
        status = params.get('status')
        error_message = params.get('error_message')
        
        if not document_id or not status:
            raise ValueError("Missing required parameters: document_id and status")
        
        await self.mcp.postgres.execute(
            """
            UPDATE documents SET
                status = $1,
                error_message = $2,
                updated_at = $3
            WHERE id = $4
            """,
            status,
            error_message,
            datetime.now(),
            document_id
        )
        
        # Log the status update
        await self._log_action(
            document_id,
            'update_status',
            'success',
            {'new_status': status, 'error_message': error_message}
        )
        
        return {
            'document_id': document_id,
            'status': status,
            'updated_at': datetime.now().isoformat()
        }
    
    async def handle_search_documents(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Search documents with filters
        Params: {
            "status": "validated" (optional),
            "document_type": "pdf" (optional),
            "min_score": 80.0 (optional),
            "limit": 50,
            "offset": 0
        }
        """
        status = params.get('status')
        document_type = params.get('document_type')
        min_score = params.get('min_score')
        limit = params.get('limit', 50)
        offset = params.get('offset', 0)
        
        # Build query
        where_clauses = []
        query_params = []
        param_idx = 1
        
        if status:
            where_clauses.append(f"status = ${param_idx}")
            query_params.append(status)
            param_idx += 1
        
        if document_type:
            where_clauses.append(f"document_type = ${param_idx}")
            query_params.append(document_type)
            param_idx += 1
        
        if min_score is not None:
            where_clauses.append(f"validation_score >= ${param_idx}")
            query_params.append(min_score)
            param_idx += 1
        
        where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
        
        query = f"""
        SELECT id, s3_key, document_type, file_name, file_size,
               status, validation_score, processing_date, created_at
        FROM documents
        WHERE {where_clause}
        ORDER BY processing_date DESC
        LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        
        query_params.extend([limit, offset])
        
        documents = await self.mcp.postgres.fetch_all(query, *query_params)
        
        # Convert datetime fields
        for doc in documents:
            for field in ['processing_date', 'created_at']:
                if doc.get(field):
                    doc[field] = doc[field].isoformat()
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM documents WHERE {where_clause}"
        total_count = await self.mcp.postgres.fetch_value(
            count_query,
            *query_params[:len(query_params) - 2]  # Exclude limit and offset
        )
        
        return {
            'documents': documents,
            'total_count': total_count,
            'limit': limit,
            'offset': offset
        }
    
    async def handle_get_document_stats(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get document processing statistics"""
        
        # Get counts by status
        status_counts = await self.mcp.postgres.fetch_all(
            """
            SELECT status, COUNT(*) as count
            FROM documents
            GROUP BY status
            """
        )
        
        # Get counts by document type
        type_counts = await self.mcp.postgres.fetch_all(
            """
            SELECT document_type, COUNT(*) as count
            FROM documents
            GROUP BY document_type
            """
        )
        
        # Get average validation score
        avg_score = await self.mcp.postgres.fetch_value(
            """
            SELECT AVG(validation_score)
            FROM documents
            WHERE validation_score IS NOT NULL
            """
        )
        
        # Get total documents
        total_docs = await self.mcp.postgres.fetch_value(
            "SELECT COUNT(*) FROM documents"
        )
        
        # Get recent activity (last 24 hours)
        recent_activity = await self.mcp.postgres.fetch_value(
            """
            SELECT COUNT(*)
            FROM documents
            WHERE processing_date >= NOW() - INTERVAL '24 hours'
            """
        )
        
        return {
            'total_documents': total_docs,
            'recent_activity_24h': recent_activity,
            'average_validation_score': round(float(avg_score), 2) if avg_score else None,
            'by_status': {row['status']: row['count'] for row in status_counts},
            'by_type': {row['document_type']: row['count'] for row in type_counts}
        }
    
    async def _log_action(self, document_id: int, action: str, status: str, details: Dict[str, Any]):
        """Log an action to the processing_logs table"""
        try:
            await self.mcp.postgres.execute(
                """
                INSERT INTO processing_logs (document_id, agent_name, action, status, details)
                VALUES ($1, $2, $3, $4, $5)
                """,
                document_id,
                self.name,
                action,
                status,
                json.dumps(details)
            )
        except Exception as e:
            self.logger.error(f"Failed to log action: {str(e)}")
    
    async def _check_dependencies(self) -> Dict[str, Dict[str, Any]]:
        """Check PostgreSQL health"""
        dependencies = {}
        
        try:
            # Test PostgreSQL connection
            result = await self.mcp.postgres.fetch_value("SELECT 1")
            dependencies['postgresql'] = {
                'healthy': result == 1,
                'latency_ms': 0  # Could track actual latency
            }
        except Exception as e:
            dependencies['postgresql'] = {
                'healthy': False,
                'error': str(e)
            }
        
        return dependencies
        
        try:
            stats = await self.handle_get_document_stats({})
            status.update({
                'database_stats': stats
            })
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {str(e)}")
        
        return status


async def main():
    """Run the Archivist agent"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    agent = ArchivistAgent()
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())

