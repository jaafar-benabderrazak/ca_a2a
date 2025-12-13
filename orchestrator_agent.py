"""
Orchestrator Agent
Coordinates the document processing pipeline between agents
"""
import asyncio
from typing import Dict, Any, List
from datetime import datetime
import uuid

from base_agent import BaseAgent
from a2a_protocol import A2AMessage, ErrorCodes
from mcp_protocol import MCPContext
from config import AGENTS_CONFIG


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator agent that coordinates the document processing workflow:
    1. Receives processing requests
    2. Coordinates extraction, validation, and archiving
    3. Tracks processing status and handles errors
    """
    
    def __init__(self):
        config = AGENTS_CONFIG['orchestrator']
        super().__init__('Orchestrator', config['host'], config['port'])
        
        self.mcp: MCPContext = None
        self.processing_tasks: Dict[str, Dict[str, Any]] = {}
        
        # Agent URLs
        self.extractor_url = f"http://{AGENTS_CONFIG['extractor']['host']}:{AGENTS_CONFIG['extractor']['port']}"
        self.validator_url = f"http://{AGENTS_CONFIG['validator']['host']}:{AGENTS_CONFIG['validator']['port']}"
        self.archivist_url = f"http://{AGENTS_CONFIG['archivist']['host']}:{AGENTS_CONFIG['archivist']['port']}"
    
    def _register_handlers(self):
        """Register message handlers"""
        self.protocol.register_handler('process_document', self.handle_process_document)
        self.protocol.register_handler('process_batch', self.handle_process_batch)
        self.protocol.register_handler('get_task_status', self.handle_get_task_status)
        self.protocol.register_handler('list_pending_documents', self.handle_list_pending_documents)
    
    async def initialize(self):
        """Initialize MCP context"""
        self.mcp = MCPContext()
        await self.mcp.__aenter__()
        
        # Initialize database schema
        await self.mcp.postgres.initialize_schema()
        
        self.logger.info("Orchestrator initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.mcp:
            await self.mcp.__aexit__(None, None, None)
        self.logger.info("Orchestrator cleanup completed")
    
    async def handle_process_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle document processing request
        Params: {
            "s3_key": "path/to/document.pdf",
            "priority": "normal|high" (optional)
        }
        """
        s3_key = params.get('s3_key')
        if not s3_key:
            raise ValueError("Missing required parameter: s3_key")
        
        task_id = str(uuid.uuid4())
        priority = params.get('priority', 'normal')
        
        self.logger.info(f"Starting document processing: task_id={task_id}, s3_key={s3_key}")
        
        # Create task record
        self.processing_tasks[task_id] = {
            'task_id': task_id,
            's3_key': s3_key,
            'status': 'processing',
            'started_at': datetime.now().isoformat(),
            'priority': priority,
            'current_stage': 'extraction',
            'stages': {}
        }
        
        # Start async processing
        asyncio.create_task(self._process_document_pipeline(task_id, s3_key))
        
        return {
            'task_id': task_id,
            's3_key': s3_key,
            'status': 'processing',
            'message': 'Document processing started'
        }
    
    async def handle_process_batch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle batch document processing
        Params: {
            "prefix": "path/prefix/" (optional),
            "file_extension": ".pdf|.csv" (optional)
        }
        """
        prefix = params.get('prefix', '')
        file_extension = params.get('file_extension', '')
        
        self.logger.info(f"Starting batch processing: prefix={prefix}, extension={file_extension}")
        
        # List documents from S3
        documents = await self.mcp.s3.list_objects(prefix=prefix, suffix=file_extension)
        
        batch_id = str(uuid.uuid4())
        task_ids = []
        
        # Process each document
        for doc in documents:
            result = await self.handle_process_document({'s3_key': doc['key']})
            task_ids.append(result['task_id'])
        
        return {
            'batch_id': batch_id,
            'total_documents': len(documents),
            'task_ids': task_ids,
            'status': 'processing',
            'message': f'Batch processing started for {len(documents)} documents'
        }
    
    async def handle_get_task_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get status of a processing task"""
        task_id = params.get('task_id')
        if not task_id:
            raise ValueError("Missing required parameter: task_id")
        
        if task_id not in self.processing_tasks:
            raise ValueError(f"Task not found: {task_id}")
        
        return self.processing_tasks[task_id]
    
    async def handle_list_pending_documents(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List documents pending processing"""
        query = """
        SELECT id, s3_key, document_type, file_name, status, processing_date
        FROM documents
        WHERE status IN ('pending', 'processing')
        ORDER BY processing_date DESC
        LIMIT $1
        """
        limit = params.get('limit', 50)
        
        documents = await self.mcp.postgres.fetch_all(query, limit)
        
        return {
            'count': len(documents),
            'documents': documents
        }
    
    async def _process_document_pipeline(self, task_id: str, s3_key: str):
        """
        Execute the complete document processing pipeline
        """
        task = self.processing_tasks[task_id]
        
        try:
            # Stage 1: Extraction
            self.logger.info(f"Task {task_id}: Starting extraction")
            task['current_stage'] = 'extraction'
            
            extraction_message = A2AMessage.create_request(
                'extract_document',
                {'s3_key': s3_key}
            )
            
            extraction_result = await self.send_message_to_agent(
                self.extractor_url,
                extraction_message
            )
            
            task['stages']['extraction'] = {
                'status': 'completed',
                'result': extraction_result,
                'completed_at': datetime.now().isoformat()
            }
            
            self.logger.info(f"Task {task_id}: Extraction completed")
            
            # Stage 2: Validation
            self.logger.info(f"Task {task_id}: Starting validation")
            task['current_stage'] = 'validation'
            
            validation_message = A2AMessage.create_request(
                'validate_document',
                {
                    's3_key': s3_key,
                    'extracted_data': extraction_result['extracted_data'],
                    'document_type': extraction_result['document_type']
                }
            )
            
            validation_result = await self.send_message_to_agent(
                self.validator_url,
                validation_message
            )
            
            task['stages']['validation'] = {
                'status': 'completed',
                'result': validation_result,
                'completed_at': datetime.now().isoformat()
            }
            
            self.logger.info(f"Task {task_id}: Validation completed")
            
            # Stage 3: Archiving
            self.logger.info(f"Task {task_id}: Starting archiving")
            task['current_stage'] = 'archiving'
            
            archiving_message = A2AMessage.create_request(
                'archive_document',
                {
                    's3_key': s3_key,
                    'document_type': extraction_result['document_type'],
                    'extracted_data': extraction_result['extracted_data'],
                    'validation_score': validation_result['score'],
                    'validation_details': validation_result['details'],
                    'metadata': extraction_result.get('metadata', {})
                }
            )
            
            archiving_result = await self.send_message_to_agent(
                self.archivist_url,
                archiving_message
            )
            
            task['stages']['archiving'] = {
                'status': 'completed',
                'result': archiving_result,
                'completed_at': datetime.now().isoformat()
            }
            
            self.logger.info(f"Task {task_id}: Archiving completed")
            
            # Update final task status
            task['status'] = 'completed'
            task['current_stage'] = 'completed'
            task['completed_at'] = datetime.now().isoformat()
            task['document_id'] = archiving_result.get('document_id')
            
            self.logger.info(f"Task {task_id}: Pipeline completed successfully")
            
        except Exception as e:
            self.logger.error(f"Task {task_id}: Pipeline failed - {str(e)}")
            
            # Update task with error
            task['status'] = 'failed'
            task['error'] = str(e)
            task['failed_at'] = datetime.now().isoformat()
            
            # Log error to database if possible
            try:
                if task.get('document_id'):
                    await self.mcp.postgres.execute(
                        """
                        INSERT INTO processing_logs (document_id, agent_name, action, status, details)
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        task['document_id'],
                        'Orchestrator',
                        'pipeline_execution',
                        'failed',
                        {'error': str(e), 'task_id': task_id}
                    )
            except Exception as log_error:
                self.logger.error(f"Failed to log error: {str(log_error)}")
    
    async def _get_agent_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        status = await super()._get_agent_status()
        status.update({
            'active_tasks': len([t for t in self.processing_tasks.values() if t['status'] == 'processing']),
            'completed_tasks': len([t for t in self.processing_tasks.values() if t['status'] == 'completed']),
            'failed_tasks': len([t for t in self.processing_tasks.values() if t['status'] == 'failed']),
            'total_tasks': len(self.processing_tasks)
        })
        return status


async def main():
    """Run the Orchestrator agent"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    agent = OrchestratorAgent()
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())

