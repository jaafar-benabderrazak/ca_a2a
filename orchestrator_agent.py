"""
Orchestrator Agent
Coordinates the document processing pipeline between agents
Includes automatic SQS polling for event-driven processing
"""
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import json
import os

from base_agent import BaseAgent
from a2a_protocol import A2AMessage, ErrorCodes
from mcp_context_auto import get_mcp_context
from config import AGENTS_CONFIG
from agent_card import AgentSkill, AgentRegistry, ResourceRequirements, AgentDependencies
import aiohttp
from upload_handler import UploadHandler

# AWS SDK for SQS polling
try:
    import boto3
    from botocore.exceptions import ClientError
    SQS_AVAILABLE = True
except ImportError:
    SQS_AVAILABLE = False


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator agent that coordinates the document processing workflow:
    1. Receives processing requests
    2. Coordinates extraction, validation, and archiving
    3. Tracks processing status and handles errors
    """
    
    def __init__(self):
        config = AGENTS_CONFIG['orchestrator']
        super().__init__(
            'Orchestrator',
            config['host'],
            config['port'],
            version='1.0.0',
            description='Coordinates document processing pipeline between specialized agents with dynamic discovery'
        )
        
        self.mcp: MCPContext = None
        self.processing_tasks: Dict[str, Dict[str, Any]] = {}
        self.upload_handler: UploadHandler = None
        
        # Agent registry for discovery
        self.agent_registry = AgentRegistry()
        
        # SQS polling configuration
        self.sqs_client = None
        self.sqs_queue_url = None
        self.sqs_polling_task = None
        self.sqs_enabled = os.getenv('SQS_ENABLED', 'true').lower() == 'true'
        self.sqs_queue_name = os.getenv('SQS_QUEUE_NAME', 'ca-a2a-document-processing')
        self.sqs_region = os.getenv('AWS_REGION', 'eu-west-3')
        self.sqs_poll_interval = int(os.getenv('SQS_POLL_INTERVAL', '10'))  # seconds
        self.sqs_max_messages = int(os.getenv('SQS_MAX_MESSAGES', '10'))
        self.sqs_wait_time = int(os.getenv('SQS_WAIT_TIME', '20'))  # long polling
        
        # Add upload endpoint
        self.app.router.add_post('/upload', self.handle_upload_endpoint)
        self.logger.info("Upload endpoint registered at POST /upload")
        
        # Agent URLs
        self.extractor_url = f"http://{AGENTS_CONFIG['extractor']['host']}:{AGENTS_CONFIG['extractor']['port']}"
        self.validator_url = f"http://{AGENTS_CONFIG['validator']['host']}:{AGENTS_CONFIG['validator']['port']}"
        self.archivist_url = f"http://{AGENTS_CONFIG['archivist']['host']}:{AGENTS_CONFIG['archivist']['port']}"
        
        # Set resource requirements and dependencies
        if self.agent_card:
            self.agent_card.resources = ResourceRequirements(
                memory_mb=512,
                cpu_cores=0.5,
                storage_required=False,
                network_required=True
            )
            self.agent_card.dependencies = AgentDependencies(
                services=['s3', 'postgres'],
                libraries=['aiohttp', 'asyncio']
            )
            self.agent_card.tags = ['orchestration', 'coordination', 'pipeline', 'workflow']
    
    def _register_handlers(self):
        """Register message handlers"""
        self.protocol.register_handler('process_document', self.handle_process_document)
        self.protocol.register_handler('process_batch', self.handle_process_batch)
        self.protocol.register_handler('get_task_status', self.handle_get_task_status)
        self.protocol.register_handler('list_pending_documents', self.handle_list_pending_documents)
        self.protocol.register_handler('discover_agents', self.handle_discover_agents)
        self.protocol.register_handler('get_agent_registry', self.handle_get_agent_registry)
    
    def _define_skills(self):
        """Define orchestrator agent skills"""
        return [
            AgentSkill(
                skill_id='process_document',
                name='Process Document',
                description='Orchestrate complete document processing pipeline (extraction, validation, archiving)',
                method='process_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {'type': 'string', 'description': 'S3 key of document to process'},
                        'priority': {
                            'type': 'string',
                            'enum': ['low', 'normal', 'high'],
                            'default': 'normal',
                            'description': 'Processing priority'
                        }
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'task_id': {'type': 'string'},
                        's3_key': {'type': 'string'},
                        'status': {'type': 'string'},
                        'message': {'type': 'string'}
                    }
                },
                tags=['orchestration', 'pipeline', 'workflow', 'core'],
                avg_processing_time_ms=5000
            ),
            AgentSkill(
                skill_id='process_batch',
                name='Process Batch',
                description='Process multiple documents from S3 with filtering options',
                method='process_batch',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'prefix': {'type': 'string', 'description': 'S3 prefix filter'},
                        'file_extension': {'type': 'string', 'description': 'File extension filter'}
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'batch_id': {'type': 'string'},
                        'total_documents': {'type': 'integer'},
                        'task_ids': {'type': 'array', 'items': {'type': 'string'}},
                        'status': {'type': 'string'},
                        'message': {'type': 'string'}
                    }
                },
                tags=['orchestration', 'batch', 'bulk-processing'],
                avg_processing_time_ms=10000
            ),
            AgentSkill(
                skill_id='get_task_status',
                name='Get Task Status',
                description='Retrieve the current status of a processing task',
                method='get_task_status',
                input_schema={
                    'type': 'object',
                    'required': ['task_id'],
                    'properties': {
                        'task_id': {'type': 'string', 'description': 'Task ID to query'}
                    }
                },
                output_schema={
                    'type': 'object',
                    'description': 'Complete task information with stages and results'
                },
                tags=['monitoring', 'status', 'tracking'],
                avg_processing_time_ms=50
            ),
            AgentSkill(
                skill_id='list_pending_documents',
                name='List Pending Documents',
                description='List documents that are pending or currently being processed',
                method='list_pending_documents',
                input_schema={
                    'type': 'object',
                    'properties': {
                        'limit': {'type': 'integer', 'default': 50}
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        'count': {'type': 'integer'},
                        'documents': {'type': 'array'}
                    }
                },
                tags=['monitoring', 'listing', 'query'],
                avg_processing_time_ms=200
            ),
            AgentSkill(
                skill_id='discover_agents',
                name='Discover Agents',
                description='Discover and register all available agents with their capabilities',
                method='discover_agents',
                input_schema={'type': 'object'},
                output_schema={
                    'type': 'object',
                    'properties': {
                        'discovered_agents': {'type': 'integer'},
                        'agents': {'type': 'array'},
                        'discovery_timestamp': {'type': 'string'}
                    }
                },
                tags=['discovery', 'registry', 'capabilities', 'metadata'],
                avg_processing_time_ms=500
            ),
            AgentSkill(
                skill_id='get_agent_registry',
                name='Get Agent Registry',
                description='Get the complete registry of discovered agents and their skills',
                method='get_agent_registry',
                input_schema={'type': 'object'},
                output_schema={
                    'type': 'object',
                    'properties': {
                        'total_agents': {'type': 'integer'},
                        'active_agents': {'type': 'integer'},
                        'total_skills': {'type': 'integer'},
                        'agents': {'type': 'object'}
                    }
                },
                tags=['registry', 'metadata', 'discovery'],
                avg_processing_time_ms=50
            )
        ]
    
    async def initialize(self):
        """Initialize MCP context and SQS polling"""
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
        
        # Initialize upload handler
        self.upload_handler = UploadHandler(self.mcp, max_file_size=100 * 1024 * 1024)
        self.logger.info("Upload handler initialized")
        
        # Initialize SQS client and start polling
        if self.sqs_enabled and SQS_AVAILABLE:
            await self._initialize_sqs()
        elif self.sqs_enabled and not SQS_AVAILABLE:
            self.logger.warning("SQS polling enabled but boto3 not available - install with: pip install boto3")
        else:
            self.logger.info("SQS polling disabled via SQS_ENABLED environment variable")
        
        # Discover all agents
        await self._discover_agents()
        
        self.logger.info("Orchestrator initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        # Stop SQS polling
        if self.sqs_polling_task:
            self.sqs_polling_task.cancel()
            try:
                await self.sqs_polling_task
            except asyncio.CancelledError:
                self.logger.info("SQS polling task cancelled")
        
        if self.mcp:
            await self.mcp.__aexit__(None, None, None)
        self.logger.info("Orchestrator cleanup completed")
    
    async def _initialize_sqs(self):
        """Initialize SQS client and start polling"""
        try:
            self.logger.info(f"Initializing SQS client for queue: {self.sqs_queue_name}")
            
            # Create SQS client
            self.sqs_client = boto3.client('sqs', region_name=self.sqs_region)
            
            # Get queue URL
            try:
                response = self.sqs_client.get_queue_url(QueueName=self.sqs_queue_name)
                self.sqs_queue_url = response['QueueUrl']
                self.logger.info(f"✓ SQS queue found: {self.sqs_queue_url}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
                    self.logger.error(f"✗ SQS queue '{self.sqs_queue_name}' does not exist!")
                    self.logger.info("Create it with: aws sqs create-queue --queue-name ca-a2a-document-processing --region eu-west-3")
                    return
                raise
            
            # Start polling task
            self.sqs_polling_task = asyncio.create_task(self._sqs_polling_loop())
            self.logger.info(f"✓ SQS polling started (interval: {self.sqs_poll_interval}s, max messages: {self.sqs_max_messages})")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SQS: {e}")
            self.sqs_client = None
            self.sqs_queue_url = None
    
    async def _sqs_polling_loop(self):
        """Main SQS polling loop - runs continuously"""
        self.logger.info("SQS polling loop started")
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while True:
            try:
                # Poll for messages
                await self._poll_sqs_messages()
                consecutive_errors = 0  # Reset error counter on success
                
                # Wait before next poll
                await asyncio.sleep(self.sqs_poll_interval)
                
            except asyncio.CancelledError:
                self.logger.info("SQS polling loop cancelled")
                break
            except Exception as e:
                consecutive_errors += 1
                self.logger.error(f"Error in SQS polling loop: {e} (consecutive errors: {consecutive_errors})")
                
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.critical(f"Too many consecutive errors ({consecutive_errors}), stopping SQS polling")
                    break
                
                # Exponential backoff on errors
                backoff = min(60, 2 ** consecutive_errors)
                self.logger.warning(f"Backing off for {backoff} seconds before retry")
                await asyncio.sleep(backoff)
    
    async def _poll_sqs_messages(self):
        """Poll SQS for messages and process them"""
        if not self.sqs_client or not self.sqs_queue_url:
            return
        
        try:
            # Receive messages (long polling)
            response = self.sqs_client.receive_message(
                QueueUrl=self.sqs_queue_url,
                MaxNumberOfMessages=self.sqs_max_messages,
                WaitTimeSeconds=self.sqs_wait_time,
                AttributeNames=['All'],
                MessageAttributeNames=['All']
            )
            
            messages = response.get('Messages', [])
            
            if messages:
                self.logger.info(f"Received {len(messages)} message(s) from SQS")
                
                for message in messages:
                    await self._process_sqs_message(message)
            
        except ClientError as e:
            self.logger.error(f"SQS receive_message error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error polling SQS: {e}")
            raise
    
    async def _process_sqs_message(self, message: Dict[str, Any]):
        """Process a single SQS message"""
        message_id = message.get('MessageId', 'unknown')
        receipt_handle = message.get('ReceiptHandle')
        
        try:
            self.logger.info(f"Processing SQS message: {message_id}")
            
            # Parse message body (S3 event notification format)
            body = json.loads(message['Body'])
            
            # Handle S3 event notification
            if 'Records' in body:
                for record in body['Records']:
                    if record.get('eventSource') == 'aws:s3':
                        await self._handle_s3_event(record, message_id)
            else:
                self.logger.warning(f"Unknown message format: {message_id}")
            
            # Delete message from queue after successful processing
            self.sqs_client.delete_message(
                QueueUrl=self.sqs_queue_url,
                ReceiptHandle=receipt_handle
            )
            self.logger.info(f"✓ Message {message_id} processed and deleted from queue")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse SQS message {message_id}: {e}")
            # Delete malformed messages
            self.sqs_client.delete_message(
                QueueUrl=self.sqs_queue_url,
                ReceiptHandle=receipt_handle
            )
        except Exception as e:
            self.logger.error(f"Error processing SQS message {message_id}: {e}")
            # Don't delete message on error - it will be retried
            raise
    
    async def _handle_s3_event(self, record: Dict[str, Any], message_id: str):
        """Handle S3 event notification"""
        try:
            event_name = record.get('eventName', '')
            s3_info = record.get('s3', {})
            bucket = s3_info.get('bucket', {}).get('name', '')
            s3_key = s3_info.get('object', {}).get('key', '')
            
            self.logger.info(f"S3 event: {event_name}, bucket: {bucket}, key: {s3_key}")
            
            # Only process ObjectCreated events in uploads folder
            if event_name.startswith('ObjectCreated:') and 'uploads/' in s3_key:
                # Skip folders
                if s3_key.endswith('/'):
                    self.logger.debug(f"Skipping folder: {s3_key}")
                    return
                
                # Determine document type from file extension
                file_ext = s3_key.split('.')[-1].lower()
                document_type = self._get_document_type(file_ext)
                
                self.logger.info(f"🚀 Auto-processing document from S3 event: {s3_key} (type: {document_type})")
                
                # Start document processing
                result = await self.handle_process_document({
                    's3_key': s3_key,
                    'priority': 'normal',
                    'source': 'sqs_s3_event',
                    'message_id': message_id
                })
                
                self.logger.info(f"✓ Processing initiated: task_id={result['task_id']}, s3_key={s3_key}")
            else:
                self.logger.debug(f"Ignoring S3 event: {event_name} for {s3_key}")
                
        except Exception as e:
            self.logger.error(f"Error handling S3 event: {e}")
            raise
    
    def _get_document_type(self, file_extension: str) -> str:
        """Map file extension to document type"""
        ext_map = {
            'pdf': 'invoice',
            'csv': 'invoice',
            'txt': 'invoice',
            'jpg': 'receipt',
            'jpeg': 'receipt',
            'png': 'receipt',
            'json': 'structured_data',
            'xml': 'structured_data'
        }
        return ext_map.get(file_extension, 'unknown')
    
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
    
    async def handle_upload_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle document upload (called internally after multipart parsing)
        This is for programmatic uploads via JSON-RPC
        
        Params: {
            "file_content_base64": "base64 encoded file",
            "file_name": "document.pdf",
            "folder": "invoices/2026/01" (optional),
            "metadata": {} (optional)
        }
        """
        file_content_b64 = params.get('file_content_base64')
        file_name = params.get('file_name')
        folder = params.get('folder', 'uploads')
        metadata = params.get('metadata', {})
        
        if not file_content_b64 or not file_name:
            raise ValueError("Missing required parameters: file_content_base64, file_name")
        
        import base64
        try:
            file_content = base64.b64decode(file_content_b64)
        except Exception as e:
            raise ValueError(f"Invalid base64 content: {str(e)}")
        
        # Generate S3 key
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_id = str(uuid.uuid4())[:8]
        s3_key = f"{folder}/{timestamp}_{unique_id}_{file_name}"
        
        # Upload to S3
        upload_metadata = {
            'original_filename': file_name,
            'file_size': str(len(file_content)),
            'upload_timestamp': datetime.utcnow().isoformat(),
            **metadata
        }
        
        try:
            await self.mcp.s3.put_object(
                key=s3_key,
                content=file_content_b64,  # MCP expects base64
                metadata=upload_metadata
            )
            
            self.logger.info(f"Document uploaded: {s3_key}")
            
            # Automatically trigger processing
            process_result = await self.handle_process_document({'s3_key': s3_key})
            
            return {
                'success': True,
                's3_key': s3_key,
                'file_name': file_name,
                'file_size': len(file_content),
                'upload_id': unique_id,
                'task_id': process_result['task_id'],
                'message': 'Document uploaded and processing started'
            }
        
        except Exception as e:
            self.logger.error(f"Upload failed: {str(e)}")
            raise Exception(f"Upload error: {str(e)}")
    
    async def handle_upload_endpoint(self, request):
        """
        HTTP endpoint for multipart file upload
        Route: POST /upload
        Content-Type: multipart/form-data
        
        Form fields:
            - file: The file to upload
            - folder: (optional) Target folder in S3
            - metadata: (optional) JSON metadata
        
        Returns:
            JSON response with upload result and task_id
        """
        from aiohttp import web
        
        try:
            self.logger.info("Handling file upload via /upload endpoint")
            
            # Use upload handler to process multipart
            upload_result = await self.upload_handler.handle_upload(
                request,
                default_folder="uploads"
            )
            
            # Automatically trigger processing
            s3_key = upload_result['s3_key']
            process_result = await self.handle_process_document({'s3_key': s3_key})
            
            # Combine results
            response = {
                **upload_result,
                'task_id': process_result['task_id'],
                'processing_status': process_result['status'],
                'message': 'Document uploaded and processing started'
            }
            
            return web.json_response(response, status=200)
        
        except ValueError as e:
            self.logger.warning(f"Upload validation error: {str(e)}")
            return web.json_response({
                'success': False,
                'error': str(e),
                'code': 'VALIDATION_ERROR'
            }, status=400)
        
        except Exception as e:
            self.logger.error(f"Upload error: {str(e)}")
            return web.json_response({
                'success': False,
                'error': str(e),
                'code': 'UPLOAD_ERROR'
            }, status=500)
    
    async def handle_discover_agents(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Discover all available agents and their capabilities
        """
        await self._discover_agents()
        
        registry_summary = self.agent_registry.get_summary()
        
        return {
            'discovered_agents': registry_summary['total_agents'],
            'agents': [
                {
                    'name': name,
                    'endpoint': info['endpoint'],
                    'status': info['status'],
                    'skills_count': info['skills_count']
                }
                for name, info in registry_summary['agents'].items()
            ],
            'total_skills': registry_summary['total_skills'],
            'available_skills': registry_summary['available_skills'],
            'discovery_timestamp': datetime.now().isoformat()
        }
    
    async def handle_get_agent_registry(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get the complete agent registry"""
        return self.agent_registry.get_summary()
    
    async def _discover_agents(self):
        """Discover available agents and their capabilities"""
        self.logger.info("Starting agent discovery...")
        
        agent_urls = [
            self.extractor_url,
            self.validator_url,
            self.archivist_url
        ]
        
        discovered_count = 0
        
        for url in agent_urls:
            try:
                async with aiohttp.ClientSession() as session:
                    # If auth is enabled, include a short-lived JWT so /card visibility works by role.
                    headers: Dict[str, str] = {}
                    try:
                        from urllib.parse import urlparse

                        parsed = urlparse(url)
                        host = (parsed.hostname or "").split(".")[0].strip().lower()
                        if host and self.security.can_sign_jwt() and self.security.require_auth:
                            token = self.security.sign_request_jwt(
                                subject=self.name.lower(),
                                audience=host,
                                method="card",
                                message_dict={"path": "/card"},
                                ttl_seconds=60,
                            )
                            headers["Authorization"] = f"Bearer {token}"
                    except Exception:
                        # Discovery must remain best-effort.
                        headers = headers or {}

                    async with session.get(
                        f"{url}/card",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status == 200:
                            card_data = await response.json()
                            
                            # Import and register the agent card
                            from agent_card import AgentCard
                            agent_card = AgentCard.from_dict(card_data)
                            self.agent_registry.register(agent_card)
                            
                            discovered_count += 1
                            self.logger.info(
                                f"Discovered agent: {agent_card.name} "
                                f"with {len(agent_card.skills)} skills at {url}"
                            )
                        else:
                            self.logger.warning(
                                f"Agent at {url} returned status {response.status}"
                            )
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout discovering agent at {url}")
            except Exception as e:
                self.logger.warning(f"Could not discover agent at {url}: {str(e)}")
        
        self.logger.info(f"Agent discovery completed: {discovered_count} agents discovered")
    
    def _find_agent_by_skill(self, skill_id: str) -> Optional[str]:
        """Find an agent endpoint that has a specific skill"""
        endpoints = self.agent_registry.get_endpoints_for_skill(skill_id)
        return endpoints[0] if endpoints else None
    
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
            'total_tasks': len(self.processing_tasks),
            'discovered_agents': len(self.agent_registry.get_all_agents()),
            'agent_registry_summary': self.agent_registry.get_summary(),
            'sqs_polling': {
                'enabled': self.sqs_enabled,
                'available': SQS_AVAILABLE,
                'queue_url': self.sqs_queue_url,
                'polling_active': self.sqs_polling_task is not None and not self.sqs_polling_task.done() if self.sqs_polling_task else False
            }
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

