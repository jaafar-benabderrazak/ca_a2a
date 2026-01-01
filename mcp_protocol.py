"""
Model Context Protocol (MCP) Implementation
Provides unified interface for accessing S3 and PostgreSQL resources
Implements A2A best practices: retry logic, circuit breakers, timeouts
"""
import asyncio
import io
from typing import Any, Dict, List, Optional, Union
from abc import ABC, abstractmethod
import logging

import aioboto3
import asyncpg
from botocore.exceptions import ClientError

from config import AWS_CONFIG, POSTGRES_CONFIG
from utils import retry_with_backoff, CircuitBreaker, timeout_decorator

logger = logging.getLogger(__name__)


class MCPResource(ABC):
    """Abstract base class for MCP resources"""
    
    @abstractmethod
    async def connect(self):
        """Establish connection to the resource"""
        pass
    
    @abstractmethod
    async def disconnect(self):
        """Close connection to the resource"""
        pass


class S3Resource(MCPResource):
    """
    MCP interface for AWS S3
    Implements: retry logic, circuit breaker, timeouts
    """
    
    def __init__(self):
        self.session = None
        self.client = None
        self.bucket_name = AWS_CONFIG['s3_bucket']
        self.logger = logging.getLogger(f"{__name__}.S3Resource")
        
        # Circuit breaker for S3 calls
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=ClientError
        )
    
    async def connect(self):
        """Initialize S3 client"""
        try:
            self.session = aioboto3.Session(
                aws_access_key_id=AWS_CONFIG['access_key_id'],
                aws_secret_access_key=AWS_CONFIG['secret_access_key'],
                region_name=AWS_CONFIG['region']
            )
            self.logger.info("S3 resource connected")
        except Exception as e:
            self.logger.error(f"Failed to connect to S3: {str(e)}")
            raise
    
    async def disconnect(self):
        """Close S3 client"""
        self.session = None
        self.client = None
        self.logger.info("S3 resource disconnected")
    
    async def list_objects(self, prefix: str = "", suffix: str = "") -> List[Dict[str, Any]]:
        """
        List objects in S3 bucket with optional prefix and suffix filters
        Implements: retry logic, circuit breaker
        """
        async def _list():
            objects = []
            async with self.session.client('s3') as s3_client:
                paginator = s3_client.get_paginator('list_objects_v2')
                async for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if suffix and not obj['Key'].endswith(suffix):
                                continue
                            objects.append({
                                'key': obj['Key'],
                                'size': obj['Size'],
                                'last_modified': obj['LastModified'].isoformat(),
                                'etag': obj['ETag']
                            })
            self.logger.info(f"Listed {len(objects)} objects with prefix '{prefix}' and suffix '{suffix}'")
            return objects
        
        try:
            # Apply circuit breaker and retry logic
            return await retry_with_backoff(
                lambda: self.circuit_breaker.call(_list),
                max_retries=3,
                exceptions=(ClientError,)
            )
        except Exception as e:
            self.logger.error(f"Error listing S3 objects: {str(e)}")
            raise
    
    @timeout_decorator(30.0)  # 30 second timeout for downloads
    async def get_object(self, key: str) -> bytes:
        """
        Download object from S3
        Implements: retry logic, circuit breaker, timeout
        """
        async def _get():
            async with self.session.client('s3') as s3_client:
                response = await s3_client.get_object(Bucket=self.bucket_name, Key=key)
                data = await response['Body'].read()
                self.logger.info(f"Downloaded object: {key} ({len(data)} bytes)")
                return data
        
        try:
            return await retry_with_backoff(
                lambda: self.circuit_breaker.call(_get),
                max_retries=3,
                exceptions=(ClientError,)
            )
        except Exception as e:
            self.logger.error(f"Error downloading S3 object {key}: {str(e)}")
            raise
    
    async def get_object_metadata(self, key: str) -> Dict[str, Any]:
        """Get object metadata without downloading the content"""
        try:
            async with self.session.client('s3') as s3_client:
                response = await s3_client.head_object(Bucket=self.bucket_name, Key=key)
                metadata = {
                    'content_type': response.get('ContentType'),
                    'content_length': response.get('ContentLength'),
                    'last_modified': response.get('LastModified').isoformat() if response.get('LastModified') else None,
                    'etag': response.get('ETag'),
                    'metadata': response.get('Metadata', {})
                }
                self.logger.info(f"Retrieved metadata for: {key}")
                return metadata
        except ClientError as e:
            self.logger.error(f"Error getting S3 object metadata {key}: {str(e)}")
            raise
    
    async def put_object(self, key: str, data: bytes, metadata: Dict[str, str] = None) -> Dict[str, Any]:
        """Upload object to S3"""
        try:
            async with self.session.client('s3') as s3_client:
                params = {
                    'Bucket': self.bucket_name,
                    'Key': key,
                    'Body': data
                }
                if metadata:
                    params['Metadata'] = metadata
                
                response = await s3_client.put_object(**params)
                self.logger.info(f"Uploaded object: {key} ({len(data)} bytes)")
                return {
                    'etag': response['ETag'],
                    'version_id': response.get('VersionId')
                }
        except ClientError as e:
            self.logger.error(f"Error uploading S3 object {key}: {str(e)}")
            raise


class PostgreSQLResource(MCPResource):
    """
    MCP interface for PostgreSQL
    Implements: retry logic, circuit breaker, connection pooling
    """
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.logger = logging.getLogger(f"{__name__}.PostgreSQLResource")
        
        # Circuit breaker for PostgreSQL calls
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=asyncpg.PostgresError
        )
    
    async def connect(self):
        """Create connection pool, creating database and schema if needed"""
        try:
            # First try to connect to the target database
            try:
                self.pool = await asyncpg.create_pool(
                    host=POSTGRES_CONFIG['host'],
                    port=POSTGRES_CONFIG['port'],
                    database=POSTGRES_CONFIG['database'],
                    user=POSTGRES_CONFIG['user'],
                    password=POSTGRES_CONFIG['password'],
                    min_size=2,
                    max_size=10,
                    ssl='require'  # Required for AWS RDS
                )
                self.logger.info("PostgreSQL resource connected")
            except asyncpg.InvalidCatalogNameError:
                # Database doesn't exist, create it
                self.logger.info(f"Database {POSTGRES_CONFIG['database']} doesn't exist, creating...")
                
                # Connect to postgres database to create the target database
                conn = await asyncpg.connect(
                    host=POSTGRES_CONFIG['host'],
                    port=POSTGRES_CONFIG['port'],
                    database='postgres',
                    user=POSTGRES_CONFIG['user'],
                    password=POSTGRES_CONFIG['password'],
                    ssl='require'
                )
                try:
                    await conn.execute(f'CREATE DATABASE {POSTGRES_CONFIG["database"]}')
                    self.logger.info(f"Created database {POSTGRES_CONFIG['database']}")
                finally:
                    await conn.close()
                
                # Now connect to the newly created database
                self.pool = await asyncpg.create_pool(
                    host=POSTGRES_CONFIG['host'],
                    port=POSTGRES_CONFIG['port'],
                    database=POSTGRES_CONFIG['database'],
                    user=POSTGRES_CONFIG['user'],
                    password=POSTGRES_CONFIG['password'],
                    min_size=2,
                    max_size=10,
                    ssl='require'
                )
                
                # Create schema
                async with self.pool.acquire() as conn:
                    await conn.execute('''
                        CREATE TABLE IF NOT EXISTS documents (
                            id SERIAL PRIMARY KEY,
                            filename VARCHAR(255) NOT NULL,
                            s3_key VARCHAR(512) NOT NULL UNIQUE,
                            file_type VARCHAR(50),
                            file_size BIGINT,
                            status VARCHAR(50) DEFAULT 'pending',
                            extracted_data JSONB,
                            validation_results JSONB,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            error_message TEXT
                        )
                    ''')
                    await conn.execute('''
                        CREATE TABLE IF NOT EXISTS processing_logs (
                            id SERIAL PRIMARY KEY,
                            document_id INTEGER REFERENCES documents(id),
                            agent_name VARCHAR(100),
                            operation VARCHAR(100),
                            status VARCHAR(50),
                            details JSONB,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_document_id ON processing_logs(document_id)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_timestamp ON processing_logs(timestamp)')
                    self.logger.info("Database schema created successfully")
                
                self.logger.info("PostgreSQL resource connected")
        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {str(e)}")
            raise
    
    async def disconnect(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            self.pool = None
            self.logger.info("PostgreSQL resource disconnected")
    
    @timeout_decorator(10.0)  # 10 second timeout for queries
    async def execute(self, query: str, *args) -> str:
        """
        Execute a query (INSERT, UPDATE, DELETE)
        Implements: retry logic, circuit breaker, timeout
        """
        async def _execute():
            async with self.pool.acquire() as conn:
                result = await conn.execute(query, *args)
                self.logger.debug(f"Executed query: {result}")
                return result
        
        try:
            return await retry_with_backoff(
                lambda: self.circuit_breaker.call(_execute),
                max_retries=3,
                exceptions=(asyncpg.PostgresError,)
            )
        except Exception as e:
            self.logger.error(f"Error executing query: {str(e)}")
            raise
    
    @timeout_decorator(10.0)
    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """
        Fetch a single row
        Implements: retry logic, circuit breaker, timeout
        """
        async def _fetch():
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                if row:
                    return dict(row)
                return None
        
        try:
            return await retry_with_backoff(
                lambda: self.circuit_breaker.call(_fetch),
                max_retries=3,
                exceptions=(asyncpg.PostgresError,)
            )
        except Exception as e:
            self.logger.error(f"Error fetching row: {str(e)}")
            raise
    
    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch multiple rows"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]
    
    async def fetch_value(self, query: str, *args) -> Any:
        """Fetch a single value"""
        async with self.pool.acquire() as conn:
            return await conn.fetchval(query, *args)
    
    async def execute_many(self, query: str, args_list: List[tuple]) -> None:
        """Execute query with multiple parameter sets"""
        async with self.pool.acquire() as conn:
            await conn.executemany(query, args_list)
            self.logger.debug(f"Executed batch query with {len(args_list)} parameter sets")
    
    async def transaction(self):
        """Get a transaction context"""
        conn = await self.pool.acquire()
        return conn.transaction()
    
    async def initialize_schema(self):
        """Initialize database schema for document storage"""
        schema_sql = """
        CREATE TABLE IF NOT EXISTS documents (
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
        
        CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key);
        CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
        CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);
        CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date);
        
        CREATE TABLE IF NOT EXISTS processing_logs (
            id SERIAL PRIMARY KEY,
            document_id INTEGER REFERENCES documents(id),
            agent_name VARCHAR(50) NOT NULL,
            action VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            details JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id);
        CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name);
        """
        
        try:
            await self.execute(schema_sql)
            self.logger.info("Database schema initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize schema: {str(e)}")
            raise


class MCPContext:
    """
    Context manager for MCP resources
    Provides unified access to S3 and PostgreSQL
    """
    
    def __init__(self):
        self.s3 = S3Resource()
        self.postgres = PostgreSQLResource()
        self.logger = logging.getLogger(f"{__name__}.MCPContext")
    
    async def __aenter__(self):
        """Connect to all resources"""
        await self.s3.connect()
        await self.postgres.connect()
        self.logger.info("MCP context initialized")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Disconnect from all resources"""
        await self.s3.disconnect()
        await self.postgres.disconnect()
        self.logger.info("MCP context closed")

