"""
Configuration management for the multi-agent document pipeline
"""
import os
from dotenv import load_dotenv

load_dotenv()

# AWS Configuration
AWS_CONFIG = {
    'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
    'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
    'region': os.getenv('AWS_REGION', 'us-east-1'),
    's3_bucket': os.getenv('S3_BUCKET_NAME')
}

# PostgreSQL Configuration
POSTGRES_CONFIG = {
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': int(os.getenv('POSTGRES_PORT', 5432)),
    'database': os.getenv('POSTGRES_DB', 'documents_db'),
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD')
}

# Agent Configuration
AGENTS_CONFIG = {
    'orchestrator': {
        'host': os.getenv('ORCHESTRATOR_HOST', 'localhost'),
        'port': int(os.getenv('ORCHESTRATOR_PORT', 8001))
    },
    'extractor': {
        'host': os.getenv('EXTRACTOR_HOST', 'localhost'),
        'port': int(os.getenv('EXTRACTOR_PORT', 8002))
    },
    'validator': {
        'host': os.getenv('VALIDATOR_HOST', 'localhost'),
        'port': int(os.getenv('VALIDATOR_PORT', 8003))
    },
    'archivist': {
        'host': os.getenv('ARCHIVIST_HOST', 'localhost'),
        'port': int(os.getenv('ARCHIVIST_PORT', 8004))
    }
}

# Logging Configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

