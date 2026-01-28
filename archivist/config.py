"""
Configuration management for the multi-agent document pipeline
Includes security settings for authentication and authorization
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
        'port': int(os.getenv('ORCHESTRATOR_PORT', 8001)),
        'url': os.getenv('ORCHESTRATOR_URL', 'http://localhost:8001')
    },
    'extractor': {
        'host': os.getenv('EXTRACTOR_HOST', 'localhost'),
        'port': int(os.getenv('EXTRACTOR_PORT', 8002)),
        'url': os.getenv('EXTRACTOR_URL', 'http://localhost:8002')
    },
    'validator': {
        'host': os.getenv('VALIDATOR_HOST', 'localhost'),
        'port': int(os.getenv('VALIDATOR_PORT', 8003)),
        'url': os.getenv('VALIDATOR_URL', 'http://localhost:8003')
    },
    'archivist': {
        'host': os.getenv('ARCHIVIST_HOST', 'localhost'),
        'port': int(os.getenv('ARCHIVIST_PORT', 8004)),
        'url': os.getenv('ARCHIVIST_URL', 'http://localhost:8004')
    }
}

# Security Configuration
SECURITY_CONFIG = {
    # Enable/disable security features
    'enable_authentication': os.getenv('ENABLE_AUTHENTICATION', 'true').lower() == 'true',
    'enable_rate_limiting': os.getenv('ENABLE_RATE_LIMITING', 'true').lower() == 'true',
    'enable_request_signing': os.getenv('ENABLE_REQUEST_SIGNING', 'false').lower() == 'true',
    
    # JWT Configuration
    'jwt_secret_key': os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production'),
    'jwt_algorithm': os.getenv('JWT_ALGORITHM', 'HS256'),
    'jwt_expiration_hours': int(os.getenv('JWT_EXPIRATION_HOURS', 24)),
    
    # API Key Configuration
    'api_key_header': os.getenv('API_KEY_HEADER', 'X-API-Key'),
    
    # Rate Limiting Configuration
    'rate_limit_rpm': int(os.getenv('RATE_LIMIT_RPM', 60)),  # requests per minute
    'rate_limit_rph': int(os.getenv('RATE_LIMIT_RPH', 1000)),  # requests per hour
    
    # Request Signing (HMAC)
    'signature_secret_key': os.getenv('SIGNATURE_SECRET_KEY', 'dev-signature-secret'),
    'signature_max_age_seconds': int(os.getenv('SIGNATURE_MAX_AGE_SECONDS', 300)),
    
    # Agent Tokens (for inter-agent communication)
    'agent_jwt_token': os.getenv('AGENT_JWT_TOKEN'),
    'agent_api_key': os.getenv('AGENT_API_KEY'),
    
    # Audit Logging
    'enable_audit_logging': os.getenv('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true',
}

# SSL/TLS Configuration
SSL_CONFIG = {
    'enable_ssl': os.getenv('ENABLE_SSL', 'false').lower() == 'true',
    'ssl_cert_path': os.getenv('SSL_CERT_PATH'),
    'ssl_key_path': os.getenv('SSL_KEY_PATH'),
    'ssl_ca_cert_path': os.getenv('SSL_CA_CERT_PATH'),
    'ssl_verify': os.getenv('SSL_VERIFY', 'true').lower() == 'true',
}

# Logging Configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')  # 'json' or 'text'

