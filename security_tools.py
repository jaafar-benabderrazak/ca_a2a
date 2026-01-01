#!/usr/bin/env python3
"""
Security Tools and Utilities
Provides CLI tools for managing security: generating tokens, managing API keys, etc.
"""
import os
import sys
import secrets
import hashlib
import argparse
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security import SecurityManager, JWTManager, APIKeyManager


def generate_secret(length: int = 64) -> str:
    """Generate a cryptographically secure random secret"""
    return secrets.token_urlsafe(length)


def generate_jwt_token(
    agent_id: str,
    permissions: list,
    expires_hours: int = 24,
    secret_key: str = None
):
    """Generate a JWT token for an agent"""
    if not secret_key:
        secret_key = os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production')
    
    jwt_manager = JWTManager(secret_key)
    token = jwt_manager.generate_token(agent_id, permissions, expires_hours)
    
    print(f"\n✅ JWT Token Generated for: {agent_id}")
    print(f"📅 Expires: {datetime.utcnow() + timedelta(hours=expires_hours)}")
    print(f"🔑 Token:")
    print(f"\n{token}\n")
    print(f"💡 Add to your .env file:")
    print(f"AGENT_JWT_TOKEN={token}")
    print(f"\n📋 Permissions: {', '.join(permissions)}")


def generate_api_key(agent_id: str) -> str:
    """Generate an API key for an agent"""
    # Format: agent-id:random-secret
    random_part = secrets.token_urlsafe(32)
    api_key = f"{agent_id}-{random_part}"
    
    print(f"\n✅ API Key Generated for: {agent_id}")
    print(f"🔑 API Key:")
    print(f"\n{api_key}\n")
    print(f"💡 Add to your .env file:")
    print(f"AGENT_API_KEY={api_key}")
    print(f"\n⚠️  Store this securely! It won't be shown again.")
    
    return api_key


def verify_jwt_token(token: str, secret_key: str = None):
    """Verify and decode a JWT token"""
    if not secret_key:
        secret_key = os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production')
    
    jwt_manager = JWTManager(secret_key)
    success, auth_context, error = jwt_manager.verify_token(token)
    
    if success:
        print(f"\n✅ Token is VALID")
        print(f"🆔 Agent ID: {auth_context.agent_id}")
        print(f"📋 Permissions: {', '.join(auth_context.permissions)}")
        print(f"📅 Expires: {auth_context.expires_at}")
        print(f"🔐 Auth Method: {auth_context.auth_method.value}")
    else:
        print(f"\n❌ Token is INVALID")
        print(f"Error: {error}")


def setup_agent_keys(agents: list = None):
    """Generate keys for all agents"""
    if agents is None:
        agents = ['orchestrator', 'extractor', 'validator', 'archivist']
    
    print("\n" + "="*70)
    print("CA A2A Agent Keys Setup")
    print("="*70)
    
    print("\n🔐 Generating authentication credentials for all agents...\n")
    
    api_keys = {}
    jwt_tokens = {}
    
    # Generate API keys
    print("\n" + "-"*70)
    print("API KEYS")
    print("-"*70)
    for agent in agents:
        api_keys[agent] = generate_api_key(agent)
        print()
    
    # Generate JWT tokens with full permissions
    print("\n" + "-"*70)
    print("JWT TOKENS (Full Permissions)")
    print("-"*70)
    secret_key = os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production')
    
    for agent in agents:
        jwt_tokens[agent] = None  # Generate on demand
        jwt_manager = JWTManager(secret_key)
        token = jwt_manager.generate_token(
            agent_id=agent,
            permissions=['*'],  # Full permissions
            expires_hours=8760  # 1 year
        )
        jwt_tokens[agent] = token
        
        print(f"\n{agent.upper()}:")
        print(f"  Token: {token}")
    
    # Create .env file snippet
    print("\n" + "="*70)
    print("ADD TO YOUR .env FILE:")
    print("="*70)
    
    env_snippet = f"""
# Generated on {datetime.utcnow().isoformat()}

# JWT Secret (CHANGE THIS IN PRODUCTION!)
JWT_SECRET_KEY={secret_key}

# Agent API Keys
"""
    for agent, key in api_keys.items():
        env_snippet += f"{agent.upper()}_API_KEY={key}\n"
    
    env_snippet += "\n# Agent JWT Tokens (1 year expiration)\n"
    for agent, token in jwt_tokens.items():
        env_snippet += f"{agent.upper()}_JWT_TOKEN={token}\n"
    
    print(env_snippet)
    
    # Save to file
    output_file = "agent_credentials.env"
    with open(output_file, 'w') as f:
        f.write(env_snippet)
    
    print(f"\n💾 Credentials saved to: {output_file}")
    print(f"⚠️  KEEP THIS FILE SECURE! Add to .gitignore")


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description='CA A2A Security Tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a random secret
  python security_tools.py generate-secret
  
  # Generate JWT token for orchestrator
  python security_tools.py generate-jwt orchestrator
  
  # Generate JWT with custom permissions
  python security_tools.py generate-jwt extractor --permissions extract_document validate_document
  
  # Generate API key
  python security_tools.py generate-api-key validator
  
  # Verify a JWT token
  python security_tools.py verify-jwt <token>
  
  # Setup all agent credentials
  python security_tools.py setup-all-agents
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate secret command
    secret_parser = subparsers.add_parser('generate-secret', help='Generate a random secret')
    secret_parser.add_argument('--length', type=int, default=64, help='Length of secret')
    
    # Generate JWT command
    jwt_parser = subparsers.add_parser('generate-jwt', help='Generate JWT token')
    jwt_parser.add_argument('agent_id', help='Agent identifier')
    jwt_parser.add_argument('--permissions', nargs='+', default=['*'], help='List of permissions')
    jwt_parser.add_argument('--expires', type=int, default=24, help='Expiration in hours')
    jwt_parser.add_argument('--secret', help='JWT secret key (or use JWT_SECRET_KEY env var)')
    
    # Generate API key command
    api_parser = subparsers.add_parser('generate-api-key', help='Generate API key')
    api_parser.add_argument('agent_id', help='Agent identifier')
    
    # Verify JWT command
    verify_parser = subparsers.add_parser('verify-jwt', help='Verify JWT token')
    verify_parser.add_argument('token', help='JWT token to verify')
    verify_parser.add_argument('--secret', help='JWT secret key (or use JWT_SECRET_KEY env var)')
    
    # Setup all agents command
    setup_parser = subparsers.add_parser('setup-all-agents', help='Setup credentials for all agents')
    setup_parser.add_argument('--agents', nargs='+', help='List of agents (default: all)')
    
    # Hash API key command
    hash_parser = subparsers.add_parser('hash-api-key', help='Hash an API key for storage')
    hash_parser.add_argument('api_key', help='API key to hash')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'generate-secret':
        secret = generate_secret(args.length)
        print(f"\n🔐 Generated Secret ({args.length} bytes):")
        print(f"\n{secret}\n")
        print("💡 Add to your .env file:")
        print(f"JWT_SECRET_KEY={secret}")
    
    elif args.command == 'generate-jwt':
        generate_jwt_token(
            args.agent_id,
            args.permissions,
            args.expires,
            args.secret
        )
    
    elif args.command == 'generate-api-key':
        generate_api_key(args.agent_id)
    
    elif args.command == 'verify-jwt':
        verify_jwt_token(args.token, args.secret)
    
    elif args.command == 'setup-all-agents':
        setup_agent_keys(args.agents)
    
    elif args.command == 'hash-api-key':
        hashed = hash_api_key(args.api_key)
        print(f"\n🔐 Hashed API Key:")
        print(f"\n{hashed}\n")
        print("💾 Store this hash in your database, not the original key!")


if __name__ == '__main__':
    main()
