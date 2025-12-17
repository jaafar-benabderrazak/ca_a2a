"""
Skill Filter Integration Examples
Shows how to integrate skill filtering into agents and API endpoints
"""
import asyncio
from typing import Dict, Any, Optional
from aiohttp import web
import jwt
import logging

from skill_filter import (
    SkillFilter,
    SkillFilterMiddleware,
    UserContext,
    UserCategory,
    create_user_context_from_token,
    create_api_client_context
)
from a2a_protocol import A2AMessage, ErrorCodes


class FilteredAgentMixin:
    """
    Mixin to add skill filtering to BaseAgent
    Add this to your agent classes to enable permission checking
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.skill_filter_middleware = SkillFilterMiddleware()
        self.require_auth = kwargs.get('require_auth', True)

    def extract_user_context(self, request_headers: Dict[str, str]) -> Optional[UserContext]:
        """
        Extract user context from request headers

        Supports multiple auth methods:
        - Authorization: Bearer <JWT>
        - X-API-Key: <api_key>
        - X-User-Category: <category>
        """
        # Method 1: JWT token
        auth_header = request_headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                # Decode JWT (in production, verify signature!)
                payload = jwt.decode(token, options={"verify_signature": False})
                return create_user_context_from_token(payload)
            except Exception as e:
                logging.warning(f"Failed to decode JWT: {e}")

        # Method 2: API Key (lookup in database)
        api_key = request_headers.get('x-api-key')
        if api_key:
            # In production, lookup API key in database
            client_config = self._lookup_api_client(api_key)
            if client_config:
                return create_api_client_context(
                    client_id=client_config['client_id'],
                    allowed_skills=client_config['allowed_skills'],
                    metadata=client_config.get('metadata')
                )

        # Method 3: Simple category header (for development)
        user_category = request_headers.get('x-user-category')
        user_id = request_headers.get('x-user-id', 'anonymous')
        if user_category:
            try:
                return UserContext(
                    user_id=user_id,
                    category=UserCategory(user_category)
                )
            except ValueError:
                logging.warning(f"Invalid user category: {user_category}")

        # Default: viewer access for unauthenticated requests
        if not self.require_auth:
            return UserContext(
                user_id='anonymous',
                category=UserCategory.VIEWER
            )

        return None

    def _lookup_api_client(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Lookup API client configuration by API key
        In production, this would query a database
        """
        # Example configuration (move to database in production)
        api_clients = {
            'test-key-standard': {
                'client_id': 'client_001',
                'allowed_skills': ['extract_document', 'get_task_status', 'get_document'],
                'metadata': {'tier': 'standard'}
            },
            'test-key-premium': {
                'client_id': 'client_002',
                'allowed_skills': [
                    'extract_document', 'process_document', 'process_batch',
                    'validate_document', 'archive_document',
                    'get_document', 'search_documents', 'get_document_stats'
                ],
                'metadata': {'tier': 'premium'}
            },
            'test-key-analytics': {
                'client_id': 'client_003',
                'allowed_skills': [
                    'get_document', 'search_documents', 'get_document_stats',
                    'get_task_status', 'list_pending_documents'
                ],
                'metadata': {'tier': 'analytics'}
            }
        }
        return api_clients.get(api_key)

    async def handle_filtered_message(
        self,
        message: A2AMessage,
        user_context: Optional[UserContext]
    ) -> A2AMessage:
        """
        Handle A2A message with permission checking

        Args:
            message: A2A message
            user_context: User context (None for unauthenticated)

        Returns:
            A2A response message
        """
        # If auth required but no context, deny
        if self.require_auth and not user_context:
            return A2AMessage.create_error(
                message.id,
                ErrorCodes.INVALID_REQUEST,
                "Authentication required"
            )

        # Default to viewer if no context
        if not user_context:
            user_context = UserContext(
                user_id='anonymous',
                category=UserCategory.VIEWER
            )

        # Check permission for the method
        allowed, error_msg = self.skill_filter_middleware.check_permission(
            message.method,
            user_context
        )

        if not allowed:
            self.logger.warning(
                f"Access denied: user={user_context.user_id}, "
                f"category={user_context.category.value}, "
                f"method={message.method}"
            )
            return A2AMessage.create_error(
                message.id,
                ErrorCodes.METHOD_NOT_FOUND,
                error_msg
            )

        # Permission granted, proceed with normal handling
        self.logger.info(
            f"Access granted: user={user_context.user_id}, "
            f"category={user_context.category.value}, "
            f"method={message.method}"
        )

        # Call the original message handler
        try:
            response = await self.protocol.handle_message(message)
            return response
        except Exception as e:
            return A2AMessage.create_error(
                message.id,
                ErrorCodes.INTERNAL_ERROR,
                str(e)
            )

    def get_filtered_card_for_user(self, user_context: UserContext) -> Dict[str, Any]:
        """
        Get agent card filtered for specific user

        Args:
            user_context: User context

        Returns:
            Filtered agent card dictionary
        """
        return self.skill_filter_middleware.get_filtered_card(
            self.agent_card,
            user_context
        )


# HTTP middleware for aiohttp

@web.middleware
async def skill_filter_middleware(request: web.Request, handler):
    """
    aiohttp middleware for skill filtering

    Add this to your aiohttp application:
        app.middlewares.append(skill_filter_middleware)
    """
    # Extract user context from headers
    user_context = None

    # Get the agent instance from app context
    agent = request.app.get('agent')
    if agent and hasattr(agent, 'extract_user_context'):
        user_context = agent.extract_user_context(dict(request.headers))

    # Store in request for handlers to use
    request['user_context'] = user_context

    # Proceed with request
    return await handler(request)


async def filtered_a2a_handler(request: web.Request) -> web.Response:
    """
    A2A endpoint handler with skill filtering

    Example route:
        app.router.add_post('/a2a', filtered_a2a_handler)
    """
    agent = request.app.get('agent')
    user_context = request.get('user_context')

    try:
        # Parse A2A message
        body = await request.json()
        message = A2AMessage(**body)

        # Handle with filtering
        if hasattr(agent, 'handle_filtered_message'):
            response = await agent.handle_filtered_message(message, user_context)
        else:
            # Fallback to normal handling
            response = await agent.protocol.handle_message(message)

        return web.json_response(response.to_dict())

    except Exception as e:
        error_response = A2AMessage.create_error(
            "unknown",
            ErrorCodes.INVALID_REQUEST,
            str(e)
        )
        return web.json_response(error_response.to_dict(), status=400)


async def filtered_card_handler(request: web.Request) -> web.Response:
    """
    Agent card endpoint that returns filtered skills based on user

    Example route:
        app.router.add_get('/card', filtered_card_handler)
    """
    agent = request.app.get('agent')
    user_context = request.get('user_context')

    if not user_context:
        # Return full card if no auth (or minimal card)
        return web.json_response(agent.agent_card.to_dict())

    # Return filtered card
    if hasattr(agent, 'get_filtered_card_for_user'):
        filtered_card = agent.get_filtered_card_for_user(user_context)
        return web.json_response(filtered_card)
    else:
        return web.json_response(agent.agent_card.to_dict())


async def user_permissions_handler(request: web.Request) -> web.Response:
    """
    Endpoint to query user's permissions

    Example route:
        app.router.add_get('/permissions', user_permissions_handler)

    Response:
        {
            "user_id": "user123",
            "category": "power_user",
            "allowed_skills": [...],
            "skill_count": 15,
            "skill_count_by_category": {...}
        }
    """
    agent = request.app.get('agent')
    user_context = request.get('user_context')

    if not user_context:
        return web.json_response({
            'error': 'Authentication required'
        }, status=401)

    skill_filter = SkillFilter()

    # Get all skills from agent
    all_skills = agent.agent_card.skills if agent.agent_card else []

    # Filter for user
    allowed_skills = skill_filter.filter_skills(all_skills, user_context)
    skill_counts = skill_filter.get_skill_count_by_category(user_context, all_skills)

    return web.json_response({
        'user_id': user_context.user_id,
        'category': user_context.category.value,
        'allowed_skills': [skill.skill_id for skill in allowed_skills],
        'skill_count': len(allowed_skills),
        'skill_count_by_category': skill_counts,
        'permissions': skill_filter.get_allowed_skills_for_category(user_context.category)
    })


# Example: How to update your agent to support filtering

class FilteredOrchestratorAgent:
    """
    Example of integrating skill filtering into OrchestratorAgent

    Usage:
        # In orchestrator_agent.py, update the class definition:

        class OrchestratorAgent(FilteredAgentMixin, BaseAgent):
            def __init__(self):
                super().__init__(
                    'Orchestrator',
                    config['host'],
                    config['port'],
                    require_auth=True  # Enable authentication
                )
                # ... rest of init
    """
    pass


# Example: Configure aiohttp app with filtering

def create_filtered_agent_app(agent) -> web.Application:
    """
    Create aiohttp application with skill filtering enabled

    Args:
        agent: Agent instance (should inherit from FilteredAgentMixin)

    Returns:
        Configured aiohttp application
    """
    app = web.Application(middlewares=[skill_filter_middleware])
    app['agent'] = agent

    # Add routes
    app.router.add_post('/a2a', filtered_a2a_handler)
    app.router.add_get('/card', filtered_card_handler)
    app.router.add_get('/permissions', user_permissions_handler)
    app.router.add_get('/health', lambda r: web.json_response({'status': 'healthy'}))

    return app


# Example usage scenarios

def example_usage():
    """Examples of how to use the filtering system"""

    # Example 1: Check if user can use a skill
    skill_filter = SkillFilter()

    viewer = UserContext(user_id='user1', category=UserCategory.VIEWER)
    can_extract = skill_filter.can_use_skill('extract_document', viewer)
    print(f"Viewer can extract: {can_extract}")  # False

    power_user = UserContext(user_id='user2', category=UserCategory.POWER_USER)
    can_extract = skill_filter.can_use_skill('extract_document', power_user)
    print(f"Power user can extract: {can_extract}")  # True

    # Example 2: Create custom API client
    analytics_client = create_api_client_context(
        client_id='analytics_team',
        allowed_skills=[
            'get_document',
            'search_documents',
            'get_document_stats',
            'get_task_status'
        ],
        metadata={'department': 'analytics', 'tier': 'premium'}
    )

    # Example 3: Filter agent card
    from agent_card import AgentCard, AgentSkill

    # Assume we have an agent card
    # filtered_card = skill_filter.filter_agent_card(agent_card, analytics_client)

    # Example 4: Get permissions for a category
    auditor_perms = skill_filter.get_allowed_skills_for_category(UserCategory.AUDITOR)
    print(f"Auditor permissions: {auditor_perms}")

    # Example 5: Create JWT token for a user
    import jwt

    token_payload = {
        'user_id': 'user123',
        'category': 'power_user',
        'custom_allowed_skills': ['special_skill'],
        'exp': 1234567890  # expiration timestamp
    }

    # In production, use a secret key
    token = jwt.encode(token_payload, 'your-secret-key', algorithm='HS256')
    print(f"JWT token: {token}")


if __name__ == '__main__':
    example_usage()
