"""
Skill Filtering System
Dynamically filters available agent skills based on user categories/roles
Supports role-based access control (RBAC) for agent capabilities
"""
from typing import Dict, Any, List, Optional, Set
from enum import Enum
from dataclasses import dataclass, field
from agent_card import AgentSkill, AgentCard


class UserCategory(str, Enum):
    """
    User categories for skill filtering
    Each category has different access levels to agent capabilities
    """
    # Basic users - limited read-only access
    VIEWER = "viewer"

    # Standard users - can process documents
    STANDARD_USER = "standard_user"

    # Power users - can process and validate
    POWER_USER = "power_user"

    # Analysts - focus on analytics and reporting
    ANALYST = "analyst"

    # Auditors - focus on compliance and auditing
    AUDITOR = "auditor"

    # Administrators - full access
    ADMIN = "admin"

    # API clients - programmatic access with custom scopes
    API_CLIENT = "api_client"


class SkillCategory(str, Enum):
    """
    Skill categories for organizing capabilities
    Maps to the 3 main categories in AGENT_SKILLS_BY_CLIENT_USE_CASE.md
    """
    DOCUMENT_PROCESSING = "document_processing"
    QUALITY_CONTROL = "quality_control"
    STORAGE_ANALYTICS = "storage_analytics"
    DISCOVERY = "discovery"
    ADMINISTRATIVE = "administrative"


# Define which skills belong to which categories
SKILL_TO_CATEGORY_MAPPING: Dict[str, SkillCategory] = {
    # Document Processing skills
    'extract_document': SkillCategory.DOCUMENT_PROCESSING,
    'pdf_text_extraction': SkillCategory.DOCUMENT_PROCESSING,
    'pdf_table_extraction': SkillCategory.DOCUMENT_PROCESSING,
    'csv_parsing': SkillCategory.DOCUMENT_PROCESSING,
    'list_supported_formats': SkillCategory.DOCUMENT_PROCESSING,
    'process_document': SkillCategory.DOCUMENT_PROCESSING,
    'process_batch': SkillCategory.DOCUMENT_PROCESSING,
    'get_task_status': SkillCategory.DOCUMENT_PROCESSING,
    'list_pending_documents': SkillCategory.DOCUMENT_PROCESSING,

    # Quality Control skills
    'validate_document': SkillCategory.QUALITY_CONTROL,
    'data_completeness_check': SkillCategory.QUALITY_CONTROL,
    'data_format_validation': SkillCategory.QUALITY_CONTROL,
    'data_quality_assessment': SkillCategory.QUALITY_CONTROL,
    'data_consistency_check': SkillCategory.QUALITY_CONTROL,
    'get_validation_rules': SkillCategory.QUALITY_CONTROL,
    'audit_logging': SkillCategory.QUALITY_CONTROL,

    # Storage & Analytics skills
    'archive_document': SkillCategory.STORAGE_ANALYTICS,
    'get_document': SkillCategory.STORAGE_ANALYTICS,
    'update_document_status': SkillCategory.STORAGE_ANALYTICS,
    'search_documents': SkillCategory.STORAGE_ANALYTICS,
    'get_document_stats': SkillCategory.STORAGE_ANALYTICS,

    # Discovery skills
    'discover_agents': SkillCategory.DISCOVERY,
    'get_agent_registry': SkillCategory.DISCOVERY,
}


# Define access permissions for each user category
USER_CATEGORY_PERMISSIONS: Dict[UserCategory, Dict[str, Any]] = {
    UserCategory.VIEWER: {
        'allowed_skill_categories': [
            SkillCategory.DISCOVERY
        ],
        'allowed_skills': [
            'get_task_status',
            'list_supported_formats',
            'get_validation_rules',
            'get_document',
            'search_documents',
            'get_document_stats'
        ],
        'denied_skills': [],
        'description': 'Read-only access to view documents and statistics'
    },

    UserCategory.STANDARD_USER: {
        'allowed_skill_categories': [
            SkillCategory.DOCUMENT_PROCESSING,
            SkillCategory.DISCOVERY
        ],
        'allowed_skills': [
            'get_document',
            'search_documents',
            'get_task_status'
        ],
        'denied_skills': [
            'process_batch',  # Can't do batch processing
            'update_document_status'  # Can't update status
        ],
        'description': 'Can process individual documents and view results'
    },

    UserCategory.POWER_USER: {
        'allowed_skill_categories': [
            SkillCategory.DOCUMENT_PROCESSING,
            SkillCategory.QUALITY_CONTROL,
            SkillCategory.DISCOVERY
        ],
        'allowed_skills': [
            'get_document',
            'search_documents',
            'archive_document'
        ],
        'denied_skills': [
            'update_document_status'  # Can't manually update status
        ],
        'description': 'Full document processing and validation capabilities'
    },

    UserCategory.ANALYST: {
        'allowed_skill_categories': [
            SkillCategory.STORAGE_ANALYTICS,
            SkillCategory.DISCOVERY
        ],
        'allowed_skills': [
            'get_task_status',
            'list_pending_documents',
            'list_supported_formats'
        ],
        'denied_skills': [
            'archive_document',
            'update_document_status'
        ],
        'description': 'Analytics and reporting focused access'
    },

    UserCategory.AUDITOR: {
        'allowed_skill_categories': [
            SkillCategory.QUALITY_CONTROL,
            SkillCategory.STORAGE_ANALYTICS,
            SkillCategory.DISCOVERY
        ],
        'allowed_skills': [
            'get_task_status',
            'list_pending_documents'
        ],
        'denied_skills': [
            'extract_document',
            'process_document',
            'process_batch',
            'archive_document',
            'update_document_status'
        ],
        'description': 'Audit and compliance focused access'
    },

    UserCategory.ADMIN: {
        'allowed_skill_categories': [
            SkillCategory.DOCUMENT_PROCESSING,
            SkillCategory.QUALITY_CONTROL,
            SkillCategory.STORAGE_ANALYTICS,
            SkillCategory.DISCOVERY,
            SkillCategory.ADMINISTRATIVE
        ],
        'allowed_skills': [],  # Empty means all skills
        'denied_skills': [],
        'description': 'Full administrative access to all capabilities'
    },

    UserCategory.API_CLIENT: {
        'allowed_skill_categories': [],  # Must explicitly grant skills
        'allowed_skills': [],  # Configured per API client
        'denied_skills': [],
        'description': 'Programmatic access with custom scope configuration'
    }
}


@dataclass
class UserContext:
    """
    User context for skill filtering
    Contains user identity and permissions
    """
    user_id: str
    category: UserCategory
    custom_allowed_skills: Set[str] = field(default_factory=set)
    custom_denied_skills: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure custom skills are sets"""
        if isinstance(self.custom_allowed_skills, list):
            self.custom_allowed_skills = set(self.custom_allowed_skills)
        if isinstance(self.custom_denied_skills, list):
            self.custom_denied_skills = set(self.custom_denied_skills)


class SkillFilter:
    """
    Filters agent skills based on user category and permissions
    """

    def __init__(self):
        self.skill_categories = SKILL_TO_CATEGORY_MAPPING
        self.permissions = USER_CATEGORY_PERMISSIONS

    def filter_skills(
        self,
        skills: List[AgentSkill],
        user_context: UserContext
    ) -> List[AgentSkill]:
        """
        Filter skills based on user context

        Args:
            skills: List of all available skills
            user_context: User context with category and permissions

        Returns:
            Filtered list of skills the user can access
        """
        if user_context.category == UserCategory.ADMIN:
            # Admins get all skills (unless custom denied)
            if user_context.custom_denied_skills:
                return [
                    skill for skill in skills
                    if skill.skill_id not in user_context.custom_denied_skills
                ]
            return skills

        # Get permissions for user category
        permissions = self.permissions.get(user_context.category, {})
        allowed_categories = set(permissions.get('allowed_skill_categories', []))
        allowed_skills = set(permissions.get('allowed_skills', []))
        denied_skills = set(permissions.get('denied_skills', []))

        # Merge with custom permissions (will be used for category-level checks)
        custom_allowed = user_context.custom_allowed_skills or set()
        custom_denied = user_context.custom_denied_skills or set()

        filtered_skills = []

        for skill in skills:
            skill_id = skill.skill_id

            # Custom allowed overrides category-level denials
            if skill_id in custom_allowed:
                filtered_skills.append(skill)
                continue
            
            # Custom denied overrides everything
            if skill_id in custom_denied:
                continue

            # Check if explicitly denied at category level
            if skill_id in denied_skills:
                continue

            # Check if explicitly allowed at category level
            if skill_id in allowed_skills:
                filtered_skills.append(skill)
                continue

            # Check if skill's category is allowed
            skill_category = self.skill_categories.get(skill_id)
            if skill_category and skill_category in allowed_categories:
                # Double-check not in denied list
                if skill_id not in denied_skills:
                    filtered_skills.append(skill)

        return filtered_skills

    def filter_agent_card(
        self,
        agent_card: AgentCard,
        user_context: UserContext
    ) -> AgentCard:
        """
        Create a filtered version of an agent card for a user

        Args:
            agent_card: Original agent card
            user_context: User context

        Returns:
            New agent card with filtered skills
        """
        # Create a copy of the agent card
        filtered_card = AgentCard(
            name=agent_card.name,
            version=agent_card.version,
            description=agent_card.description,
            endpoint=agent_card.endpoint,
            skills=[],
            resources=agent_card.resources,
            dependencies=agent_card.dependencies,
            tags=agent_card.tags
        )

        # Filter skills
        filtered_card.skills = self.filter_skills(agent_card.skills, user_context)

        return filtered_card

    def can_use_skill(
        self,
        skill_id: str,
        user_context: UserContext
    ) -> bool:
        """
        Check if a user can use a specific skill

        Args:
            skill_id: Skill identifier
            user_context: User context

        Returns:
            True if user can use the skill
        """
        if user_context.category == UserCategory.ADMIN:
            return skill_id not in user_context.custom_denied_skills

        permissions = self.permissions.get(user_context.category, {})
        allowed_categories = set(permissions.get('allowed_skill_categories', []))
        allowed_skills = set(permissions.get('allowed_skills', []))
        denied_skills = set(permissions.get('denied_skills', []))

        # Check custom permissions first (they override category defaults)
        if user_context.custom_allowed_skills and skill_id in user_context.custom_allowed_skills:
            return True
        
        if user_context.custom_denied_skills and skill_id in user_context.custom_denied_skills:
            return False

        # Merge custom permissions with category defaults
        if user_context.custom_allowed_skills:
            allowed_skills.update(user_context.custom_allowed_skills)
        if user_context.custom_denied_skills:
            denied_skills.update(user_context.custom_denied_skills)

        # Check denied
        if skill_id in denied_skills:
            return False

        # Check allowed
        if skill_id in allowed_skills:
            return True

        # Check category
        skill_category = self.skill_categories.get(skill_id)
        if skill_category and skill_category in allowed_categories:
            return True

        return False

    def get_allowed_skills_for_category(
        self,
        user_category: UserCategory
    ) -> Dict[str, Any]:
        """
        Get all allowed skills for a user category

        Args:
            user_category: User category

        Returns:
            Dictionary with allowed skills and categories
        """
        permissions = self.permissions.get(user_category, {})

        return {
            'user_category': user_category.value,
            'description': permissions.get('description', ''),
            'allowed_skill_categories': [
                cat.value for cat in permissions.get('allowed_skill_categories', [])
            ],
            'explicitly_allowed_skills': permissions.get('allowed_skills', []),
            'denied_skills': permissions.get('denied_skills', [])
        }

    def get_skill_count_by_category(
        self,
        user_context: UserContext,
        all_skills: List[AgentSkill]
    ) -> Dict[str, int]:
        """
        Count available skills by category for a user

        Args:
            user_context: User context
            all_skills: All available skills

        Returns:
            Dictionary with skill counts per category
        """
        filtered = self.filter_skills(all_skills, user_context)
        counts = {}

        for skill in filtered:
            category = self.skill_categories.get(skill.skill_id, 'uncategorized')
            category_name = category.value if hasattr(category, 'value') else str(category)
            counts[category_name] = counts.get(category_name, 0) + 1

        return counts


class SkillFilterMiddleware:
    """
    Middleware for applying skill filters to agent requests
    Use this in your agent's request handler to enforce permissions
    """

    def __init__(self, skill_filter: Optional[SkillFilter] = None):
        self.filter = skill_filter or SkillFilter()

    def check_permission(
        self,
        method: str,
        user_context: UserContext
    ) -> tuple[bool, Optional[str]]:
        """
        Check if user has permission to call a method

        Args:
            method: A2A method name (skill_id)
            user_context: User context

        Returns:
            Tuple of (allowed: bool, error_message: Optional[str])
        """
        if self.filter.can_use_skill(method, user_context):
            return True, None
        else:
            return False, f"Access denied: User category '{user_context.category.value}' cannot use skill '{method}'"

    def get_filtered_card(
        self,
        agent_card: AgentCard,
        user_context: UserContext
    ) -> Dict[str, Any]:
        """
        Get filtered agent card as dictionary for API response

        Args:
            agent_card: Original agent card
            user_context: User context

        Returns:
            Filtered agent card as dictionary
        """
        filtered = self.filter.filter_agent_card(agent_card, user_context)
        card_dict = filtered.to_dict()

        # Add user context info
        card_dict['filtered_for'] = {
            'user_id': user_context.user_id,
            'category': user_context.category.value,
            'skills_count': len(filtered.skills)
        }

        return card_dict


# Example usage and helper functions

def create_user_context_from_token(token_payload: Dict[str, Any]) -> UserContext:
    """
    Create user context from JWT or API token payload

    Example token payload:
    {
        "user_id": "user123",
        "category": "power_user",
        "custom_skills": ["special_skill"],
        "metadata": {"department": "finance"}
    }
    """
    return UserContext(
        user_id=token_payload.get('user_id', 'unknown'),
        category=UserCategory(token_payload.get('category', 'viewer')),
        custom_allowed_skills=set(token_payload.get('custom_allowed_skills', [])),
        custom_denied_skills=set(token_payload.get('custom_denied_skills', [])),
        metadata=token_payload.get('metadata', {})
    )


def create_api_client_context(
    client_id: str,
    allowed_skills: List[str],
    metadata: Optional[Dict[str, Any]] = None
) -> UserContext:
    """
    Create context for API client with specific skill grants

    Args:
        client_id: API client identifier
        allowed_skills: List of skill IDs this client can use
        metadata: Optional metadata

    Returns:
        UserContext configured for API client
    """
    return UserContext(
        user_id=f"api_client:{client_id}",
        category=UserCategory.API_CLIENT,
        custom_allowed_skills=set(allowed_skills),
        metadata=metadata or {'type': 'api_client', 'client_id': client_id}
    )


# Example permission configurations for different industries

INDUSTRY_CONFIGURATIONS = {
    'financial_services': {
        'loan_officer': UserContext(
            user_id='loan_officer',
            category=UserCategory.STANDARD_USER,
            custom_allowed_skills={'search_documents', 'get_document_stats'}
        ),
        'compliance_officer': UserContext(
            user_id='compliance_officer',
            category=UserCategory.AUDITOR,
            custom_allowed_skills={'update_document_status'}
        ),
        'data_analyst': UserContext(
            user_id='data_analyst',
            category=UserCategory.ANALYST,
            custom_allowed_skills=set()
        )
    },
    'healthcare': {
        'data_entry': UserContext(
            user_id='data_entry',
            category=UserCategory.STANDARD_USER,
            custom_denied_skills={'process_batch'}
        ),
        'records_manager': UserContext(
            user_id='records_manager',
            category=UserCategory.POWER_USER,
            custom_allowed_skills={'update_document_status'}
        ),
        'hipaa_auditor': UserContext(
            user_id='hipaa_auditor',
            category=UserCategory.AUDITOR,
            custom_allowed_skills=set()
        )
    }
}
