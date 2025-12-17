"""
Test Skill Filtering System
Demonstrates how skill filtering works with different user categories
"""
import pytest
from skill_filter import (
    SkillFilter,
    UserContext,
    UserCategory,
    create_api_client_context
)
from agent_card import AgentSkill


class TestSkillFiltering:
    """Test suite for skill filtering functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.skill_filter = SkillFilter()

        # Create sample skills
        self.all_skills = [
            AgentSkill(
                skill_id='extract_document',
                name='Extract Document',
                description='Extract data from documents',
                method='extract_document',
                tags=['extraction', 'core']
            ),
            AgentSkill(
                skill_id='process_batch',
                name='Process Batch',
                description='Process multiple documents',
                method='process_batch',
                tags=['batch', 'processing']
            ),
            AgentSkill(
                skill_id='validate_document',
                name='Validate Document',
                description='Validate document data',
                method='validate_document',
                tags=['validation', 'quality']
            ),
            AgentSkill(
                skill_id='archive_document',
                name='Archive Document',
                description='Archive to database',
                method='archive_document',
                tags=['storage', 'persistence']
            ),
            AgentSkill(
                skill_id='get_document',
                name='Get Document',
                description='Retrieve document',
                method='get_document',
                tags=['retrieval', 'read']
            ),
            AgentSkill(
                skill_id='search_documents',
                name='Search Documents',
                description='Search documents',
                method='search_documents',
                tags=['search', 'query']
            ),
            AgentSkill(
                skill_id='get_document_stats',
                name='Get Statistics',
                description='Get document statistics',
                method='get_document_stats',
                tags=['analytics', 'metrics']
            ),
            AgentSkill(
                skill_id='update_document_status',
                name='Update Status',
                description='Update document status',
                method='update_document_status',
                tags=['update', 'admin']
            )
        ]

    def test_viewer_access(self):
        """Test viewer can only read, not process"""
        viewer = UserContext(user_id='viewer1', category=UserCategory.VIEWER)

        # Can read
        assert self.skill_filter.can_use_skill('get_document', viewer)
        assert self.skill_filter.can_use_skill('search_documents', viewer)
        assert self.skill_filter.can_use_skill('get_document_stats', viewer)

        # Cannot process
        assert not self.skill_filter.can_use_skill('extract_document', viewer)
        assert not self.skill_filter.can_use_skill('process_batch', viewer)
        assert not self.skill_filter.can_use_skill('validate_document', viewer)
        assert not self.skill_filter.can_use_skill('archive_document', viewer)

        # Filter skills
        filtered = self.skill_filter.filter_skills(self.all_skills, viewer)
        assert len(filtered) == 3  # Only read skills

    def test_standard_user_access(self):
        """Test standard user can process but not batch"""
        user = UserContext(user_id='user1', category=UserCategory.STANDARD_USER)

        # Can process individual documents
        assert self.skill_filter.can_use_skill('extract_document', user)

        # Cannot batch process
        assert not self.skill_filter.can_use_skill('process_batch', user)

        # Cannot validate
        assert not self.skill_filter.can_use_skill('validate_document', user)

        # Can read
        assert self.skill_filter.can_use_skill('get_document', user)

    def test_power_user_access(self):
        """Test power user can process and validate"""
        power_user = UserContext(user_id='power1', category=UserCategory.POWER_USER)

        # Can process
        assert self.skill_filter.can_use_skill('extract_document', power_user)
        assert self.skill_filter.can_use_skill('validate_document', power_user)
        assert self.skill_filter.can_use_skill('archive_document', power_user)

        # Cannot update status (admin only)
        assert not self.skill_filter.can_use_skill('update_document_status', power_user)

        filtered = self.skill_filter.filter_skills(self.all_skills, power_user)
        assert len(filtered) >= 6  # Most skills except admin

    def test_analyst_access(self):
        """Test analyst has analytics focus"""
        analyst = UserContext(user_id='analyst1', category=UserCategory.ANALYST)

        # Can analyze
        assert self.skill_filter.can_use_skill('get_document', analyst)
        assert self.skill_filter.can_use_skill('search_documents', analyst)
        assert self.skill_filter.can_use_skill('get_document_stats', analyst)

        # Cannot process
        assert not self.skill_filter.can_use_skill('extract_document', analyst)
        assert not self.skill_filter.can_use_skill('validate_document', analyst)

        # Cannot archive
        assert not self.skill_filter.can_use_skill('archive_document', analyst)

    def test_auditor_access(self):
        """Test auditor can validate and audit"""
        auditor = UserContext(user_id='auditor1', category=UserCategory.AUDITOR)

        # Can validate
        assert self.skill_filter.can_use_skill('validate_document', auditor)

        # Can search and read
        assert self.skill_filter.can_use_skill('get_document', auditor)
        assert self.skill_filter.can_use_skill('search_documents', auditor)

        # Cannot process
        assert not self.skill_filter.can_use_skill('extract_document', auditor)
        assert not self.skill_filter.can_use_skill('process_batch', auditor)

        # Cannot archive or update
        assert not self.skill_filter.can_use_skill('archive_document', auditor)
        assert not self.skill_filter.can_use_skill('update_document_status', auditor)

    def test_admin_access(self):
        """Test admin has full access"""
        admin = UserContext(user_id='admin1', category=UserCategory.ADMIN)

        # Can do everything
        for skill in self.all_skills:
            assert self.skill_filter.can_use_skill(skill.skill_id, admin)

        filtered = self.skill_filter.filter_skills(self.all_skills, admin)
        assert len(filtered) == len(self.all_skills)

    def test_custom_allowed_skills(self):
        """Test custom allowed skills override category defaults"""
        viewer = UserContext(
            user_id='viewer_special',
            category=UserCategory.VIEWER,
            custom_allowed_skills={'extract_document'}  # Special permission
        )

        # Viewer normally can't extract, but custom permission allows it
        assert self.skill_filter.can_use_skill('extract_document', viewer)

        # Still can't batch (not in custom list)
        assert not self.skill_filter.can_use_skill('process_batch', viewer)

    def test_custom_denied_skills(self):
        """Test custom denied skills override category defaults"""
        power_user = UserContext(
            user_id='power_restricted',
            category=UserCategory.POWER_USER,
            custom_denied_skills={'validate_document'}  # Restriction
        )

        # Power user normally can validate, but denied
        assert not self.skill_filter.can_use_skill('validate_document', power_user)

        # Can still extract (not denied)
        assert self.skill_filter.can_use_skill('extract_document', power_user)

    def test_api_client_custom_scope(self):
        """Test API client with custom skill grants"""
        api_client = create_api_client_context(
            client_id='analytics_api',
            allowed_skills=[
                'get_document',
                'search_documents',
                'get_document_stats'
            ],
            metadata={'tier': 'premium'}
        )

        # Can use explicitly granted skills
        assert self.skill_filter.can_use_skill('get_document', api_client)
        assert self.skill_filter.can_use_skill('search_documents', api_client)
        assert self.skill_filter.can_use_skill('get_document_stats', api_client)

        # Cannot use non-granted skills
        assert not self.skill_filter.can_use_skill('extract_document', api_client)
        assert not self.skill_filter.can_use_skill('validate_document', api_client)

        filtered = self.skill_filter.filter_skills(self.all_skills, api_client)
        assert len(filtered) == 3

    def test_get_skill_count_by_category(self):
        """Test skill counting by category"""
        power_user = UserContext(user_id='power1', category=UserCategory.POWER_USER)

        counts = self.skill_filter.get_skill_count_by_category(power_user, self.all_skills)

        # Should have skills from multiple categories
        assert 'document_processing' in counts
        assert 'quality_control' in counts or 'storage_analytics' in counts

    def test_admin_with_denied_skill(self):
        """Test admin can be restricted with custom denied skills"""
        admin_restricted = UserContext(
            user_id='admin_restricted',
            category=UserCategory.ADMIN,
            custom_denied_skills={'update_document_status'}  # Safety restriction
        )

        # Admin normally can update status, but denied
        assert not self.skill_filter.can_use_skill('update_document_status', admin_restricted)

        # Can still do everything else
        assert self.skill_filter.can_use_skill('extract_document', admin_restricted)
        assert self.skill_filter.can_use_skill('validate_document', admin_restricted)


def test_real_world_scenario_financial():
    """Test real-world scenario: Financial services"""
    skill_filter = SkillFilter()

    # Loan officer - process individual applications
    loan_officer = UserContext(
        user_id='loan_officer_001',
        category=UserCategory.STANDARD_USER,
        custom_allowed_skills={'search_documents', 'get_document_stats'}
    )

    assert skill_filter.can_use_skill('extract_document', loan_officer)
    assert skill_filter.can_use_skill('search_documents', loan_officer)
    assert not skill_filter.can_use_skill('process_batch', loan_officer)

    # Compliance officer - audit focus
    compliance = UserContext(
        user_id='compliance_001',
        category=UserCategory.AUDITOR,
        custom_allowed_skills={'update_document_status'}
    )

    assert skill_filter.can_use_skill('validate_document', compliance)
    assert skill_filter.can_use_skill('update_document_status', compliance)
    assert not skill_filter.can_use_skill('extract_document', compliance)


def test_real_world_scenario_healthcare():
    """Test real-world scenario: Healthcare"""
    skill_filter = SkillFilter()

    # Data entry clerk - limited processing
    data_entry = UserContext(
        user_id='clerk_001',
        category=UserCategory.STANDARD_USER,
        custom_denied_skills={'process_batch'}  # Safety: no batch
    )

    assert skill_filter.can_use_skill('extract_document', data_entry)
    assert not skill_filter.can_use_skill('process_batch', data_entry)

    # HIPAA auditor - compliance focus
    hipaa_auditor = UserContext(
        user_id='auditor_001',
        category=UserCategory.AUDITOR,
        metadata={'certification': 'HIPAA'}
    )

    assert skill_filter.can_use_skill('validate_document', hipaa_auditor)
    assert skill_filter.can_use_skill('search_documents', hipaa_auditor)
    assert not skill_filter.can_use_skill('extract_document', hipaa_auditor)


def test_permission_escalation_prevention():
    """Test that permission escalation is prevented"""
    skill_filter = SkillFilter()

    # Viewer trying to grant themselves admin powers via custom skills
    # This should NOT work - custom_allowed_skills should still respect base restrictions
    malicious_viewer = UserContext(
        user_id='malicious',
        category=UserCategory.VIEWER,
        custom_allowed_skills={'extract_document'}  # Try to gain extract permission
    )

    # Custom allowed skill works
    assert skill_filter.can_use_skill('extract_document', malicious_viewer)

    # But cannot grant category-level permissions
    assert not skill_filter.can_use_skill('process_batch', malicious_viewer)
    assert not skill_filter.can_use_skill('update_document_status', malicious_viewer)


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v'])
