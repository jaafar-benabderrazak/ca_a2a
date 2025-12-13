"""
Agent Card and Skills System
Provides self-description and capability discovery for agents
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict, field
import json


@dataclass
class AgentSkill:
    """
    Represents a single skill/capability that an agent can perform
    """
    skill_id: str
    name: str
    description: str
    method: str  # A2A method name
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    avg_processing_time_ms: Optional[int] = None
    max_input_size_mb: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert skill to dictionary"""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ResourceRequirements:
    """Resource requirements for an agent"""
    memory_mb: int = 512
    cpu_cores: float = 0.5
    storage_required: bool = False
    network_required: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentDependencies:
    """External dependencies required by an agent"""
    services: List[str] = field(default_factory=list)  # e.g., ["s3", "postgres"]
    libraries: List[str] = field(default_factory=list)  # e.g., ["PyPDF2", "pandas"]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AgentCard:
    """
    Agent Card: Self-descriptive profile for agent discovery and capability negotiation
    
    An agent card provides:
    - Identity and version information
    - List of skills/capabilities
    - Resource requirements
    - Endpoint information
    - Health and metrics endpoints
    """
    
    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        endpoint: str,
        skills: List[AgentSkill] = None,
        resources: Optional[ResourceRequirements] = None,
        dependencies: Optional[AgentDependencies] = None,
        tags: List[str] = None
    ):
        self.agent_id = f"{name.lower()}-{id(self)}"
        self.name = name
        self.version = version
        self.description = description
        self.endpoint = endpoint
        self.skills = skills or []
        self.resources = resources or ResourceRequirements()
        self.dependencies = dependencies or AgentDependencies()
        self.tags = tags or []
        self.status = "active"
        self.last_updated = datetime.now()
        
        # Standard endpoints
        self.health_check_endpoint = "/health"
        self.metrics_endpoint = "/status"
        self.card_endpoint = "/card"
        self.skills_endpoint = "/skills"
    
    def add_skill(self, skill: AgentSkill):
        """Add a skill to the agent card"""
        self.skills.append(skill)
        self.last_updated = datetime.now()
    
    def has_skill(self, skill_id: str) -> bool:
        """Check if agent has a specific skill"""
        return any(skill.skill_id == skill_id for skill in self.skills)
    
    def get_skill(self, skill_id: str) -> Optional[AgentSkill]:
        """Get a skill by ID"""
        for skill in self.skills:
            if skill.skill_id == skill_id:
                return skill
        return None
    
    def get_skills_by_tag(self, tag: str) -> List[AgentSkill]:
        """Get all skills with a specific tag"""
        return [skill for skill in self.skills if tag in skill.tags]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert agent card to dictionary"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "status": self.status,
            "endpoint": self.endpoint,
            "skills": [skill.to_dict() for skill in self.skills],
            "resources": self.resources.to_dict(),
            "dependencies": self.dependencies.to_dict(),
            "tags": self.tags,
            "endpoints": {
                "health_check": self.health_check_endpoint,
                "metrics": self.metrics_endpoint,
                "card": self.card_endpoint,
                "skills": self.skills_endpoint
            },
            "last_updated": self.last_updated.isoformat()
        }
    
    def to_json(self) -> str:
        """Convert agent card to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentCard':
        """Create AgentCard from dictionary"""
        skills = [
            AgentSkill(**skill_data) 
            for skill_data in data.get('skills', [])
        ]
        
        resources = ResourceRequirements(**data.get('resources', {}))
        dependencies = AgentDependencies(**data.get('dependencies', {}))
        
        card = cls(
            name=data['name'],
            version=data['version'],
            description=data['description'],
            endpoint=data['endpoint'],
            skills=skills,
            resources=resources,
            dependencies=dependencies,
            tags=data.get('tags', [])
        )
        
        card.status = data.get('status', 'active')
        if 'last_updated' in data:
            card.last_updated = datetime.fromisoformat(data['last_updated'])
        
        return card


class AgentRegistry:
    """
    Registry for managing discovered agents and their capabilities
    """
    
    def __init__(self):
        self.agents: Dict[str, AgentCard] = {}
    
    def register(self, agent_card: AgentCard):
        """Register an agent card"""
        self.agents[agent_card.name] = agent_card
    
    def unregister(self, agent_name: str):
        """Unregister an agent"""
        if agent_name in self.agents:
            del self.agents[agent_name]
    
    def get_agent(self, agent_name: str) -> Optional[AgentCard]:
        """Get an agent card by name"""
        return self.agents.get(agent_name)
    
    def get_all_agents(self) -> List[AgentCard]:
        """Get all registered agents"""
        return list(self.agents.values())
    
    def find_agents_by_skill(self, skill_id: str) -> List[AgentCard]:
        """Find all agents that have a specific skill"""
        return [
            agent for agent in self.agents.values()
            if agent.has_skill(skill_id)
        ]
    
    def find_agents_by_tag(self, tag: str) -> List[AgentCard]:
        """Find all agents with a specific tag"""
        return [
            agent for agent in self.agents.values()
            if tag in agent.tags
        ]
    
    def get_endpoints_for_skill(self, skill_id: str) -> List[str]:
        """Get all agent endpoints that support a specific skill"""
        agents = self.find_agents_by_skill(skill_id)
        return [agent.endpoint for agent in agents]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert registry to dictionary"""
        return {
            "total_agents": len(self.agents),
            "agents": {
                name: card.to_dict() 
                for name, card in self.agents.items()
            }
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the registry"""
        all_skills = set()
        all_tags = set()
        
        for agent in self.agents.values():
            for skill in agent.skills:
                all_skills.add(skill.skill_id)
                all_tags.update(skill.tags)
            all_tags.update(agent.tags)
        
        return {
            "total_agents": len(self.agents),
            "active_agents": len([a for a in self.agents.values() if a.status == "active"]),
            "total_skills": len(all_skills),
            "available_skills": sorted(list(all_skills)),
            "tags": sorted(list(all_tags)),
            "agents": {
                name: {
                    "endpoint": agent.endpoint,
                    "status": agent.status,
                    "skills_count": len(agent.skills)
                }
                for name, agent in self.agents.items()
            }
        }
