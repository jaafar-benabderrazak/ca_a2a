#!/usr/bin/env python3
"""
Agent Card Discovery Example
Demonstrates how to use the agent card system for capability discovery
"""
import asyncio
import aiohttp
import json
from typing import Dict, Any, List


async def fetch_agent_card(url: str) -> Dict[str, Any]:
    """Fetch agent card from an agent"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{url}/card", timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return None
    except Exception as e:
        print(f"Error fetching card from {url}: {str(e)}")
        return None


async def fetch_agent_skills(url: str) -> Dict[str, Any]:
    """Fetch just the skills from an agent"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{url}/skills", timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return None
    except Exception as e:
        print(f"Error fetching skills from {url}: {str(e)}")
        return None


async def discover_all_agents(agent_urls: List[str]):
    """Discover all agents and their capabilities"""
    print("=" * 80)
    print("AGENT DISCOVERY DEMO")
    print("=" * 80)
    print()
    
    all_cards = {}
    
    for url in agent_urls:
        print(f"Discovering agent at {url}...")
        card = await fetch_agent_card(url)
        
        if card:
            all_cards[card['name']] = card
            print(f"  ✓ Found: {card['name']} v{card['version']}")
            print(f"    Description: {card['description']}")
            print(f"    Skills: {len(card['skills'])}")
            print(f"    Status: {card['status']}")
            print()
        else:
            print(f"  ✗ Could not reach agent at {url}")
            print()
    
    return all_cards


async def print_agent_details(card: Dict[str, Any]):
    """Print detailed information about an agent"""
    print("-" * 80)
    print(f"AGENT: {card['name']} (v{card['version']})")
    print("-" * 80)
    print(f"Endpoint: {card['endpoint']}")
    print(f"Description: {card['description']}")
    print(f"Status: {card['status']}")
    print()
    
    print("Resources:")
    print(f"  Memory: {card['resources']['memory_mb']} MB")
    print(f"  CPU: {card['resources']['cpu_cores']} cores")
    print(f"  Storage Required: {card['resources']['storage_required']}")
    print()
    
    print("Dependencies:")
    print(f"  Services: {', '.join(card['dependencies']['services']) or 'None'}")
    print(f"  Libraries: {', '.join(card['dependencies']['libraries'][:3])}..." if len(card['dependencies']['libraries']) > 3 else f"  Libraries: {', '.join(card['dependencies']['libraries'])}")
    print()
    
    print(f"Skills ({len(card['skills'])}):")
    for skill in card['skills']:
        print(f"  • {skill['skill_id']}")
        print(f"    - {skill['description']}")
        print(f"    - Method: {skill['method']}")
        if skill.get('avg_processing_time_ms'):
            print(f"    - Avg Time: {skill['avg_processing_time_ms']}ms")
        print(f"    - Tags: {', '.join(skill['tags'])}")
        print()
    print()


async def find_agents_by_skill(cards: Dict[str, Dict[str, Any]], skill_id: str) -> List[str]:
    """Find all agents that have a specific skill"""
    agents = []
    for name, card in cards.items():
        for skill in card['skills']:
            if skill['skill_id'] == skill_id:
                agents.append(name)
                break
    return agents


async def get_all_skills(cards: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Get a mapping of all skills to agents that provide them"""
    skill_map = {}
    for name, card in cards.items():
        for skill in card['skills']:
            if skill['skill_id'] not in skill_map:
                skill_map[skill['skill_id']] = []
            skill_map[skill['skill_id']].append(name)
    return skill_map


async def main():
    """Main demonstration"""
    
    # Agent URLs (adjust ports if needed)
    agent_urls = [
        "http://localhost:8002",  # Extractor
        "http://localhost:8003",  # Validator
        "http://localhost:8004",  # Archivist
    ]
    
    # Discover all agents
    cards = await discover_all_agents(agent_urls)
    
    if not cards:
        print("No agents discovered. Make sure agents are running!")
        print("Start them with: python run_agents.py")
        return
    
    # Print details for each agent
    for name, card in cards.items():
        await print_agent_details(card)
    
    # Skill analysis
    print("=" * 80)
    print("SKILL ANALYSIS")
    print("=" * 80)
    print()
    
    skill_map = await get_all_skills(cards)
    print(f"Total unique skills: {len(skill_map)}")
    print()
    
    print("Skills by Agent:")
    for skill_id, agents in sorted(skill_map.items()):
        print(f"  • {skill_id}")
        print(f"    Provided by: {', '.join(agents)}")
    print()
    
    # Example: Find agents for specific skills
    print("=" * 80)
    print("SKILL-BASED DISCOVERY")
    print("=" * 80)
    print()
    
    test_skills = ['extract_document', 'validate_document', 'archive_document']
    for skill in test_skills:
        agents = await find_agents_by_skill(cards, skill)
        if agents:
            print(f"Skill '{skill}' is provided by: {', '.join(agents)}")
        else:
            print(f"Skill '{skill}' not found in any agent")
    print()
    
    # Summary statistics
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print(f"Total Agents Discovered: {len(cards)}")
    print(f"Total Skills Available: {len(skill_map)}")
    print(f"Average Skills per Agent: {sum(len(card['skills']) for card in cards.values()) / len(cards):.1f}")
    print()
    
    # Check orchestrator registry (if available)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:8001/message",
                json={
                    "jsonrpc": "2.0",
                    "id": "1",
                    "method": "get_agent_registry",
                    "params": {}
                },
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if 'result' in result:
                        registry = result['result']
                        print("=" * 80)
                        print("ORCHESTRATOR REGISTRY")
                        print("=" * 80)
                        print()
                        print(f"Active Agents: {registry.get('active_agents', 0)}")
                        print(f"Total Skills: {registry.get('total_skills', 0)}")
                        print(f"Available Skills: {', '.join(registry.get('available_skills', [])[:5])}...")
                        print()
    except Exception as e:
        print(f"Note: Could not reach orchestrator at http://localhost:8001")
        print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nDiscovery interrupted by user")
    except Exception as e:
        print(f"\nError: {str(e)}")
