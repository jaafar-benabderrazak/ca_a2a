"""
Script to run all agents simultaneously
"""
import asyncio
import logging
import sys

from orchestrator_agent import OrchestratorAgent
from extractor_agent import ExtractorAgent
from validator_agent import ValidatorAgent
from archivist_agent import ArchivistAgent


async def run_all_agents():
    """Start all agents concurrently"""
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('agents.log')
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting all agents...")
    
    # Initialize agents
    orchestrator = OrchestratorAgent()
    extractor = ExtractorAgent()
    validator = ValidatorAgent()
    archivist = ArchivistAgent()
    
    # Start all agents concurrently
    try:
        await asyncio.gather(
            orchestrator.run(),
            extractor.run(),
            validator.run(),
            archivist.run()
        )
    except KeyboardInterrupt:
        logger.info("Received shutdown signal, stopping all agents...")
    except Exception as e:
        logger.error(f"Error running agents: {str(e)}")
        raise


if __name__ == '__main__':
    try:
        asyncio.run(run_all_agents())
    except KeyboardInterrupt:
        print("\nShutdown complete")

