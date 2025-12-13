"""
Client utility to interact with the document processing pipeline
"""
import asyncio
import aiohttp
import json
from typing import Dict, Any, Optional
import argparse

from config import AGENTS_CONFIG


class PipelineClient:
    """Client for interacting with the document processing pipeline"""
    
    def __init__(self):
        self.orchestrator_url = f"http://{AGENTS_CONFIG['orchestrator']['host']}:{AGENTS_CONFIG['orchestrator']['port']}"
    
    async def send_request(self, method: str, params: Dict[str, Any] = None) -> Any:
        """Send a request to the orchestrator"""
        message = {
            'jsonrpc': '2.0',
            'id': '1',
            'method': method,
            'params': params or {}
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.orchestrator_url}/message",
                json=message,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status != 200:
                    raise Exception(f"Request failed with status {response.status}")
                
                result = await response.json()
                
                if 'error' in result:
                    raise Exception(f"Error: {result['error']}")
                
                return result.get('result')
    
    async def process_document(self, s3_key: str, priority: str = 'normal') -> Dict[str, Any]:
        """Process a single document"""
        return await self.send_request('process_document', {
            's3_key': s3_key,
            'priority': priority
        })
    
    async def process_batch(self, prefix: str = '', file_extension: str = '') -> Dict[str, Any]:
        """Process a batch of documents"""
        return await self.send_request('process_batch', {
            'prefix': prefix,
            'file_extension': file_extension
        })
    
    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of a processing task"""
        return await self.send_request('get_task_status', {
            'task_id': task_id
        })
    
    async def list_pending_documents(self, limit: int = 50) -> Dict[str, Any]:
        """List pending documents"""
        return await self.send_request('list_pending_documents', {
            'limit': limit
        })
    
    async def check_health(self) -> Dict[str, Any]:
        """Check health of orchestrator"""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.orchestrator_url}/health") as response:
                return await response.json()
    
    async def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.orchestrator_url}/status") as response:
                return await response.json()


async def main():
    """CLI interface for the pipeline client"""
    parser = argparse.ArgumentParser(description='Document Processing Pipeline Client')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Process document command
    process_parser = subparsers.add_parser('process', help='Process a document')
    process_parser.add_argument('s3_key', help='S3 key of the document')
    process_parser.add_argument('--priority', default='normal', choices=['normal', 'high'], help='Processing priority')
    
    # Process batch command
    batch_parser = subparsers.add_parser('batch', help='Process a batch of documents')
    batch_parser.add_argument('--prefix', default='', help='S3 prefix filter')
    batch_parser.add_argument('--extension', default='', help='File extension filter (e.g., .pdf)')
    
    # Task status command
    status_parser = subparsers.add_parser('status', help='Get task status')
    status_parser.add_argument('task_id', help='Task ID')
    
    # List pending command
    list_parser = subparsers.add_parser('list', help='List pending documents')
    list_parser.add_argument('--limit', type=int, default=50, help='Maximum number of documents to list')
    
    # Health check command
    subparsers.add_parser('health', help='Check system health')
    
    # System status command
    subparsers.add_parser('info', help='Get system status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    client = PipelineClient()
    
    try:
        if args.command == 'process':
            result = await client.process_document(args.s3_key, args.priority)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'batch':
            result = await client.process_batch(args.prefix, args.extension)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'status':
            result = await client.get_task_status(args.task_id)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'list':
            result = await client.list_pending_documents(args.limit)
            print(json.dumps(result, indent=2))
        
        elif args.command == 'health':
            result = await client.check_health()
            print(json.dumps(result, indent=2))
        
        elif args.command == 'info':
            result = await client.get_status()
            print(json.dumps(result, indent=2))
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(asyncio.run(main()))

