"""
Example usage of the document processing pipeline
"""
import asyncio
from client import PipelineClient


async def example_single_document():
    """Example: Process a single document"""
    print("=== Example 1: Process Single Document ===\n")
    
    client = PipelineClient()
    
    # Check health
    print("Checking system health...")
    health = await client.check_health()
    print(f"System status: {health['status']}\n")
    
    # Process a document
    print("Processing document...")
    result = await client.process_document("documents/sample.pdf", priority="high")
    print(f"Task created: {result['task_id']}")
    print(f"Status: {result['status']}\n")
    
    # Wait a bit and check status
    await asyncio.sleep(5)
    
    print("Checking task status...")
    status = await client.get_task_status(result['task_id'])
    print(f"Current stage: {status.get('current_stage')}")
    print(f"Status: {status.get('status')}\n")
    
    return result['task_id']


async def example_batch_processing():
    """Example: Process multiple documents"""
    print("=== Example 2: Batch Processing ===\n")
    
    client = PipelineClient()
    
    # Process all PDFs in a folder
    print("Starting batch processing...")
    result = await client.process_batch(
        prefix="documents/2024/",
        file_extension=".pdf"
    )
    
    print(f"Batch ID: {result['batch_id']}")
    print(f"Total documents: {result['total_documents']}")
    print(f"Task IDs: {result['task_ids'][:3]}..." if len(result['task_ids']) > 3 else result['task_ids'])
    print()


async def example_monitoring():
    """Example: Monitor system status"""
    print("=== Example 3: System Monitoring ===\n")
    
    client = PipelineClient()
    
    # Get system status
    print("Getting system status...")
    status = await client.get_status()
    print(f"Active tasks: {status.get('active_tasks', 0)}")
    print(f"Completed tasks: {status.get('completed_tasks', 0)}")
    print(f"Failed tasks: {status.get('failed_tasks', 0)}")
    print()
    
    # List pending documents
    print("Listing pending documents...")
    pending = await client.list_pending_documents(limit=10)
    print(f"Pending documents: {pending['count']}")
    if pending['documents']:
        print("Recent documents:")
        for doc in pending['documents'][:3]:
            print(f"  - {doc['file_name']} ({doc['status']})")
    print()


async def example_direct_api_call():
    """Example: Direct A2A message to an agent"""
    print("=== Example 4: Direct API Call ===\n")
    
    import aiohttp
    
    # Call Validator to get validation rules
    message = {
        'jsonrpc': '2.0',
        'id': '1',
        'method': 'get_validation_rules',
        'params': {'document_type': 'pdf'}
    }
    
    validator_url = "http://localhost:8003/message"
    
    print("Getting validation rules from Validator agent...")
    async with aiohttp.ClientSession() as session:
        async with session.post(validator_url, json=message) as response:
            result = await response.json()
            
            if 'result' in result:
                print(f"Document type: {result['result']['document_type']}")
                print("Validation rules:")
                for rule in result['result']['rules']:
                    print(f"  - {rule['name']} (weight: {rule['weight']})")
            else:
                print(f"Error: {result.get('error')}")
    print()


async def example_error_handling():
    """Example: Error handling"""
    print("=== Example 5: Error Handling ===\n")
    
    client = PipelineClient()
    
    # Try to process non-existent document
    try:
        print("Attempting to process non-existent document...")
        result = await client.process_document("non/existent/file.pdf")
        print(f"Result: {result}")
    except Exception as e:
        print(f"Caught expected error: {str(e)}")
    
    print()
    
    # Try to get non-existent task
    try:
        print("Attempting to get non-existent task...")
        status = await client.get_task_status("invalid-task-id")
        print(f"Status: {status}")
    except Exception as e:
        print(f"Caught expected error: {str(e)}")
    
    print()


async def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("Document Processing Pipeline - Examples")
    print("="*60 + "\n")
    
    try:
        # Example 1: Single document
        await example_single_document()
        
        # Example 2: Batch processing
        await example_batch_processing()
        
        # Example 3: Monitoring
        await example_monitoring()
        
        # Example 4: Direct API call
        await example_direct_api_call()
        
        # Example 5: Error handling
        await example_error_handling()
        
        print("="*60)
        print("All examples completed!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\nError running examples: {str(e)}")
        print("Make sure all agents are running (python run_agents.py)")


if __name__ == '__main__':
    asyncio.run(main())

