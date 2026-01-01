"""
MCP Server Integration Tests
Tests all MCP server functionality including resources and tools
"""
import asyncio
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_client import MCPClient, MCPS3Client, MCPPostgreSQLClient, create_mcp_context

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class MCPServerTests:
    """Test suite for MCP server"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests_run = 0
    
    def assert_true(self, condition, message):
        """Assert that condition is true"""
        self.tests_run += 1
        if condition:
            self.passed += 1
            print(f"  [OK] {message}")
        else:
            self.failed += 1
            print(f"  [FAIL] {message}")
    
    def assert_equal(self, actual, expected, message):
        """Assert that actual equals expected"""
        self.tests_run += 1
        if actual == expected:
            self.passed += 1
            print(f"  [OK] {message}")
        else:
            self.failed += 1
            print(f"  [FAIL] {message} (expected: {expected}, got: {actual})")
    
    def assert_not_none(self, value, message):
        """Assert that value is not None"""
        self.tests_run += 1
        if value is not None:
            self.passed += 1
            print(f"  [OK] {message}")
        else:
            self.failed += 1
            print(f"  [FAIL] {message} (value was None)")
    
    def assert_greater(self, actual, minimum, message):
        """Assert that actual is greater than minimum"""
        self.tests_run += 1
        if actual > minimum:
            self.passed += 1
            print(f"  [OK] {message}")
        else:
            self.failed += 1
            print(f"  [FAIL] {message} (expected > {minimum}, got: {actual})")
    
    async def test_connection(self, client: MCPClient):
        """Test 1: Basic Connection"""
        print("\n[TEST 1] Connection to MCP Server")
        print("-" * 60)
        
        try:
            await client.connect()
            self.assert_true(client.session is not None, "Client session created")
            print("  Connected to MCP server successfully")
        except Exception as e:
            self.assert_true(False, f"Connection failed: {str(e)}")
    
    async def test_list_resources(self, client: MCPClient):
        """Test 2: List Resources"""
        print("\n[TEST 2] List Resources")
        print("-" * 60)
        
        try:
            resources = await client.list_resources()
            self.assert_not_none(resources, "Resources returned")
            self.assert_greater(len(resources), 0, "At least one resource available")
            
            # Check for S3 resource
            s3_resources = [r for r in resources if r['uri'].startswith('s3://')]
            self.assert_equal(len(s3_resources), 1, "S3 resource found")
            
            # Check for PostgreSQL resource
            pg_resources = [r for r in resources if r['uri'].startswith('postgres://')]
            self.assert_equal(len(pg_resources), 1, "PostgreSQL resource found")
            
            print(f"\n  Available resources:")
            for r in resources:
                print(f"    • {r['name']} ({r['uri']})")
        
        except Exception as e:
            self.assert_true(False, f"List resources failed: {str(e)}")
    
    async def test_list_tools(self, client: MCPClient):
        """Test 3: List Tools"""
        print("\n[TEST 3] List Tools")
        print("-" * 60)
        
        try:
            tools = await client.list_tools()
            self.assert_not_none(tools, "Tools returned")
            self.assert_equal(len(tools), 7, "All 7 tools available")
            
            tool_names = [t['name'] for t in tools]
            expected_tools = [
                's3_list_objects', 's3_get_object', 's3_put_object',
                'postgres_query', 'postgres_execute',
                'document_store', 'document_list'
            ]
            
            for tool_name in expected_tools:
                self.assert_true(tool_name in tool_names, f"Tool '{tool_name}' available")
            
            print(f"\n  Available tools:")
            for t in tools:
                print(f"    • {t['name']}: {t['description']}")
        
        except Exception as e:
            self.assert_true(False, f"List tools failed: {str(e)}")
    
    async def test_s3_list_objects(self, client: MCPClient):
        """Test 4: S3 List Objects Tool"""
        print("\n[TEST 4] S3 List Objects")
        print("-" * 60)
        
        try:
            result = await client.call_tool("s3_list_objects", {
                "prefix": "",
                "limit": 10
            })
            
            self.assert_not_none(result, "Result returned")
            self.assert_true('bucket' in result, "Result contains bucket")
            self.assert_true('count' in result, "Result contains count")
            self.assert_true('objects' in result, "Result contains objects")
            
            print(f"  Bucket: {result['bucket']}")
            print(f"  Objects found: {result['count']}")
            
            if result['count'] > 0:
                print(f"  First object: {result['objects'][0]['key']}")
        
        except Exception as e:
            self.assert_true(False, f"S3 list objects failed: {str(e)}")
    
    async def test_postgres_query(self, client: MCPClient):
        """Test 5: PostgreSQL Query Tool"""
        print("\n[TEST 5] PostgreSQL Query")
        print("-" * 60)
        
        try:
            # Query for document count
            result = await client.call_tool("postgres_query", {
                "query": "SELECT COUNT(*) as count FROM documents"
            })
            
            self.assert_not_none(result, "Result returned")
            self.assert_true('rows' in result, "Result contains rows")
            self.assert_equal(len(result['rows']), 1, "One row returned")
            
            count = result['rows'][0]['count']
            print(f"  Documents in database: {count}")
        
        except Exception as e:
            self.assert_true(False, f"PostgreSQL query failed: {str(e)}")
    
    async def test_document_list_tool(self, client: MCPClient):
        """Test 6: Document List Tool"""
        print("\n[TEST 6] Document List Tool")
        print("-" * 60)
        
        try:
            result = await client.call_tool("document_list", {
                "limit": 10
            })
            
            self.assert_not_none(result, "Result returned")
            self.assert_true('count' in result, "Result contains count")
            self.assert_true('documents' in result, "Result contains documents")
            
            print(f"  Documents found: {result['count']}")
            
            if result['count'] > 0:
                doc = result['documents'][0]
                print(f"  First document: {doc.get('file_name', 'N/A')} (status: {doc.get('status', 'N/A')})")
        
        except Exception as e:
            self.assert_true(False, f"Document list failed: {str(e)}")
    
    async def test_high_level_s3_client(self):
        """Test 7: High-Level S3 Client Interface"""
        print("\n[TEST 7] High-Level S3 Client")
        print("-" * 60)
        
        try:
            async with create_mcp_context() as mcp:
                # Test list_objects
                objects = await mcp.s3.list_objects(prefix="", limit=5)
                self.assert_not_none(objects, "Objects returned")
                self.assert_true(isinstance(objects, list), "Objects is a list")
                
                print(f"  Listed {len(objects)} objects")
                
                if len(objects) > 0:
                    # Test get_object_metadata
                    metadata = await mcp.s3.get_object_metadata(objects[0]['key'])
                    self.assert_not_none(metadata, "Metadata returned")
                    self.assert_true('content_type' in metadata, "Metadata contains content_type")
                    
                    print(f"  Got metadata for: {objects[0]['key']}")
        
        except Exception as e:
            self.assert_true(False, f"High-level S3 client failed: {str(e)}")
    
    async def test_high_level_postgres_client(self):
        """Test 8: High-Level PostgreSQL Client Interface"""
        print("\n[TEST 8] High-Level PostgreSQL Client")
        print("-" * 60)
        
        try:
            async with create_mcp_context() as mcp:
                # Test list_documents
                documents = await mcp.postgres.list_documents(limit=5)
                self.assert_not_none(documents, "Documents returned")
                self.assert_true(isinstance(documents, list), "Documents is a list")
                
                print(f"  Listed {len(documents)} documents")
                
                # Test fetch_value
                count = await mcp.postgres.fetch_value("SELECT COUNT(*) FROM documents")
                self.assert_not_none(count, "Count returned")
                
                print(f"  Total documents in database: {count}")
        
        except Exception as e:
            self.assert_true(False, f"High-level PostgreSQL client failed: {str(e)}")
    
    async def test_mcp_context_manager(self):
        """Test 9: MCP Context Manager"""
        print("\n[TEST 9] MCP Context Manager")
        print("-" * 60)
        
        try:
            async with create_mcp_context() as mcp:
                self.assert_not_none(mcp.s3, "S3 client available")
                self.assert_not_none(mcp.postgres, "PostgreSQL client available")
                self.assert_not_none(mcp.client, "MCP client available")
                
                print("  Context manager created successfully")
                print("  All clients available (s3, postgres)")
        
        except Exception as e:
            self.assert_true(False, f"Context manager failed: {str(e)}")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {self.tests_run}")
        print(f"Passed: {self.passed} ({100 * self.passed // self.tests_run if self.tests_run > 0 else 0}%)")
        print(f"Failed: {self.failed}")
        
        if self.failed == 0:
            print("\n✓ ALL TESTS PASSED")
            print("=" * 60)
            return True
        else:
            print(f"\n✗ {self.failed} TEST(S) FAILED")
            print("=" * 60)
            return False


async def run_all_tests():
    """Run all MCP server tests"""
    print("\n" + "=" * 60)
    print("MCP SERVER INTEGRATION TESTS")
    print("=" * 60)
    
    tests = MCPServerTests()
    client = MCPClient()
    
    try:
        # Tests with basic client
        await tests.test_connection(client)
        await tests.test_list_resources(client)
        await tests.test_list_tools(client)
        await tests.test_s3_list_objects(client)
        await tests.test_postgres_query(client)
        await tests.test_document_list_tool(client)
        
        await client.disconnect()
        
        # Tests with high-level clients
        await tests.test_high_level_s3_client()
        await tests.test_high_level_postgres_client()
        await tests.test_mcp_context_manager()
        
    except Exception as e:
        logger.error(f"Test suite error: {str(e)}")
        tests.failed += 1
    
    # Print summary
    success = tests.print_summary()
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(run_all_tests())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {str(e)}")
        sys.exit(1)

