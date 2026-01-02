"""
Extractor Agent
Extracts structured data from PDF and CSV documents from S3
"""
import io
import asyncio
from typing import Dict, Any, List
from datetime import datetime
import csv
import math

import PyPDF2
import pdfplumber
import pandas as pd

from base_agent import BaseAgent
from a2a_protocol import ErrorCodes
from mcp_context_auto import get_mcp_context
from config import AGENTS_CONFIG
from agent_card import AgentSkill, ResourceRequirements, AgentDependencies


class ExtractorAgent(BaseAgent):
    """
    Extractor agent that reads documents from S3 and extracts structured data:
    - PDF: Extracts text, tables, and metadata
    - CSV: Parses structured data with type inference
    """
    
    def __init__(self):
        config = AGENTS_CONFIG['extractor']
        super().__init__(
            'Extractor',
            config['host'],
            config['port'],
            version='1.0.0',
            description='Extracts structured data from PDF and CSV documents stored in S3'
        )
        
        self.mcp: MCPContext = None
        self.supported_formats = ['.pdf', '.csv']
        
        # Set resource requirements and dependencies
        if self.agent_card:
            self.agent_card.resources = ResourceRequirements(
                memory_mb=1024,
                cpu_cores=1.0,
                storage_required=False,
                network_required=True
            )
            self.agent_card.dependencies = AgentDependencies(
                services=['s3'],
                libraries=['PyPDF2', 'pdfplumber', 'pandas']
            )
            self.agent_card.tags = ['extraction', 'pdf', 'csv', 's3', 'document-processing']
    
    def _register_handlers(self):
        """Register message handlers"""
        self.protocol.register_handler('extract_document', self.handle_extract_document)
        self.protocol.register_handler('list_supported_formats', self.handle_list_supported_formats)
    
    def _define_skills(self):
        """Define extractor agent skills"""
        return [
            AgentSkill(
                skill_id='extract_document',
                name='Document Extraction',
                description='Extract structured data from PDF or CSV files stored in S3',
                method='extract_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {
                            'type': 'string',
                            'description': 'S3 key path to the document'
                        }
                    }
                },
                output_schema={
                    'type': 'object',
                    'properties': {
                        's3_key': {'type': 'string'},
                        'document_type': {'type': 'string', 'enum': ['pdf', 'csv']},
                        'file_name': {'type': 'string'},
                        'file_size': {'type': 'integer'},
                        'extracted_data': {'type': 'object'},
                        'metadata': {'type': 'object'},
                        'extraction_status': {'type': 'string'}
                    }
                },
                tags=['extraction', 'pdf', 'csv', 's3', 'core'],
                avg_processing_time_ms=2500,
                max_input_size_mb=50
            ),
            AgentSkill(
                skill_id='pdf_text_extraction',
                name='PDF Text Extraction',
                description='Extract text content from PDF documents',
                method='extract_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {
                            'type': 'string',
                            'pattern': '.*\\.pdf$',
                            'description': 'S3 key to PDF document'
                        }
                    }
                },
                tags=['pdf', 'text', 'extraction'],
                avg_processing_time_ms=2000,
                max_input_size_mb=50
            ),
            AgentSkill(
                skill_id='pdf_table_extraction',
                name='PDF Table Extraction',
                description='Extract tables from PDF documents',
                method='extract_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {
                            'type': 'string',
                            'pattern': '.*\\.pdf$'
                        }
                    }
                },
                tags=['pdf', 'tables', 'extraction', 'structured-data'],
                avg_processing_time_ms=3000,
                max_input_size_mb=50
            ),
            AgentSkill(
                skill_id='csv_parsing',
                name='CSV Data Parsing',
                description='Parse CSV files with type inference and statistics',
                method='extract_document',
                input_schema={
                    'type': 'object',
                    'required': ['s3_key'],
                    'properties': {
                        's3_key': {
                            'type': 'string',
                            'pattern': '.*\\.csv$'
                        }
                    }
                },
                tags=['csv', 'parsing', 'structured-data', 'statistics'],
                avg_processing_time_ms=1500,
                max_input_size_mb=100
            ),
            AgentSkill(
                skill_id='list_supported_formats',
                name='List Supported Document Formats',
                description='Get list of all supported document formats and their capabilities',
                method='list_supported_formats',
                input_schema={'type': 'object'},
                output_schema={
                    'type': 'object',
                    'properties': {
                        'supported_formats': {
                            'type': 'array',
                            'items': {'type': 'string'}
                        },
                        'format_descriptions': {'type': 'object'}
                    }
                },
                tags=['metadata', 'discovery', 'formats'],
                avg_processing_time_ms=10
            )
        ]
    
    async def initialize(self):
        """Initialize MCP context"""
        self.mcp = get_mcp_context()
        await self.mcp.__aenter__()
        self.logger.info("Extractor initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.mcp:
            await self.mcp.__aexit__(None, None, None)
        self.logger.info("Extractor cleanup completed")
    
    async def handle_extract_document(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract data from a document
        Params: {
            "s3_key": "path/to/document.pdf"
        }
        """
        s3_key = params.get('s3_key')
        if not s3_key:
            raise ValueError("Missing required parameter: s3_key")
        
        self.logger.info(f"Extracting document: {s3_key}")
        
        # Determine document type
        document_type = self._get_document_type(s3_key)
        
        if document_type not in ['pdf', 'csv']:
            raise ValueError(f"Unsupported document type: {document_type}")
        
        # Download document from S3
        try:
            document_data = await self.mcp.s3.get_object(s3_key)
            metadata = await self.mcp.s3.get_object_metadata(s3_key)
        except Exception as e:
            self.logger.error(f"Failed to download document from S3: {str(e)}")
            raise Exception(f"S3 download error: {str(e)}")
        
        # Extract data based on document type
        try:
            if document_type == 'pdf':
                extracted_data = await self._extract_pdf(document_data)
            elif document_type == 'csv':
                extracted_data = await self._extract_csv(document_data)
            else:
                raise ValueError(f"Unsupported document type: {document_type}")

            # Ensure JSON-safe payloads (no NaN/Infinity for JSON/JSONB)
            extracted_data = self._sanitize_for_json(extracted_data)
            
            # Prepare result
            result = {
                's3_key': s3_key,
                'document_type': document_type,
                'file_name': s3_key.split('/')[-1],
                'file_size': len(document_data),
                'extracted_data': extracted_data,
                'metadata': {
                    'content_type': metadata.get('content_type'),
                    'extraction_timestamp': datetime.now().isoformat(),
                    's3_last_modified': metadata.get('last_modified')
                },
                'extraction_status': 'success'
            }
            
            self.logger.info(f"Successfully extracted document: {s3_key}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to extract document: {str(e)}")
            raise Exception(f"Extraction error: {str(e)}")

    def _sanitize_for_json(self, obj: Any) -> Any:
        """
        Convert values to JSON-safe types:
        - Replace NaN/Infinity with None (JSON/JSONB do not accept NaN tokens)
        - Recurse through dicts/lists
        """
        if obj is None:
            return None

        # Handle floats (including numpy floats) with NaN/Inf
        if isinstance(obj, (float, int)):
            if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
                return None
            return obj

        # Recurse for common containers
        if isinstance(obj, dict):
            return {k: self._sanitize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._sanitize_for_json(v) for v in obj]

        return obj
    
    async def handle_list_supported_formats(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List supported document formats"""
        return {
            'supported_formats': self.supported_formats,
            'format_descriptions': {
                '.pdf': 'PDF documents (text and table extraction)',
                '.csv': 'CSV files (structured data with type inference)'
            }
        }
    
    def _get_document_type(self, filename: str) -> str:
        """Determine document type from filename"""
        filename_lower = filename.lower()
        if filename_lower.endswith('.pdf'):
            return 'pdf'
        elif filename_lower.endswith('.csv'):
            return 'csv'
        else:
            return 'unknown'
    
    async def _extract_pdf(self, pdf_data: bytes) -> Dict[str, Any]:
        """
        Extract text, tables, and metadata from PDF with robust error handling
        """
        pdf_file = io.BytesIO(pdf_data)
        extracted = {
            'pages': [],
            'tables': [],
            'metadata': {},
            'total_pages': 0,
            'text_content': ''
        }
        
        try:
            # Extract metadata and text using PyPDF2 with strict=False for lenient parsing
            try:
                pdf_reader = PyPDF2.PdfReader(pdf_file, strict=False)
            except Exception as pypdf_error:
                # Fallback: Try with pdfplumber only if PyPDF2 fails
                self.logger.warning(f"PyPDF2 failed, using pdfplumber only: {str(pypdf_error)}")
                return await self._extract_pdf_fallback(pdf_data)
            
            try:
                extracted['total_pages'] = len(pdf_reader.pages)
            except Exception as e:
                self.logger.warning(f"Could not get page count: {str(e)}")
                extracted['total_pages'] = 0
            
            # Extract metadata safely
            try:
                if pdf_reader.metadata:
                extracted['metadata'] = {
                        'title': str(pdf_reader.metadata.get('/Title', '')),
                        'author': str(pdf_reader.metadata.get('/Author', '')),
                        'subject': str(pdf_reader.metadata.get('/Subject', '')),
                        'creator': str(pdf_reader.metadata.get('/Creator', '')),
                        'producer': str(pdf_reader.metadata.get('/Producer', '')),
                    'creation_date': str(pdf_reader.metadata.get('/CreationDate', ''))
                }
            except Exception as e:
                self.logger.warning(f"Could not extract PDF metadata: {str(e)}")
                extracted['metadata'] = {'extraction_note': 'Metadata extraction failed'}
            
            # Extract text from each page with error handling
            for page_num, page in enumerate(pdf_reader.pages):
                try:
                    text = page.extract_text() or ""
                extracted['pages'].append({
                    'page_number': page_num + 1,
                    'text': text,
                    'char_count': len(text)
                })
                extracted['text_content'] += text + '\n'
                except Exception as e:
                    self.logger.warning(f"Could not extract text from page {page_num + 1}: {str(e)}")
                    extracted['pages'].append({
                        'page_number': page_num + 1,
                        'text': '',
                        'char_count': 0,
                        'extraction_error': str(e)
                    })
            
            # Extract tables using pdfplumber
            pdf_file.seek(0)  # Reset file pointer
            try:
                with pdfplumber.open(pdf_file) as pdf:
                    for page_num, page in enumerate(pdf.pages):
                        try:
                            tables = page.extract_tables()
                            if tables:
                                for table_idx, table in enumerate(tables):
                                    if table and len(table) > 0:
                                        # Convert table to structured format
                                        headers = table[0] if table[0] else [f"Column_{i}" for i in range(len(table[0]) if table[0] else 0)]
                                        rows = table[1:] if len(table) > 1 else []
                                        
                                        extracted['tables'].append({
                                            'page': page_num + 1,
                                            'table_index': table_idx,
                                            'headers': headers,
                                            'rows': rows,
                                            'row_count': len(rows),
                                            'column_count': len(headers)
                                        })
                        except Exception as table_error:
                            self.logger.warning(f"Could not extract tables from page {page_num + 1}: {str(table_error)}")
            except Exception as pdfplumber_error:
                self.logger.warning(f"pdfplumber extraction failed: {str(pdfplumber_error)}")
            
            self.logger.info(f"PDF extraction completed: {extracted['total_pages']} pages, {len(extracted['tables'])} tables")
            return extracted
            
        except Exception as e:
            self.logger.error(f"PDF extraction failed: {str(e)}")
            # Try fallback method
            try:
                self.logger.info("Attempting fallback PDF extraction...")
                return await self._extract_pdf_fallback(pdf_data)
            except Exception as fallback_error:
                self.logger.error(f"Fallback extraction also failed: {str(fallback_error)}")
                raise Exception(f"PDF extraction error: {str(e)}")
    
    async def _extract_pdf_fallback(self, pdf_data: bytes) -> Dict[str, Any]:
        """
        Fallback PDF extraction using pdfplumber only (more lenient)
        """
        pdf_file = io.BytesIO(pdf_data)
        extracted = {
            'pages': [],
            'tables': [],
            'metadata': {'extraction_method': 'fallback_pdfplumber'},
            'total_pages': 0,
            'text_content': ''
        }
        
        try:
            with pdfplumber.open(pdf_file) as pdf:
                extracted['total_pages'] = len(pdf.pages)
                
                for page_num, page in enumerate(pdf.pages):
                    text = page.extract_text() or ""
                    extracted['pages'].append({
                        'page_number': page_num + 1,
                        'text': text,
                        'char_count': len(text)
                    })
                    extracted['text_content'] += text + '\n'
                    
                    # Extract tables
                    tables = page.extract_tables()
                    if tables:
                        for table_idx, table in enumerate(tables):
                            if table and len(table) > 0:
                                headers = table[0] if table[0] else [f"Column_{i}" for i in range(len(table[0]) if table[0] else 0)]
                                rows = table[1:] if len(table) > 1 else []
                                
                                extracted['tables'].append({
                                    'page': page_num + 1,
                                    'table_index': table_idx,
                                    'headers': headers,
                                    'rows': rows,
                                    'row_count': len(rows),
                                    'column_count': len(headers)
                                })
            
            self.logger.info(f"Fallback PDF extraction succeeded: {extracted['total_pages']} pages")
            return extracted
            
        except Exception as e:
            self.logger.error(f"Fallback PDF extraction failed: {str(e)}")
            raise Exception(f"Fallback PDF extraction error: {str(e)}")
    
    async def _extract_csv(self, csv_data: bytes) -> Dict[str, Any]:
        """
        Extract structured data from CSV file
        """
        try:
            # Try reading with pandas for better type inference
            csv_file = io.BytesIO(csv_data)
            
            # Detect encoding
            try:
                df = pd.read_csv(csv_file, encoding='utf-8')
            except UnicodeDecodeError:
                csv_file.seek(0)
                df = pd.read_csv(csv_file, encoding='latin-1')
            
            extracted = {
                'row_count': len(df),
                'column_count': len(df.columns),
                'columns': df.columns.tolist(),
                'column_types': {col: str(dtype) for col, dtype in df.dtypes.items()},
                'data': df.to_dict('records'),
                'summary_statistics': {}
            }
            
            # Generate summary statistics for numeric columns
            numeric_cols = df.select_dtypes(include=['number']).columns
            for col in numeric_cols:
                extracted['summary_statistics'][col] = {
                    'mean': float(df[col].mean()) if not df[col].isna().all() else None,
                    'median': float(df[col].median()) if not df[col].isna().all() else None,
                    'min': float(df[col].min()) if not df[col].isna().all() else None,
                    'max': float(df[col].max()) if not df[col].isna().all() else None,
                    'std': float(df[col].std()) if not df[col].isna().all() else None,
                    'missing_count': int(df[col].isna().sum())
                }
            
            # Count missing values per column
            extracted['missing_values'] = {col: int(df[col].isna().sum()) for col in df.columns}
            
            self.logger.info(f"CSV extraction completed: {extracted['row_count']} rows, {extracted['column_count']} columns")
            return extracted
            
        except Exception as e:
            self.logger.error(f"CSV extraction failed: {str(e)}")
            
            # Fallback to basic CSV parsing
            try:
                csv_file = io.BytesIO(csv_data)
                csv_text = csv_file.read().decode('utf-8')
                csv_file = io.StringIO(csv_text)
                
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                
                extracted = {
                    'row_count': len(rows),
                    'column_count': len(reader.fieldnames) if reader.fieldnames else 0,
                    'columns': list(reader.fieldnames) if reader.fieldnames else [],
                    'data': rows,
                    'column_types': {},
                    'summary_statistics': {},
                    'missing_values': {},
                    'extraction_method': 'fallback'
                }
                
                self.logger.info(f"CSV extraction (fallback) completed: {extracted['row_count']} rows")
                return extracted
                
            except Exception as fallback_error:
                self.logger.error(f"CSV fallback extraction failed: {str(fallback_error)}")
                raise Exception(f"CSV extraction error: {str(e)}, fallback also failed: {str(fallback_error)}")
    
    async def _get_agent_status(self) -> Dict[str, Any]:
        """Get extractor status"""
        status = await super()._get_agent_status()
        status.update({
            'supported_formats': self.supported_formats
        })
        return status
    
    async def _check_dependencies(self) -> Dict[str, Dict[str, Any]]:
        """Check S3 health"""
        dependencies = {}
        
        try:
            # Test S3 connection by listing (with empty prefix, limit 1)
            await self.mcp.s3.list_objects(prefix="", suffix="")
            dependencies['s3'] = {
                'healthy': True,
                'bucket': self.mcp.s3.bucket_name
            }
        except Exception as e:
            dependencies['s3'] = {
                'healthy': False,
                'error': str(e)
            }
        
        return dependencies


async def main():
    """Run the Extractor agent"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    agent = ExtractorAgent()
    await agent.run()


if __name__ == '__main__':
    asyncio.run(main())

