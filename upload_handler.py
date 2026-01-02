"""
Upload Handler for Multipart File Upload
Handles file uploads via ALB with MCP integration
"""
import logging
import uuid
import mimetypes
from typing import Dict, Any, Optional, Tuple
from aiohttp import web, multipart
from datetime import datetime
import base64

logger = logging.getLogger(__name__)


class UploadHandler:
    """
    Handles multipart/form-data file uploads
    Integrates with MCP for S3 storage
    """
    
    def __init__(self, mcp_context, max_file_size: int = 100 * 1024 * 1024):  # 100 MB default
        """
        Args:
            mcp_context: MCP context for S3 operations
            max_file_size: Maximum file size in bytes (default 100 MB)
        """
        self.mcp = mcp_context
        self.max_file_size = max_file_size
        self.logger = logging.getLogger(f"{__name__}.UploadHandler")
    
    async def handle_upload(
        self,
        request: web.Request,
        default_folder: str = "uploads"
    ) -> Dict[str, Any]:
        """
        Handle multipart file upload
        
        Args:
            request: aiohttp Request object
            default_folder: Default S3 folder if not specified
        
        Returns:
            Dict with upload result
        
        Raises:
            ValueError: If validation fails
            Exception: If upload fails
        """
        
        self.logger.info("Processing file upload request")
        
        # Parse multipart data
        reader = await request.multipart()
        
        file_data = None
        file_name = None
        file_size = 0
        content_type = None
        metadata = {}
        folder = default_folder
        
        # Read all parts
        async for part in reader:
            if part.name == 'file':
                # File part
                file_name = part.filename
                content_type = part.headers.get('Content-Type', 'application/octet-stream')
                
                # Read file data with size limit
                chunks = []
                async for chunk in part:
                    file_size += len(chunk)
                    if file_size > self.max_file_size:
                        raise ValueError(
                            f"File size exceeds maximum allowed size of {self.max_file_size} bytes"
                        )
                    chunks.append(chunk)
                
                file_data = b''.join(chunks)
                
            elif part.name == 'folder':
                # Optional folder override
                folder = await part.text()
                
            elif part.name == 'metadata':
                # Optional metadata JSON
                metadata_text = await part.text()
                try:
                    import json
                    metadata = json.loads(metadata_text)
                except json.JSONDecodeError:
                    self.logger.warning(f"Invalid metadata JSON: {metadata_text}")
        
        # Validate we have a file
        if not file_data or not file_name:
            raise ValueError("No file provided in request")
        
        # Generate S3 key
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        file_ext = self._get_file_extension(file_name)
        safe_filename = self._sanitize_filename(file_name)
        unique_id = str(uuid.uuid4())[:8]
        
        s3_key = f"{folder}/{timestamp}_{unique_id}_{safe_filename}"
        
        # Add metadata
        upload_metadata = {
            'original_filename': file_name,
            'content_type': content_type,
            'file_size': str(file_size),
            'upload_timestamp': datetime.utcnow().isoformat(),
            **metadata  # Merge custom metadata
        }
        
        # Upload to S3 via MCP
        self.logger.info(f"Uploading to S3: {s3_key} ({file_size} bytes)")
        
        try:
            # Convert bytes to base64 for MCP transport
            file_content_b64 = base64.b64encode(file_data).decode('utf-8')
            
            result = await self.mcp.s3.put_object(
                key=s3_key,
                content=file_content_b64,
                content_type=content_type,
                metadata=upload_metadata
            )
            
            self.logger.info(f"Upload successful: {s3_key}")
            
            return {
                'success': True,
                's3_key': s3_key,
                'file_name': file_name,
                'file_size': file_size,
                'content_type': content_type,
                'upload_id': unique_id,
                'timestamp': datetime.utcnow().isoformat(),
                'metadata': upload_metadata
            }
            
        except Exception as e:
            self.logger.error(f"Upload failed: {str(e)}")
            raise Exception(f"S3 upload error: {str(e)}")
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and special characters
        """
        import re
        # Remove path separators
        filename = filename.replace('/', '_').replace('\\', '_')
        # Remove special characters except dots, underscores, and hyphens
        filename = re.sub(r'[^\w\s.-]', '', filename)
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        # Limit length
        if len(filename) > 200:
            name, ext = self._split_filename(filename)
            filename = name[:190] + ext
        return filename or 'unnamed_file'
    
    def _split_filename(self, filename: str) -> Tuple[str, str]:
        """Split filename into name and extension"""
        if '.' in filename:
            parts = filename.rsplit('.', 1)
            return parts[0], '.' + parts[1]
        return filename, ''
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension"""
        _, ext = self._split_filename(filename)
        return ext.lower() if ext else ''
    
    def _validate_file_type(
        self,
        filename: str,
        allowed_extensions: Optional[list] = None
    ) -> bool:
        """
        Validate file type based on extension
        
        Args:
            filename: File name to validate
            allowed_extensions: List of allowed extensions (e.g., ['.pdf', '.csv'])
                               None means all extensions allowed
        
        Returns:
            True if valid, False otherwise
        """
        if allowed_extensions is None:
            return True
        
        ext = self._get_file_extension(filename)
        return ext in [e.lower() for e in allowed_extensions]


async def create_upload_handler(mcp_context, max_file_size: int = 100 * 1024 * 1024):
    """
    Factory function to create an UploadHandler
    
    Args:
        mcp_context: MCP context for S3 operations
        max_file_size: Maximum file size in bytes
    
    Returns:
        UploadHandler instance
    """
    return UploadHandler(mcp_context, max_file_size)

