"""
Admin API for Token Revocation and Security Management

Provides administrative endpoints for:
- Token revocation
- Listing revoked tokens
- Security auditing
- User management

Only accessible to users with admin permissions.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field

# Import security components
from a2a_security_enhanced import (
    TokenRevocationList,
    RevokedToken,
    A2ASecurityManager
)

logger = logging.getLogger(__name__)

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class RevokeTokenRequest(BaseModel):
    """Request to revoke a JWT token"""
    jti: str = Field(..., description="JWT ID (jti claim) to revoke")
    reason: str = Field(..., description="Reason for revocation")
    revoked_by: Optional[str] = Field(None, description="Admin username (auto-detected if not provided)")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time (optional)")


class RevokeTokenResponse(BaseModel):
    """Response after revoking a token"""
    success: bool
    message: str
    jti: str
    revoked_at: datetime


class RevokedTokenInfo(BaseModel):
    """Information about a revoked token"""
    jti: str
    revoked_at: datetime
    revoked_by: str
    reason: str
    expires_at: datetime


class ListRevokedTokensResponse(BaseModel):
    """List of revoked tokens"""
    tokens: List[RevokedTokenInfo]
    total: int
    limit: int


class SecurityStatsResponse(BaseModel):
    """Security statistics"""
    total_revoked_tokens: int
    active_revoked_tokens: int
    expired_revoked_tokens: int
    revocations_last_24h: int
    most_common_reasons: List[Dict[str, Any]]


# ============================================================================
# ADMIN API APPLICATION
# ============================================================================

class AdminAPI:
    """
    Admin API for security management.
    
    Requires admin authentication for all endpoints.
    """
    
    def __init__(self, security_manager: A2ASecurityManager, db_pool=None):
        self.app = FastAPI(
            title="CA-A2A Admin API",
            description="Administrative endpoints for security management",
            version="1.0.0"
        )
        self.security_manager = security_manager
        self.revocation_list = TokenRevocationList(db_pool=db_pool)
        
        # Register routes
        self._register_routes()
        
        logger.info("Admin API initialized")
    
    def _register_routes(self):
        """Register all admin API routes"""
        
        @self.app.post("/admin/revoke-token", response_model=RevokeTokenResponse)
        async def revoke_token(
            request: RevokeTokenRequest,
            authorization: Optional[str] = Header(None)
        ):
            """
            Revoke a JWT token.
            
            Requires admin authentication.
            """
            # Authenticate admin
            admin_principal = await self._authenticate_admin(authorization)
            
            # Use provided revoked_by or default to authenticated admin
            revoked_by = request.revoked_by or admin_principal
            
            # Revoke the token
            try:
                success = await self.revocation_list.revoke_token(
                    jti=request.jti,
                    reason=request.reason,
                    revoked_by=revoked_by,
                    expires_at=request.expires_at
                )
                
                if success:
                    logger.info(f"Token {request.jti} revoked by {revoked_by}: {request.reason}")
                    return RevokeTokenResponse(
                        success=True,
                        message="Token revoked successfully",
                        jti=request.jti,
                        revoked_at=datetime.utcnow()
                    )
                else:
                    raise HTTPException(status_code=500, detail="Failed to revoke token")
                    
            except Exception as e:
                logger.error(f"Error revoking token: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/admin/revoked-tokens", response_model=ListRevokedTokensResponse)
        async def list_revoked_tokens(
            limit: int = 100,
            authorization: Optional[str] = Header(None)
        ):
            """
            List currently revoked tokens.
            
            Requires admin authentication.
            """
            # Authenticate admin
            await self._authenticate_admin(authorization)
            
            try:
                tokens = await self.revocation_list.get_revoked_tokens(limit=limit)
                
                return ListRevokedTokensResponse(
                    tokens=[
                        RevokedTokenInfo(
                            jti=t.jti,
                            revoked_at=t.revoked_at,
                            revoked_by=t.revoked_by,
                            reason=t.reason,
                            expires_at=t.expires_at
                        )
                        for t in tokens
                    ],
                    total=len(tokens),
                    limit=limit
                )
            except Exception as e:
                logger.error(f"Error listing revoked tokens: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/admin/security-stats", response_model=SecurityStatsResponse)
        async def get_security_stats(
            authorization: Optional[str] = Header(None)
        ):
            """
            Get security statistics.
            
            Requires admin authentication.
            """
            # Authenticate admin
            await self._authenticate_admin(authorization)
            
            try:
                tokens = await self.revocation_list.get_revoked_tokens(limit=10000)
                
                now = datetime.utcnow()
                active = [t for t in tokens if t.expires_at > now]
                expired = [t for t in tokens if t.expires_at <= now]
                last_24h = [t for t in tokens if (now - t.revoked_at).total_seconds() < 86400]
                
                # Count reasons
                reason_counts = {}
                for token in tokens:
                    reason = token.reason or "Unknown"
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
                
                most_common = sorted(
                    [{"reason": k, "count": v} for k, v in reason_counts.items()],
                    key=lambda x: x["count"],
                    reverse=True
                )[:5]
                
                return SecurityStatsResponse(
                    total_revoked_tokens=len(tokens),
                    active_revoked_tokens=len(active),
                    expired_revoked_tokens=len(expired),
                    revocations_last_24h=len(last_24h),
                    most_common_reasons=most_common
                )
            except Exception as e:
                logger.error(f"Error getting security stats: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.delete("/admin/cleanup-expired-tokens")
        async def cleanup_expired_tokens(
            authorization: Optional[str] = Header(None)
        ):
            """
            Manually trigger cleanup of expired revoked tokens.
            
            Requires admin authentication.
            """
            # Authenticate admin
            await self._authenticate_admin(authorization)
            
            try:
                # Force cleanup
                self.revocation_list._cleanup_expired()
                
                return {
                    "success": True,
                    "message": "Expired tokens cleaned up"
                }
            except Exception as e:
                logger.error(f"Error cleaning up expired tokens: {e}")
                raise HTTPException(status_code=500, detail=str(e))
    
    async def _authenticate_admin(self, authorization: Optional[str]) -> str:
        """
        Authenticate admin user from Authorization header.
        
        Returns admin principal if authentication succeeds.
        Raises HTTPException if authentication fails.
        """
        if not authorization:
            raise HTTPException(
                status_code=401,
                detail="Missing Authorization header"
            )
        
        try:
            # Parse Bearer token
            if not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Authorization header format"
                )
            
            token = authorization.split(" ", 1)[1]
            
            # Verify token and check admin permissions
            principal, auth_context = await self.security_manager.authenticate(
                headers={"Authorization": authorization},
                method="admin_api",
                message_dict={}
            )
            
            # Check if user has admin role
            if not self._is_admin(principal, auth_context):
                raise HTTPException(
                    status_code=403,
                    detail="Admin permissions required"
                )
            
            return principal
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Admin authentication error: {e}")
            raise HTTPException(
                status_code=401,
                detail=f"Authentication failed: {str(e)}"
            )
    
    def _is_admin(self, principal: str, auth_context: Dict) -> bool:
        """
        Check if principal has admin permissions.
        
        Admin can be:
        - Principal with "admin" role in Keycloak
        - Principal with "*" permissions
        - Configured admin principals
        """
        # Check Keycloak roles
        if auth_context.get("keycloak_roles"):
            if "admin" in auth_context["keycloak_roles"]:
                return True
        
        # Check RBAC permissions
        if auth_context.get("permissions"):
            if "*" in auth_context["permissions"]:
                return True
        
        # Check configured admin list
        admins = self.security_manager.config.get("admin_principals", [])
        if principal in admins:
            return True
        
        return False


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

async def example_usage():
    """Example of how to use the Admin API"""
    import asyncpg
    
    # Initialize database pool
    db_pool = await asyncpg.create_pool(
        host="localhost",
        port=5432,
        user="postgres",
        password="password",
        database="documents"
    )
    
    # Initialize security manager
    security_manager = A2ASecurityManager(agent_id="admin-api")
    
    # Create Admin API
    admin_api = AdminAPI(security_manager=security_manager, db_pool=db_pool)
    
    # Run with uvicorn
    import uvicorn
    uvicorn.run(admin_api.app, host="0.0.0.0", port=9000)


if __name__ == "__main__":
    asyncio.run(example_usage())

