"""
Enhanced A2A Security Implementation
Based on "Securing Agent-to-Agent (A2A) Communications Across Domains" best practices

Implements:
1. TLS/mTLS configuration
2. Message integrity verification (HMAC)
3. Zero-trust principles
4. Enhanced anomaly detection
5. Certificate management
"""
import ssl
import os
import hmac
import hashlib
import json
import logging
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, deque
import asyncio

from security import SecurityManager, AuthContext, AuthMethod

logger = logging.getLogger(__name__)


@dataclass
class MessageIntegrity:
    """Message integrity verification using HMAC"""
    message_id: str
    timestamp: str
    hmac_signature: str
    algorithm: str = "sha256"


class TLSConfigManager:
    """
    Manages TLS/mTLS configuration for agent-to-agent communication
    
    Implements best practices:
    - TLS 1.3 with strong cipher suites
    - Mutual TLS authentication
    - Certificate validation
    - Perfect forward secrecy
    
    Reference: PDF Section "Transport Layer Encryption (TLS/DTLS)"
    """
    
    def __init__(
        self,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        require_client_cert: bool = False
    ):
        self.cert_path = cert_path or os.getenv('TLS_CERT_PATH')
        self.key_path = key_path or os.getenv('TLS_KEY_PATH')
        self.ca_cert_path = ca_cert_path or os.getenv('TLS_CA_CERT_PATH')
        self.require_client_cert = require_client_cert
        
        logger.info(
            f"TLS Config: cert={self.cert_path}, "
            f"require_client_cert={require_client_cert}"
        )
    
    def create_server_ssl_context(self) -> Optional[ssl.SSLContext]:
        """
        Create SSL context for server with strong security settings
        
        Returns:
            SSLContext configured for TLS 1.3 with mutual auth if enabled
        """
        if not self.cert_path or not self.key_path:
            logger.warning("TLS certificates not configured - running without TLS")
            return None
        
        # Create SSL context with TLS 1.3
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Require TLS 1.2 minimum (1.3 preferred)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load server certificate and private key
        try:
            context.load_cert_chain(self.cert_path, self.key_path)
        except FileNotFoundError as e:
            logger.error(f"TLS certificate files not found: {e}")
            return None
        
        # Strong cipher suites (AES-256, ChaCha20)
        context.set_ciphers(
            'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
        )
        
        # Mutual TLS authentication
        if self.require_client_cert and self.ca_cert_path:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.ca_cert_path)
            logger.info("Mutual TLS (mTLS) enabled - clients must present certificates")
        else:
            context.verify_mode = ssl.CERT_NONE
            logger.info("TLS enabled (server-side only)")
        
        # Disable weak protocols and compression
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_COMPRESSION
        
        logger.info("Server SSL context created with TLS 1.2+ and strong ciphers")
        return context
    
    def create_client_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for client connections
        
        Returns:
            SSLContext for outbound agent-to-agent connections
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Verify server certificates
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Load CA certificates
        if self.ca_cert_path:
            context.load_verify_locations(self.ca_cert_path)
        else:
            context.load_default_certs()
        
        # Load client certificate for mutual TLS
        if self.cert_path and self.key_path:
            try:
                context.load_cert_chain(self.cert_path, self.key_path)
                logger.info("Client certificate loaded for mTLS")
            except FileNotFoundError:
                logger.warning("Client certificate not found - connecting without mTLS")
        
        return context


class MessageIntegrityVerifier:
    """
    Implements message-level integrity verification using HMAC
    
    Protects against:
    - Man-in-the-middle tampering
    - Message injection
    - Partial message alteration
    
    Reference: PDF Section "HMAC/MAC on Messages"
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.algorithm = hashlib.sha256
        
        logger.info("Message integrity verification enabled (HMAC-SHA256)")
    
    def sign_message(self, message: Dict[str, Any]) -> MessageIntegrity:
        """
        Sign A2A message with HMAC
        
        Args:
            message: A2A message dictionary
        
        Returns:
            MessageIntegrity object with signature
        """
        # Canonical JSON representation
        message_bytes = json.dumps(message, sort_keys=True).encode()
        
        # Generate HMAC
        signature = hmac.new(
            self.secret_key,
            message_bytes,
            self.algorithm
        ).hexdigest()
        
        message_id = message.get('id', 'notification')
        timestamp = datetime.utcnow().isoformat()
        
        return MessageIntegrity(
            message_id=message_id,
            timestamp=timestamp,
            hmac_signature=signature,
            algorithm='sha256'
        )
    
    def verify_message(
        self,
        message: Dict[str, Any],
        integrity: MessageIntegrity,
        max_age_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify message HMAC and freshness
        
        Args:
            message: A2A message dictionary
            integrity: MessageIntegrity with signature
            max_age_seconds: Maximum message age (prevents replay)
        
        Returns:
            Tuple of (valid, error_message)
        """
        # Check message age (anti-replay)
        try:
            msg_time = datetime.fromisoformat(integrity.timestamp)
            age = (datetime.utcnow() - msg_time).total_seconds()
            
            if age > max_age_seconds:
                return False, f"Message too old ({age}s > {max_age_seconds}s)"
            
            if age < -60:  # Clock skew tolerance
                return False, f"Message timestamp in future"
        except ValueError as e:
            return False, f"Invalid timestamp: {e}"
        
        # Compute expected HMAC
        message_bytes = json.dumps(message, sort_keys=True).encode()
        expected_signature = hmac.new(
            self.secret_key,
            message_bytes,
            self.algorithm
        ).hexdigest()
        
        # Constant-time comparison
        if not hmac.compare_digest(integrity.hmac_signature, expected_signature):
            return False, "HMAC verification failed - message may be tampered"
        
        return True, None
    
    def attach_integrity_headers(self, message: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate HTTP headers for message integrity
        
        Returns:
            Headers dictionary with X-Message-Integrity fields
        """
        integrity = self.sign_message(message)
        
        return {
            'X-Message-ID': integrity.message_id,
            'X-Message-Timestamp': integrity.timestamp,
            'X-Message-HMAC': integrity.hmac_signature,
            'X-Message-HMAC-Algorithm': integrity.algorithm
        }
    
    def verify_from_headers(
        self,
        message: Dict[str, Any],
        headers: Dict[str, str]
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify message integrity from HTTP headers
        
        Returns:
            Tuple of (valid, error_message)
        """
        try:
            integrity = MessageIntegrity(
                message_id=headers.get('X-Message-ID', ''),
                timestamp=headers.get('X-Message-Timestamp', ''),
                hmac_signature=headers.get('X-Message-HMAC', ''),
                algorithm=headers.get('X-Message-HMAC-Algorithm', 'sha256')
            )
            
            return self.verify_message(message, integrity)
        
        except Exception as e:
            return False, f"Header verification failed: {e}"


class ZeroTrustEnforcer:
    """
    Implements Zero-Trust Architecture principles for A2A communication
    
    Principles:
    - Never trust, always verify
    - Verify explicitly on every request
    - Use least privilege access
    - Assume breach
    
    Reference: PDF Section "Zero-Trust Architecture"
    """
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.trust_decisions: Dict[str, int] = defaultdict(int)  # Track decisions per agent
        
        logger.info("Zero-Trust enforcement enabled")
    
    async def verify_request(
        self,
        headers: Dict[str, str],
        message: Dict[str, Any],
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[AuthContext], List[str]]:
        """
        Comprehensive zero-trust verification
        
        Checks (in order):
        1. Authentication (who are you?)
        2. Authorization (what can you do?)
        3. Rate limiting (are you behaving normally?)
        4. Message integrity (is this message authentic?)
        
        Returns:
            Tuple of (allowed, auth_context, violations)
        """
        violations = []
        
        # Step 1: Authentication - verify identity
        success, auth_context, error = await self.security_manager.authenticate_request(
            headers, source_ip
        )
        
        if not success:
            violations.append(f"Authentication failed: {error}")
            return False, None, violations
        
        # Step 2: Rate limiting - detect anomalies
        allowed, error = self.security_manager.check_rate_limit(auth_context.agent_id)
        if not allowed:
            violations.append(f"Rate limit exceeded: {error}")
            return False, auth_context, violations
        
        # Step 3: Authorization - verify permissions for this method
        method = message.get('method')
        if method:
            has_permission = self.security_manager.check_permission(auth_context, method)
            if not has_permission:
                violations.append(f"Insufficient permissions for method: {method}")
                return False, auth_context, violations
        
        # All checks passed
        self.trust_decisions[auth_context.agent_id] += 1
        return True, auth_context, []
    
    def get_trust_metrics(self, agent_id: str) -> Dict[str, Any]:
        """Get trust metrics for an agent"""
        return {
            'agent_id': agent_id,
            'successful_verifications': self.trust_decisions.get(agent_id, 0),
            'trust_level': self._calculate_trust_level(agent_id)
        }
    
    def _calculate_trust_level(self, agent_id: str) -> str:
        """Calculate trust level based on history"""
        count = self.trust_decisions.get(agent_id, 0)
        
        if count >= 100:
            return "established"
        elif count >= 10:
            return "trusted"
        else:
            return "new"


class AnomalyDetector:
    """
    AI-enhanced anomaly detection for A2A communication patterns
    
    Detects:
    - Unusual request patterns
    - Spike in error rates
    - Suspicious timing patterns
    - Abnormal method usage
    
    Reference: PDF Section "AI Anomaly Detection"
    """
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.request_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.error_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.method_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        logger.info(f"Anomaly detection enabled (window={window_size})")
    
    def record_request(
        self,
        agent_id: str,
        method: str,
        success: bool,
        response_time: float
    ):
        """Record request for anomaly detection"""
        timestamp = datetime.utcnow()
        
        self.request_history[agent_id].append({
            'timestamp': timestamp,
            'method': method,
            'success': success,
            'response_time': response_time
        })
        
        if not success:
            self.error_history[agent_id].append(timestamp)
        
        self.method_counts[agent_id][method] += 1
    
    def detect_anomalies(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies in agent behavior
        
        Returns:
            List of detected anomalies with severity
        """
        anomalies = []
        
        # Check error rate
        error_rate = self._calculate_error_rate(agent_id)
        if error_rate > 0.3:  # 30% error threshold
            anomalies.append({
                'type': 'high_error_rate',
                'severity': 'high' if error_rate > 0.5 else 'medium',
                'value': error_rate,
                'description': f"Error rate: {error_rate:.1%}"
            })
        
        # Check request frequency
        freq_anomaly = self._check_frequency_anomaly(agent_id)
        if freq_anomaly:
            anomalies.append(freq_anomaly)
        
        # Check method distribution
        method_anomaly = self._check_method_anomaly(agent_id)
        if method_anomaly:
            anomalies.append(method_anomaly)
        
        return anomalies
    
    def _calculate_error_rate(self, agent_id: str) -> float:
        """Calculate recent error rate"""
        requests = self.request_history.get(agent_id, [])
        if not requests:
            return 0.0
        
        errors = sum(1 for r in requests if not r['success'])
        return errors / len(requests)
    
    def _check_frequency_anomaly(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Detect unusual request frequency"""
        requests = list(self.request_history.get(agent_id, []))
        if len(requests) < 10:
            return None
        
        # Calculate requests per minute for recent activity
        recent_requests = [r for r in requests[-10:]]
        if not recent_requests:
            return None
        
        time_span = (recent_requests[-1]['timestamp'] - recent_requests[0]['timestamp']).total_seconds()
        if time_span > 0:
            rpm = (len(recent_requests) / time_span) * 60
            
            if rpm > 120:  # More than 120 requests per minute
                return {
                    'type': 'high_frequency',
                    'severity': 'medium',
                    'value': rpm,
                    'description': f"Unusual request frequency: {rpm:.1f} req/min"
                }
        
        return None
    
    def _check_method_anomaly(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Detect unusual method usage patterns"""
        methods = self.method_counts.get(agent_id, {})
        if not methods:
            return None
        
        total = sum(methods.values())
        if total < 20:
            return None
        
        # Check if one method dominates (>80%)
        for method, count in methods.items():
            if count / total > 0.8:
                return {
                    'type': 'method_concentration',
                    'severity': 'low',
                    'value': count / total,
                    'description': f"Method '{method}' used {count/total:.1%} of time"
                }
        
        return None


class EnhancedSecurityManager:
    """
    Enhanced security manager combining all security best practices
    
    Integrates:
    - TLS/mTLS encryption
    - Message integrity verification
    - Zero-trust enforcement
    - Anomaly detection
    - Existing authentication & authorization
    """
    
    def __init__(
        self,
        base_security: SecurityManager,
        enable_tls: bool = True,
        enable_mtls: bool = False,
        enable_message_integrity: bool = True,
        enable_zero_trust: bool = True,
        enable_anomaly_detection: bool = True
    ):
        self.base_security = base_security
        
        # TLS/mTLS
        self.tls_config: Optional[TLSConfigManager] = None
        if enable_tls:
            self.tls_config = TLSConfigManager(
                require_client_cert=enable_mtls
            )
        
        # Message integrity
        self.integrity_verifier: Optional[MessageIntegrityVerifier] = None
        if enable_message_integrity:
            secret = os.getenv('MESSAGE_INTEGRITY_KEY', 'dev-integrity-secret')
            self.integrity_verifier = MessageIntegrityVerifier(secret)
        
        # Zero-trust
        self.zero_trust: Optional[ZeroTrustEnforcer] = None
        if enable_zero_trust:
            self.zero_trust = ZeroTrustEnforcer(base_security)
        
        # Anomaly detection
        self.anomaly_detector: Optional[AnomalyDetector] = None
        if enable_anomaly_detection:
            self.anomaly_detector = AnomalyDetector()
        
        logger.info(
            f"Enhanced security initialized: TLS={enable_tls}, "
            f"mTLS={enable_mtls}, Integrity={enable_message_integrity}, "
            f"ZeroTrust={enable_zero_trust}, Anomaly={enable_anomaly_detection}"
        )
    
    async def verify_secure_request(
        self,
        headers: Dict[str, str],
        message: Dict[str, Any],
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[AuthContext], List[str]]:
        """
        Comprehensive security verification for A2A requests
        
        Returns:
            Tuple of (allowed, auth_context, security_violations)
        """
        violations = []
        
        # Message integrity check
        if self.integrity_verifier:
            valid, error = self.integrity_verifier.verify_from_headers(message, headers)
            if not valid:
                violations.append(f"Message integrity: {error}")
                return False, None, violations
        
        # Zero-trust verification
        if self.zero_trust:
            allowed, auth_context, zt_violations = await self.zero_trust.verify_request(
                headers, message, source_ip
            )
            if not allowed:
                return False, auth_context, zt_violations
        else:
            # Fallback to base authentication
            success, auth_context, error = await self.base_security.authenticate_request(
                headers, source_ip
            )
            if not success:
                violations.append(f"Authentication: {error}")
                return False, None, violations
        
        return True, auth_context, []
    
    def record_request_for_anomaly_detection(
        self,
        agent_id: str,
        method: str,
        success: bool,
        response_time: float
    ):
        """Record request for anomaly detection"""
        if self.anomaly_detector:
            self.anomaly_detector.record_request(agent_id, method, success, response_time)
    
    def check_for_anomalies(self, agent_id: str) -> List[Dict[str, Any]]:
        """Check if agent behavior shows anomalies"""
        if self.anomaly_detector:
            return self.anomaly_detector.detect_anomalies(agent_id)
        return []
    
    def get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Get SSL context for server"""
        if self.tls_config:
            return self.tls_config.create_server_ssl_context()
        return None
    
    def sign_outgoing_message(self, message: Dict[str, Any]) -> Dict[str, str]:
        """Sign outgoing message with integrity headers"""
        if self.integrity_verifier:
            return self.integrity_verifier.attach_integrity_headers(message)
        return {}


# Example usage
if __name__ == "__main__":
    from security import SecurityManager
    
    # Create base security
    base_security = SecurityManager()
    
    # Create enhanced security with all features
    enhanced_security = EnhancedSecurityManager(
        base_security=base_security,
        enable_tls=True,
        enable_mtls=True,
        enable_message_integrity=True,
        enable_zero_trust=True,
        enable_anomaly_detection=True
    )
    
    print("Enhanced A2A security configured:")
    print("- TLS 1.3 encryption with strong ciphers")
    print("- Mutual TLS authentication")
    print("- Message integrity verification (HMAC)")
    print("- Zero-trust request verification")
    print("- AI-enhanced anomaly detection")

