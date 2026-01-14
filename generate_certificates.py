#!/usr/bin/env python3
"""
Certificate Generation Script for A2A mTLS

Generates all certificates needed for mutual TLS authentication:
- Root CA certificate
- Agent certificates (orchestrator, extractor, validator, archivist, lambda)
- Keycloak certificate

Usage:
    python generate_certificates.py [--certs-dir ./certs] [--force]
"""

import argparse
import logging
import sys
from pathlib import Path

# Import certificate management module
try:
    from mtls_manager import MTLSConfigManager, CertificateAuthority
except ImportError:
    print("Error: mtls_manager module not found")
    print("Ensure mtls_manager.py is in the same directory")
    sys.exit(1)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Generate mTLS certificates for A2A agents"
    )
    parser.add_argument(
        "--certs-dir",
        type=str,
        default="./certs",
        help="Directory to store certificates (default: ./certs)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force regeneration of existing certificates"
    )
    parser.add_argument(
        "--agents",
        type=str,
        nargs="+",
        default=["orchestrator", "extractor", "validator", "archivist", "keycloak", "lambda"],
        help="List of agent names to generate certificates for"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("=" * 60)
    logger.info("A2A mTLS Certificate Generation")
    logger.info("=" * 60)
    logger.info(f"Certificates directory: {args.certs_dir}")
    logger.info(f"Force regeneration: {args.force}")
    logger.info(f"Agents: {', '.join(args.agents)}")
    logger.info("=" * 60)
    
    # Initialize certificate manager
    mtls_manager = MTLSConfigManager(certs_dir=args.certs_dir)
    
    # Step 1: Generate/Load CA
    logger.info("\n[Step 1/2] Initializing Certificate Authority...")
    try:
        ca_cert_path, ca_key_path = mtls_manager.initialize_ca(force=args.force)
        logger.info(f"✓ CA Certificate: {ca_cert_path}")
        logger.info(f"✓ CA Private Key: {ca_key_path}")
    except Exception as e:
        logger.error(f"✗ Failed to initialize CA: {e}")
        sys.exit(1)
    
    # Step 2: Generate agent certificates
    logger.info("\n[Step 2/2] Generating agent certificates...")
    results = {}
    
    for agent_name in args.agents:
        try:
            logger.info(f"\nGenerating certificate for: {agent_name}")
            cert_paths = mtls_manager.generate_agent_certificate(
                agent_name,
                force=args.force
            )
            results[agent_name] = cert_paths
            logger.info(f"  ✓ Certificate: {cert_paths['cert']}")
            logger.info(f"  ✓ Private Key: {cert_paths['key']}")
        except Exception as e:
            logger.error(f"  ✗ Failed to generate certificate for {agent_name}: {e}")
            results[agent_name] = None
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Certificate Generation Summary")
    logger.info("=" * 60)
    
    successful = sum(1 for v in results.values() if v is not None)
    failed = len(results) - successful
    
    logger.info(f"Total agents: {len(results)}")
    logger.info(f"Successful: {successful}")
    logger.info(f"Failed: {failed}")
    
    if failed == 0:
        logger.info("\n✓ All certificates generated successfully!")
    else:
        logger.warning(f"\n⚠ {failed} certificate(s) failed to generate")
    
    # Print certificate paths
    logger.info("\n" + "-" * 60)
    logger.info("Certificate Locations:")
    logger.info("-" * 60)
    logger.info(f"\nCA Certificate: {ca_cert_path}")
    logger.info(f"CA Private Key: {ca_key_path}")
    
    for agent_name, paths in results.items():
        if paths:
            logger.info(f"\n{agent_name.capitalize()}:")
            logger.info(f"  Certificate: {paths['cert']}")
            logger.info(f"  Private Key: {paths['key']}")
    
    # Generate environment variable examples
    logger.info("\n" + "-" * 60)
    logger.info("Environment Variable Examples:")
    logger.info("-" * 60)
    
    for agent_name, paths in results.items():
        if paths:
            logger.info(f"\n# {agent_name.capitalize()}")
            logger.info(f"MTLS_ENABLED=true")
            logger.info(f"MTLS_CERT_PATH={paths['cert']}")
            logger.info(f"MTLS_KEY_PATH={paths['key']}")
            logger.info(f"MTLS_CA_CERT_PATH={paths['ca_cert']}")
            logger.info(f"MTLS_REQUIRE_CLIENT_CERT=true")
    
    # Generate deployment configuration
    logger.info("\n" + "-" * 60)
    logger.info("Next Steps:")
    logger.info("-" * 60)
    logger.info("""
1. Verify certificates:
   openssl x509 -in {cert_path} -text -noout

2. Test certificate chain:
   openssl verify -CAfile {ca_cert} {agent_cert}

3. Update agent configurations:
   - Add MTLS_ENABLED=true to environment
   - Specify certificate paths in ECS task definitions
   - Mount certificates as secrets or volumes

4. Update Keycloak:
   - Configure OAuth 2.0 Mutual-TLS Client Authentication
   - Enable certificate-bound access tokens (RFC 8705)
   - Map certificate subject to Keycloak users

5. Test mTLS connection:
   curl --cert {client_cert} --key {client_key} --cacert {ca_cert} \\
        https://orchestrator.ca-a2a.local:8001/health
""".format(
        cert_path=f"{args.certs_dir}/agents/orchestrator/orchestrator-cert.pem",
        ca_cert=ca_cert_path,
        agent_cert=f"{args.certs_dir}/agents/orchestrator/orchestrator-cert.pem",
        client_cert=f"{args.certs_dir}/agents/lambda/lambda-cert.pem",
        client_key=f"{args.certs_dir}/agents/lambda/lambda-key.pem"
    ))
    
    logger.info("=" * 60)
    logger.info("Certificate generation complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
