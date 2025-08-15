#!/usr/bin/env python3
"""
Production startup script for CVE Assessment API.
"""
import asyncio
import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.config import settings
from app.core.database import init_database, HealthCheck
import structlog
import uvicorn

logger = structlog.get_logger(__name__)


async def startup_checks():
    """Perform startup checks before launching the server."""
    logger.info("Performing startup checks...")
    
    # Check Supabase database connectivity
    try:
        await init_database()
        logger.info("✅ Database initialization successful")
        
        # Verify Supabase connection
        if settings.supabase_url and settings.supabase_key:
            supabase_healthy = await HealthCheck.check_supabase_connection()
            if supabase_healthy:
                logger.info("✅ Supabase connection verified")
            else:
                logger.error("❌ Supabase connection failed")
                return False
        else:
            logger.error("❌ Supabase credentials not configured")
            return False
    except Exception as e:
        logger.error("❌ Database initialization failed", error=str(e))
        return False
    
    # Check required environment variables
    required_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'SECRET_KEY']
    missing_vars = []
    
    for var in required_vars:
        if not getattr(settings, var.lower(), None):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error("❌ Missing required environment variables", missing=missing_vars)
        return False
    
    logger.info("✅ All startup checks passed")
    return True


def main():
    """Main entry point."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    
    # Run startup checks
    try:
        startup_ok = asyncio.run(startup_checks())
        if not startup_ok:
            logger.error("Startup checks failed, exiting...")
            sys.exit(1)
    except Exception as e:
        logger.error("Error during startup checks", error=str(e))
        sys.exit(1)
    
    # Configure uvicorn
    uvicorn_config = {
        "app": "app.main:app",
        "host": settings.host,
        "port": settings.port,
        "log_level": settings.log_level.lower(),
        "access_log": True,
        "reload": settings.debug,
        "workers": 1 if settings.debug else 4,
    }
    
    # Add SSL configuration if certificates are available
    ssl_cert = os.getenv("SSL_CERT_PATH")
    ssl_key = os.getenv("SSL_KEY_PATH")
    
    if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        uvicorn_config.update({
            "ssl_certfile": ssl_cert,
            "ssl_keyfile": ssl_key,
        })
        logger.info("🔒 SSL enabled")
    
    logger.info(f"🚀 Starting server on {settings.host}:{settings.port}")
    
    try:
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown requested")
    except Exception as e:
        logger.error("Server error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
