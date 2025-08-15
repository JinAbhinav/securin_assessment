"""
Supabase database client management.
"""
from typing import Optional
from supabase import create_client, Client
import structlog
import asyncio

from app.core.config import settings

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """Supabase database client manager."""
    
    def __init__(self):
        self._supabase_client: Optional[Client] = None
    
    @property
    def supabase(self) -> Client:
        """Get Supabase admin client instance."""
        if not self._supabase_client:
            # Use service key for admin operations if available, otherwise use regular key
            key = settings.supabase_service_key if settings.supabase_service_key else settings.supabase_key
            self._supabase_client = create_client(
                settings.supabase_url,
                key
            )
            logger.info("Supabase admin client initialized")
        return self._supabase_client
    
    async def init_database(self) -> None:
        """Initialize Supabase client (no setup needed)."""
        # Just verify connection by accessing the client
        _ = self.supabase
        logger.info("Supabase database client ready")
    
    async def close_database(self) -> None:
        """Close Supabase client (cleanup if needed)."""
        self._supabase_client = None
        logger.info("Supabase client cleared")


# Global database manager instance
db_manager = DatabaseManager()


def get_supabase_client() -> Client:
    """Dependency for getting Supabase client."""
    return db_manager.supabase


# Database initialization and cleanup functions
async def init_database():
    """Initialize Supabase database client."""
    await db_manager.init_database()
    logger.info("Database initialized")


async def close_database():
    """Close Supabase database client."""
    await db_manager.close_database()
    logger.info("Database closed")


class HealthCheck:
    """Database health check utilities."""
    
    @staticmethod
    async def check_supabase_connection() -> bool:
        """Check Supabase connection health."""
        try:
            # Add timeout to prevent hanging
            async def _check():
                client = get_supabase_client()
                # Lightweight query to test connection - just get one record without counting
                result = client.table('cves').select('id').limit(1).execute()
                return True
            
            return await asyncio.wait_for(_check(), timeout=settings.health_check_timeout)
        except asyncio.TimeoutError:
            logger.error("Supabase health check timed out", timeout=settings.health_check_timeout)
            return False
        except Exception as e:
            logger.error("Supabase health check failed", error=str(e))
            return False
    
    @staticmethod
    async def get_database_info() -> dict:
        """Get database information for monitoring using Supabase."""
        try:
            async def _get_info():
                client = get_supabase_client()
                
                # Get CVE count (use estimated count for better performance)
                try:
                    cve_result = client.table('cves').select('count', count='estimated').execute()
                    cve_count = cve_result.count if cve_result.count is not None else 0
                except:
                    # Fallback: if estimated count fails, try a simple query
                    try:
                        fallback_result = client.table('cves').select('id').execute()
                        cve_count = len(fallback_result.data) if fallback_result.data else 0
                    except:
                        cve_count = 0
                
                # Try to get last sync (this might fail if sync_status table doesn't exist yet)
                try:
                    sync_result = client.table('sync_status').select('completed_at').eq('status', 'completed').order('completed_at', desc=True).limit(1).execute()
                    last_sync = sync_result.data[0]['completed_at'] if sync_result.data else None
                except:
                    last_sync = None
                    
                return {
                    "database_type": "Supabase",
                    "total_cves": cve_count,
                    "last_sync": last_sync,
                    "connection_status": "connected"
                }
            
            return await asyncio.wait_for(_get_info(), timeout=settings.health_check_timeout)
            
        except asyncio.TimeoutError:
            logger.error("Database info gathering timed out", timeout=settings.health_check_timeout)
            return {"error": "timeout", "connection_status": "timeout"}
        except Exception as e:
            logger.error("Failed to get database info", error=str(e))
            return {"error": str(e), "connection_status": "error"}
