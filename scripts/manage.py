#!/usr/bin/env python3
"""
Management script for CVE Assessment API.
"""
import asyncio
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.core.config import settings
from app.core.database import init_database, db_manager, HealthCheck
from app.services.sync_service import SyncService
from app.services.cve_service import CVEService
from app.models.cve import SyncTrigger
import structlog

logger = structlog.get_logger(__name__)


async def check_health():
    """Check system health."""
    print("🔍 Checking system health...")
    
    try:
        await init_database()
        
        # Database checks (Supabase only)
        supabase_healthy = await HealthCheck.check_supabase_connection()
        
        print(f"Supabase: {'✅' if supabase_healthy else '❌'}")
        
        # Get database info
        if supabase_healthy:
            db_info = await HealthCheck.get_database_info()
            print(f"Total CVEs: {db_info.get('total_cves', 'N/A')}")
            print(f"Last sync: {db_info.get('last_sync', 'Never')}")
            print(f"Database type: {db_info.get('database_type', 'Unknown')}")
        
        return supabase_healthy
        
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False


async def sync_data(sync_type="incremental", force=False):
    """Trigger data synchronization."""
    print(f"🔄 Starting {sync_type} synchronization...")
    
    try:
        await init_database()
        sync_service = SyncService()
        
        sync_trigger = SyncTrigger(sync_type=sync_type, force=force)
        sync_id = await sync_service.trigger_sync(sync_trigger)
        
        print(f"✅ Synchronization started with ID: {sync_id}")
        
        # Monitor progress
        while sync_service.is_sync_running():
            status = await sync_service.get_sync_status(sync_id)
            if status:
                print(f"Progress: {status.processed_records}/{status.total_records} records processed")
            await asyncio.sleep(5)
        
        # Get final status
        final_status = await sync_service.get_sync_status(sync_id)
        if final_status:
            print(f"✅ Sync completed: {final_status.new_records} new, {final_status.updated_records} updated")
        
    except Exception as e:
        print(f"❌ Sync failed: {e}")


async def get_stats():
    """Get CVE statistics."""
    print("📊 Getting CVE statistics...")
    
    try:
        await init_database()
        cve_service = CVEService()
        
        stats = await cve_service.get_statistics()
        
        print(f"Total CVEs: {stats.total_cves}")
        print(f"Critical: {stats.critical_cves}")
        print(f"High: {stats.high_cves}")
        print(f"Medium: {stats.medium_cves}")
        print(f"Low: {stats.low_cves}")
        print(f"Unscored: {stats.unscored_cves}")
        print(f"Last updated: {stats.last_updated}")
        print(f"Published today: {stats.today_published}")
        print(f"Published this week: {stats.week_published}")
        print(f"Published this month: {stats.month_published}")
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")


async def cleanup_sync_history(days=30):
    """Clean up old sync records."""
    print(f"🧹 Cleaning up sync records older than {days} days...")
    
    try:
        await init_database()
        sync_service = SyncService()
        
        deleted_count = await sync_service.cleanup_old_sync_records(days)
        print(f"✅ Deleted {deleted_count} old sync records")
        
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")


async def init_schema():
    """Initialize database schema."""
    print("🗄️ Database schema initialization...")
    print("ℹ️ Using Supabase - schema is managed through the Supabase dashboard")
    print("ℹ️ Please ensure your Supabase project has the correct tables:")
    print("   - cves (CVE records)")
    print("   - sync_status (synchronization tracking)")
    print("ℹ️ Refer to database/schema.sql for the expected structure")
    
    try:
        await init_database()
        
        # Just verify we can connect and check basic tables
        supabase_healthy = await HealthCheck.check_supabase_connection()
        if supabase_healthy:
            print("✅ Supabase connection verified")
            db_info = await HealthCheck.get_database_info()
            print(f"✅ CVE table accessible (found {db_info.get('total_cves', 0)} records)")
        else:
            print("❌ Supabase connection failed")
        
    except Exception as e:
        print(f"❌ Schema verification failed: {e}")


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description="CVE Assessment API Management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Health check command
    subparsers.add_parser("health", help="Check system health")
    
    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Trigger data synchronization")
    sync_parser.add_argument("--type", choices=["full", "incremental"], default="incremental",
                           help="Type of synchronization")
    sync_parser.add_argument("--force", action="store_true", help="Force sync even if one is running")
    
    # Stats command
    subparsers.add_parser("stats", help="Get CVE statistics")
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old sync records")
    cleanup_parser.add_argument("--days", type=int, default=30, help="Days of records to keep")
    
    # Schema check command
    subparsers.add_parser("init-schema", help="Verify database schema (Supabase)")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Run the appropriate command
    try:
        if args.command == "health":
            asyncio.run(check_health())
        elif args.command == "sync":
            asyncio.run(sync_data(args.type, args.force))
        elif args.command == "stats":
            asyncio.run(get_stats())
        elif args.command == "cleanup":
            asyncio.run(cleanup_sync_history(args.days))
        elif args.command == "init-schema":
            asyncio.run(init_schema())
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled")
    except Exception as e:
        print(f"❌ Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
