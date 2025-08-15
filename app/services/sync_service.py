"""
CVE synchronization service for managing data updates from NVD API.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from enum import Enum

import structlog

from app.core.database import db_manager
from app.core.config import settings
from app.services.nvd_client import NVDClient
from app.services.cve_service import CVEService
from app.models.cve import SyncStatus, SyncTrigger

logger = structlog.get_logger(__name__)


class SyncType(Enum):
    """Enumeration for synchronization types."""
    FULL = "full"
    INCREMENTAL = "incremental"


class SyncStatusEnum(Enum):
    """Enumeration for synchronization status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SyncService:
    """Service for managing CVE data synchronization."""
    
    def __init__(self):
        self.cve_service = CVEService()
        self.batch_size = settings.sync_batch_size
        self.max_concurrent_batches = 5
        self._running_sync: Optional[asyncio.Task] = None
    
    async def trigger_sync(self, sync_trigger: SyncTrigger) -> int:
        """
        Trigger a synchronization operation.
        
        Args:
            sync_trigger: Sync configuration
            
        Returns:
            Sync status ID
        """
        if not settings.sync_enabled and not sync_trigger.force:
            raise ValueError("Synchronization is disabled")
        
        # Check if sync is already running
        if self.is_sync_running():
            if not sync_trigger.force:
                raise ValueError("Synchronization is already running")
            else:
                await self.cancel_running_sync()
        
        # Determine sync type
        sync_type = SyncType(sync_trigger.sync_type)
        
        # Create sync status record
        sync_id = await self._create_sync_status(sync_type)
        
        # Start synchronization in background
        self._running_sync = asyncio.create_task(
            self._perform_sync(sync_id, sync_type)
        )
        
        logger.info(f"Started {sync_type.value} synchronization", sync_id=sync_id)
        return sync_id
    
    async def get_sync_status(self, sync_id: Optional[int] = None) -> Optional[SyncStatus]:
        """Get synchronization status using Supabase."""
        try:
            if sync_id:
                result = db_manager.supabase.table("sync_status").select("*").eq("id", sync_id).execute()
            else:
                # Get latest sync status
                result = db_manager.supabase.table("sync_status").select("*").order("started_at", desc=True).limit(1).execute()
            
            if result.data and len(result.data) > 0:
                return SyncStatus(**result.data[0])
            return None
        except Exception as e:
            logger.error("Error getting sync status", error=str(e))
            return None
    
    async def get_sync_history(self, limit: int = 20) -> List[SyncStatus]:
        """Get synchronization history using Supabase."""
        try:
            result = db_manager.supabase.table("sync_status").select("*").order("started_at", desc=True).limit(limit).execute()
            
            return [SyncStatus(**row) for row in result.data] if result.data else []
        except Exception as e:
            logger.error("Error getting sync history", error=str(e))
            return []
    
    def is_sync_running(self) -> bool:
        """Check if synchronization is currently running."""
        return self._running_sync is not None and not self._running_sync.done()
    
    async def cancel_running_sync(self) -> bool:
        """Cancel currently running synchronization."""
        if not self.is_sync_running():
            return False
        
        if self._running_sync:
            self._running_sync.cancel()
            try:
                await self._running_sync
            except asyncio.CancelledError:
                pass
            self._running_sync = None
        
        # Update sync status to cancelled
        await self._update_sync_status_error(None, "Synchronization cancelled by user")
        logger.info("Synchronization cancelled")
        return True
    
    async def should_run_sync(self) -> bool:
        """Check if automatic synchronization should run."""
        if not settings.sync_enabled:
            return False
        
        # Check last successful sync
        last_sync = await self.get_sync_status()
        if not last_sync or last_sync.status != SyncStatusEnum.COMPLETED.value:
            return True
        
        # Check if enough time has passed
        time_since_sync = datetime.now(timezone.utc) - last_sync.completed_at
        return time_since_sync.total_seconds() >= (settings.sync_interval_hours * 3600)
    
    async def _create_sync_status(self, sync_type: SyncType) -> int:
        """Create a new sync status record using Supabase."""
        try:
            insert_data = {
                "sync_type": sync_type.value,
                "status": SyncStatusEnum.RUNNING.value,
                "started_at": datetime.now(timezone.utc).isoformat()
            }
            
            result = db_manager.supabase.table("sync_status").insert(insert_data).execute()
            
            if result.data and len(result.data) > 0:
                return result.data[0]["id"]
            else:
                raise Exception("Failed to create sync status record")
        except Exception as e:
            logger.error("Error creating sync status", error=str(e))
            raise
    
    async def _update_sync_status(
        self,
        sync_id: int,
        status: SyncStatusEnum,
        total_records: int = 0,
        processed_records: int = 0,
        new_records: int = 0,
        updated_records: int = 0,
        last_modified_date: Optional[datetime] = None
    ):
        """Update sync status record using Supabase."""
        try:
            update_data = {
                "status": status.value,
                "total_records": total_records,
                "processed_records": processed_records,
                "new_records": new_records,
                "updated_records": updated_records,
                "last_modified_date": last_modified_date.isoformat() if last_modified_date else None
            }
            
            # Set completed_at if status is terminal
            if status.value in ['completed', 'failed', 'cancelled']:
                update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            db_manager.supabase.table("sync_status").update(update_data).eq("id", sync_id).execute()
        except Exception as e:
            logger.error(f"Error updating sync status {sync_id}", error=str(e))
    
    async def _update_sync_status_error(self, sync_id: Optional[int], error_message: str):
        """Update sync status with error using Supabase."""
        try:
            if not sync_id:
                # Find the latest running sync
                result = db_manager.supabase.table("sync_status").select("id").eq("status", "running").order("started_at", desc=True).limit(1).execute()
                
                if not result.data:
                    return
                sync_id = result.data[0]["id"]
            
            update_data = {
                "status": SyncStatusEnum.FAILED.value,
                "error_message": error_message,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }
            
            db_manager.supabase.table("sync_status").update(update_data).eq("id", sync_id).execute()
        except Exception as e:
            logger.error(f"Error updating sync status with error {sync_id}", error=str(e))
    
    async def _perform_sync(self, sync_id: int, sync_type: SyncType):
        """Perform the actual synchronization."""
        try:
            logger.info(f"Starting {sync_type.value} synchronization", sync_id=sync_id)
            
            async with NVDClient() as nvd_client:
                if sync_type == SyncType.FULL:
                    await self._perform_full_sync(sync_id, nvd_client)
                else:
                    await self._perform_incremental_sync(sync_id, nvd_client)
                
            logger.info(f"Completed {sync_type.value} synchronization", sync_id=sync_id)
            
        except asyncio.CancelledError:
            logger.info("Synchronization cancelled", sync_id=sync_id)
            await self._update_sync_status_error(sync_id, "Synchronization cancelled")
            raise
        except Exception as e:
            logger.error(f"Synchronization failed", sync_id=sync_id, error=str(e))
            await self._update_sync_status_error(sync_id, str(e))
            raise
        finally:
            self._running_sync = None
    
    async def _perform_full_sync(self, sync_id: int, nvd_client: NVDClient):
        """Perform full synchronization of all CVE data."""
        total_processed = 0
        total_created = 0
        total_updated = 0
        batch = []
        
        try:
            # Get total count first for progress tracking
            initial_response = await nvd_client.get_cves(results_per_page=1)
            total_records = initial_response.total_results
            
            await self._update_sync_status(
                sync_id, 
                SyncStatusEnum.RUNNING, 
                total_records=total_records
            )
            
            logger.info(f"Full sync: processing {total_records} CVEs")
            
            # Process all CVEs in batches
            async for cve_item in nvd_client.get_all_cves():
                batch.append(cve_item)
                
                if len(batch) >= self.batch_size:
                    created, updated = await self.cve_service.upsert_cves_batch(batch)
                    total_created += created
                    total_updated += updated
                    total_processed += len(batch)
                    
                    # Update progress
                    await self._update_sync_status(
                        sync_id,
                        SyncStatusEnum.RUNNING,
                        total_records=total_records,
                        processed_records=total_processed,
                        new_records=total_created,
                        updated_records=total_updated
                    )
                    
                    logger.info(
                        f"Full sync progress: {total_processed}/{total_records} CVEs processed"
                    )
                    
                    batch = []
                    
                    # Rate limiting
                    await asyncio.sleep(0.1)
            
            # Process remaining batch
            if batch:
                created, updated = await self.cve_service.upsert_cves_batch(batch)
                total_created += created
                total_updated += updated
                total_processed += len(batch)
            
            # Mark as completed
            await self._update_sync_status(
                sync_id,
                SyncStatusEnum.COMPLETED,
                total_records=total_records,
                processed_records=total_processed,
                new_records=total_created,
                updated_records=total_updated,
                last_modified_date=datetime.now(timezone.utc)
            )
            
            logger.info(
                f"Full sync completed: {total_created} created, {total_updated} updated"
            )
            
        except Exception as e:
            logger.error(f"Full sync failed", error=str(e))
            raise
    
    async def _perform_incremental_sync(self, sync_id: int, nvd_client: NVDClient):
        """Perform incremental synchronization of recently modified CVEs."""
        # Get last sync date
        last_sync_date = await self._get_last_sync_date()
        if not last_sync_date:
            # No previous sync, fall back to recent data
            last_sync_date = datetime.now(timezone.utc) - timedelta(days=7)
        
        logger.info(f"Incremental sync: fetching CVEs modified since {last_sync_date}")
        
        total_processed = 0
        total_created = 0
        total_updated = 0
        batch = []
        latest_modified = last_sync_date
        
        try:
            # Fetch CVEs modified since last sync
            start_date = last_sync_date
            end_date = datetime.now(timezone.utc)
            
            # Get initial count
            initial_response = await nvd_client.get_cves(
                last_mod_start_date=start_date,
                last_mod_end_date=end_date,
                results_per_page=1
            )
            total_records = initial_response.total_results
            
            await self._update_sync_status(
                sync_id,
                SyncStatusEnum.RUNNING,
                total_records=total_records
            )
            
            if total_records == 0:
                logger.info("Incremental sync: no new CVEs to process")
                await self._update_sync_status(
                    sync_id,
                    SyncStatusEnum.COMPLETED,
                    total_records=0,
                    processed_records=0,
                    new_records=0,
                    updated_records=0,
                    last_modified_date=end_date
                )
                return
            
            logger.info(f"Incremental sync: processing {total_records} modified CVEs")
            
            # Process modified CVEs
            async for cve_item in nvd_client.get_all_cves(
                last_mod_start_date=start_date,
                last_mod_end_date=end_date
            ):
                batch.append(cve_item)
                
                # Track latest modification date
                cve_data = cve_item.cve
                if 'lastModified' in cve_data:
                    modified_date = datetime.fromisoformat(
                        cve_data['lastModified'].replace('Z', '+00:00')
                    )
                    # Ensure timezone-aware datetime
                    if modified_date.tzinfo is None:
                        modified_date = modified_date.replace(tzinfo=timezone.utc)
                    
                    if modified_date > latest_modified:
                        latest_modified = modified_date
                
                if len(batch) >= self.batch_size:
                    created, updated = await self.cve_service.upsert_cves_batch(batch)
                    total_created += created
                    total_updated += updated
                    total_processed += len(batch)
                    
                    # Update progress
                    await self._update_sync_status(
                        sync_id,
                        SyncStatusEnum.RUNNING,
                        total_records=total_records,
                        processed_records=total_processed,
                        new_records=total_created,
                        updated_records=total_updated
                    )
                    
                    logger.info(
                        f"Incremental sync progress: {total_processed}/{total_records} CVEs processed"
                    )
                    
                    batch = []
                    
                    # Rate limiting
                    await asyncio.sleep(0.1)
            
            # Process remaining batch
            if batch:
                created, updated = await self.cve_service.upsert_cves_batch(batch)
                total_created += created
                total_updated += updated
                total_processed += len(batch)
            
            # Mark as completed
            await self._update_sync_status(
                sync_id,
                SyncStatusEnum.COMPLETED,
                total_records=total_records,
                processed_records=total_processed,
                new_records=total_created,
                updated_records=total_updated,
                last_modified_date=latest_modified
            )
            
            logger.info(
                f"Incremental sync completed: {total_created} created, {total_updated} updated"
            )
            
        except Exception as e:
            logger.error(f"Incremental sync failed", error=str(e))
            raise
    
    async def _get_last_sync_date(self) -> Optional[datetime]:
        """Get the date of the last successful synchronization using Supabase."""
        try:
            result = db_manager.supabase.table("sync_status").select("last_modified_date").eq("status", "completed").not_.is_("last_modified_date", "null").order("completed_at", desc=True).limit(1).execute()
            
            if result.data and len(result.data) > 0:
                date_str = result.data[0]["last_modified_date"]
                if date_str:
                    # Ensure timezone-aware datetime
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                return None
            return None
        except Exception as e:
            logger.error("Error getting last sync date", error=str(e))
            return None
    
    async def cleanup_old_sync_records(self, days_to_keep: int = 30):
        """Clean up old synchronization records using Supabase."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            result = db_manager.supabase.table("sync_status").delete().lt("started_at", cutoff_date.isoformat()).in_("status", ["completed", "failed", "cancelled"]).execute()
            
            deleted_count = len(result.data) if result.data else 0
            logger.info(f"Cleaned up {deleted_count} old sync records")
        except Exception as e:
            logger.error("Error cleaning up old sync records", error=str(e))
        return deleted_count


# Scheduled sync task
async def scheduled_sync_task():
    """Background task for scheduled synchronization."""
    sync_service = SyncService()
    
    while True:
        try:
            if await sync_service.should_run_sync():
                logger.info("Starting scheduled synchronization")
                sync_trigger = SyncTrigger(sync_type="incremental")
                await sync_service.trigger_sync(sync_trigger)
                
                # Wait for sync to complete
                while sync_service.is_sync_running():
                    await asyncio.sleep(10)
            
            # Clean up old sync records weekly
            if datetime.now(timezone.utc).hour == 2:  # Run at 2 AM
                await sync_service.cleanup_old_sync_records()
            
        except Exception as e:
            logger.error("Error in scheduled sync task", error=str(e))
        
        # Wait before next check (check every hour)
        await asyncio.sleep(3600)
