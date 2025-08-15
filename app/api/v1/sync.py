"""
Synchronization API endpoints for managing CVE data updates.
"""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse
import structlog

from app.services.sync_service import SyncService
from app.core.database import HealthCheck
from app.models.cve import SyncStatus, SyncTrigger, ErrorResponse, HealthCheck as HealthCheckModel

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/sync", tags=["Synchronization"])


def get_sync_service() -> SyncService:
    """Dependency for getting sync service."""
    return SyncService()


@router.post("/", response_model=dict, status_code=202, responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def trigger_sync(
    sync_request: SyncTrigger,
    background_tasks: BackgroundTasks,
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Trigger a CVE data synchronization.
    
    - **sync_type**: Type of synchronization ('full' or 'incremental')
    - **force**: Force sync even if one is already running
    
    Returns a sync ID to track the operation status.
    """
    try:
        sync_id = await sync_service.trigger_sync(sync_request)
        
        logger.info(
            "Synchronization triggered",
            sync_id=sync_id,
            sync_type=sync_request.sync_type,
            force=sync_request.force
        )
        
        return {
            "message": f"{sync_request.sync_type.title()} synchronization started",
            "sync_id": sync_id,
            "sync_type": sync_request.sync_type
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Error triggering synchronization", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/status", response_model=SyncStatus, responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_sync_status(
    sync_id: Optional[int] = Query(None, description="Specific sync ID to check"),
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Get the status of a synchronization operation.
    
    - **sync_id**: Specific sync ID to check (optional, defaults to latest)
    """
    try:
        status = await sync_service.get_sync_status(sync_id)
        
        if not status:
            raise HTTPException(
                status_code=404,
                detail="Sync status not found"
            )
        
        logger.debug("Sync status retrieved", sync_id=status.id, status=status.status)
        return status
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving sync status", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/status/{sync_id}", response_model=SyncStatus, responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_specific_sync_status(
    sync_id: int,
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Get the status of a specific synchronization operation.
    
    - **sync_id**: Sync ID to check
    """
    try:
        status = await sync_service.get_sync_status(sync_id)
        
        if not status:
            raise HTTPException(
                status_code=404,
                detail=f"Sync with ID {sync_id} not found"
            )
        
        logger.debug("Specific sync status retrieved", sync_id=sync_id, status=status.status)
        return status
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving specific sync status", sync_id=sync_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/history", response_model=List[SyncStatus], responses={500: {"model": ErrorResponse}})
async def get_sync_history(
    limit: int = Query(20, ge=1, le=100, description="Number of records to return"),
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Get synchronization history.
    
    - **limit**: Number of sync records to return (1-100)
    """
    try:
        history = await sync_service.get_sync_history(limit)
        
        logger.debug(f"Retrieved {len(history)} sync history records")
        return history
    
    except Exception as e:
        logger.error("Error retrieving sync history", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/running", response_model=dict, responses={500: {"model": ErrorResponse}})
async def check_sync_running(
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Check if a synchronization is currently running.
    """
    try:
        is_running = sync_service.is_sync_running()
        
        return {
            "is_running": is_running,
            "message": "Synchronization is running" if is_running else "No synchronization running"
        }
    
    except Exception as e:
        logger.error("Error checking sync status", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/cancel", response_model=dict, responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def cancel_sync(
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Cancel the currently running synchronization.
    """
    try:
        cancelled = await sync_service.cancel_running_sync()
        
        if not cancelled:
            raise HTTPException(
                status_code=404,
                detail="No synchronization is currently running"
            )
        
        logger.info("Synchronization cancelled by user request")
        
        return {
            "message": "Synchronization cancelled successfully",
            "cancelled": True
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error cancelling synchronization", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/cleanup", response_model=dict, responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def cleanup_old_sync_records(
    days: int = Query(30, ge=1, le=365, description="Days of records to keep"),
    sync_service: SyncService = Depends(get_sync_service)
):
    """
    Clean up old synchronization records.
    
    - **days**: Number of days of records to keep (1-365)
    """
    try:
        deleted_count = await sync_service.cleanup_old_sync_records(days)
        
        logger.info(f"Cleaned up {deleted_count} old sync records")
        
        return {
            "message": f"Cleaned up {deleted_count} old sync records",
            "deleted_count": deleted_count,
            "days_kept": days
        }
    
    except Exception as e:
        logger.error("Error cleaning up sync records", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/health", response_model=HealthCheckModel, responses={500: {"model": ErrorResponse}})
async def sync_health_check():
    """
    Health check for synchronization system.
    """
    try:
        # Check database connectivity
        db_connected = await HealthCheck.check_supabase_connection()
        
        # Get basic database info
        db_info = await HealthCheck.get_database_info()
        
        # Get latest sync status
        sync_service = SyncService()
        latest_sync = await sync_service.get_sync_status()
        
        status = "healthy" if db_connected else "unhealthy"
        
        health_data = HealthCheckModel(
            status=status,
            timestamp=datetime.now(timezone.utc),
            database_connected=db_connected,
            last_sync=latest_sync.completed_at if latest_sync else None,
            total_cves=db_info.get("total_cves", 0),
            version="1.0.0"
        )
        
        logger.debug("Sync health check completed", status=status)
        return health_data
    
    except Exception as e:
        logger.error("Error in sync health check", error=str(e))
        return HealthCheckModel(
            status="unhealthy",
            timestamp=datetime.now(timezone.utc),
            database_connected=False,
            total_cves=0,
            version="1.0.0"
        )


# Error handlers moved to main app


# Add required import for datetime
from datetime import datetime, timezone
