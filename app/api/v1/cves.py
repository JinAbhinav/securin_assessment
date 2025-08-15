"""
CVE API endpoints for CRUD operations and filtering.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Depends, Path
from fastapi.responses import JSONResponse
import structlog

from app.services.cve_service import CVEService
from app.models.cve import (
    CVEResponse, CVEListResponse, CVEFilters, CVEStatistics,
    CVECreate, CVEUpdate, ErrorResponse
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/cves", tags=["CVEs"])


def get_cve_service() -> CVEService:
    """Dependency for getting CVE service."""
    return CVEService()


@router.get("/", response_model=CVEListResponse, responses={500: {"model": ErrorResponse}})
async def list_cves(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    year: Optional[int] = Query(None, ge=1999, le=2030, description="Filter by publication year"),
    min_score: Optional[float] = Query(None, ge=0, le=10, description="Minimum CVSS score"),
    max_score: Optional[float] = Query(None, ge=0, le=10, description="Maximum CVSS score"),
    severity: Optional[str] = Query(None, description="CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    vuln_status: Optional[str] = Query(None, description="Vulnerability status"),
    modified_since: Optional[datetime] = Query(None, description="CVEs modified since this date"),
    published_since: Optional[datetime] = Query(None, description="CVEs published since this date"),
    keyword: Optional[str] = Query(None, description="Keyword search in description"),
    sort: Optional[str] = Query("last_modified", description="Sort field (last_modified, published, cve_id, cvss_v3_score)"),
    order: Optional[str] = Query("desc", description="Sort order (asc, desc)"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Retrieve a paginated list of CVEs with optional filtering and sorting.
    
    - **page**: Page number (starting from 1)
    - **size**: Number of items per page (1-100)
    - **cve_id**: Filter by specific CVE ID
    - **year**: Filter by publication year
    - **min_score**: Minimum CVSS score filter
    - **max_score**: Maximum CVSS score filter
    - **severity**: Filter by CVSS severity level
    - **vuln_status**: Filter by vulnerability status
    - **modified_since**: Filter CVEs modified since date
    - **published_since**: Filter CVEs published since date
    - **keyword**: Search keyword in CVE description
    - **sort**: Sort field (last_modified, published, cve_id, cvss_v3_score)
    - **order**: Sort order (asc, desc)
    """
    try:
        filters = CVEFilters(
            cve_id=cve_id,
            year=year,
            min_score=min_score,
            max_score=max_score,
            severity=severity,
            vuln_status=vuln_status,
            modified_since=modified_since,
            published_since=published_since,
            keyword=keyword,
            sort=sort,
            order=order
        )
        
        result = await cve_service.get_cves(filters, page, size)
        
        logger.info(
            "CVE list retrieved",
            page=page,
            size=size,
            total=result.total,
            filters=filters.dict(exclude_none=True)
        )
        
        return result
    
    except Exception as e:
        logger.error("Error retrieving CVE list", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/count", response_model=dict, responses={500: {"model": ErrorResponse}})
async def get_cve_count(
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Get total count of CVEs in the database.
    
    Returns:
        dict: {"total": number} - Simple count response
    """
    try:
        stats = await cve_service.get_statistics()
        return {"total": stats.total_cves}
    except Exception as e:
        logger.error("Error getting CVE count", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{cve_id}", response_model=CVEResponse, responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_cve(
    cve_id: str = Path(..., min_length=1, pattern=r"^CVE-\d{4}-\d{4,}$", description="CVE identifier (e.g., CVE-2023-12345)"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Retrieve a specific CVE by its identifier.
    
    - **cve_id**: CVE identifier in format CVE-YYYY-NNNNN
    """
    try:
        cve = await cve_service.get_cve_by_id(cve_id.upper())
        
        if not cve:
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} not found"
            )
        
        logger.info("CVE retrieved", cve_id=cve_id)
        return cve
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving CVE", cve_id=cve_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/year/{year}", response_model=List[CVEResponse], responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_cves_by_year(
    year: int = Path(..., ge=1999, le=2030, description="Publication year"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Retrieve all CVEs published in a specific year.
    
    - **year**: Publication year (1999-2030)
    """
    try:
        cves = await cve_service.get_cves_by_year(year)
        
        logger.info(f"Retrieved {len(cves)} CVEs for year {year}")
        return cves
    
    except Exception as e:
        logger.error("Error retrieving CVEs by year", year=year, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/score/{min_score}/{max_score}", response_model=List[CVEResponse], responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_cves_by_score_range(
    min_score: float = Path(..., ge=0, le=10, description="Minimum CVSS score"),
    max_score: float = Path(..., ge=0, le=10, description="Maximum CVSS score"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Retrieve CVEs within a specific CVSS score range.
    
    - **min_score**: Minimum CVSS score (0.0-10.0)
    - **max_score**: Maximum CVSS score (0.0-10.0)
    """
    try:
        if min_score > max_score:
            raise HTTPException(
                status_code=400,
                detail="min_score cannot be greater than max_score"
            )
        
        cves = await cve_service.get_cves_by_score_range(min_score, max_score)
        
        logger.info(
            f"Retrieved {len(cves)} CVEs with score range {min_score}-{max_score}"
        )
        return cves
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error retrieving CVEs by score range",
            min_score=min_score,
            max_score=max_score,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/modified/{days}", response_model=List[CVEResponse], responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def get_recent_cves(
    days: int = Path(..., ge=1, le=365, description="Number of days to look back"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Retrieve CVEs modified in the last N days.
    
    - **days**: Number of days to look back (1-365)
    """
    try:
        cves = await cve_service.get_recent_cves(days)
        
        logger.info(f"Retrieved {len(cves)} CVEs from last {days} days")
        return cves
    
    except Exception as e:
        logger.error(
            "Error retrieving recent CVEs",
            days=days,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/search/", response_model=List[CVEResponse], responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def search_cves(
    q: str = Query(..., min_length=3, description="Search query"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Full-text search for CVEs in descriptions.
    
    - **q**: Search query (minimum 3 characters)
    - **limit**: Maximum number of results to return
    """
    try:
        cves = await cve_service.search_cves(q, limit)
        
        logger.info(f"Search for '{q}' returned {len(cves)} results")
        return cves
    
    except Exception as e:
        logger.error(
            "Error searching CVEs",
            query=q,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail="Internal server error")



@router.get("/statistics/", response_model=CVEStatistics, responses={500: {"model": ErrorResponse}})
async def get_cve_statistics(
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Get CVE statistics including counts by severity level.
    """
    try:
        stats = await cve_service.get_statistics()
        
        logger.info("CVE statistics retrieved", total_cves=stats.total_cves)
        return stats
    
    except Exception as e:
        logger.error("Error retrieving CVE statistics", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/", response_model=CVEResponse, status_code=201, responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def create_cve(
    cve_data: CVECreate,
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Create a new CVE record.
    
    This endpoint is typically used for manual CVE creation or testing.
    Production data should come through the synchronization process.
    """
    try:
        cve = await cve_service.create_cve(cve_data)
        
        logger.info("CVE created", cve_id=cve.cve_id)
        return cve
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Error creating CVE", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{cve_id}", response_model=CVEResponse, responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def update_cve(
    cve_id: str = Path(..., description="CVE identifier"),
    cve_data: CVEUpdate = ...,
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Update an existing CVE record.
    
    This endpoint is typically used for manual CVE updates or corrections.
    Production data should come through the synchronization process.
    """
    try:
        cve = await cve_service.update_cve(cve_id.upper(), cve_data)
        
        if not cve:
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} not found"
            )
        
        logger.info("CVE updated", cve_id=cve_id)
        return cve
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating CVE", cve_id=cve_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{cve_id}", status_code=204)
async def delete_cve(
    cve_id: str = Path(..., description="CVE identifier"),
    cve_service: CVEService = Depends(get_cve_service)
):
    """
    Delete a CVE record.
    
    Use with caution. This permanently removes the CVE from the database.
    """
    try:
        success = await cve_service.delete_cve(cve_id.upper())
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} not found"
            )
        
        logger.info("CVE deleted", cve_id=cve_id)
        return
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting CVE", cve_id=cve_id, error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


# Error handlers moved to main app
