"""
CVE service for data processing, validation, and database operations.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from decimal import Decimal

import structlog

from app.core.database import db_manager
from app.models.cve import (
    CVECreate, CVEUpdate, CVEResponse, CVEFilters, 
    CVEListResponse, CVEStatistics, NVDCVEItem
)

logger = structlog.get_logger(__name__)


class CVEService:
    """Service for managing CVE data operations."""
    
    def __init__(self):
        self.batch_size = 1000
    
    async def create_cve(self, cve_data: CVECreate) -> CVEResponse:
        """Create a new CVE record using Supabase client."""
        try:
            # Prepare data for Supabase insert
            insert_data = {
                "cve_id": cve_data.cve_id,
                "source_identifier": cve_data.source_identifier,
                "vuln_status": cve_data.vuln_status,
                "published": cve_data.published.isoformat() if cve_data.published else None,
                "last_modified": cve_data.last_modified.isoformat() if cve_data.last_modified else None,
                "description": cve_data.description,
                "cvss_v2_score": float(cve_data.cvss_v2_score) if cve_data.cvss_v2_score else None,
                "cvss_v3_score": float(cve_data.cvss_v3_score) if cve_data.cvss_v3_score else None,
                "cvss_v2_vector": cve_data.cvss_v2_vector,
                "cvss_v3_vector": cve_data.cvss_v3_vector,
                "cvss_v2_severity": cve_data.cvss_v2_severity,
                "cvss_v3_severity": cve_data.cvss_v3_severity,
                "cpe_configurations": cve_data.cpe_configurations,
                "cve_references": cve_data.references,
                "weaknesses": cve_data.weaknesses,
                "configurations": cve_data.configurations,
                "raw_data": cve_data.raw_data
            }
            
            # Insert using Supabase client
            result = db_manager.supabase.table("cves").insert(insert_data).execute()
            
            if result.data:
                return self._row_to_cve_response(result.data[0])
            else:
                raise ValueError(f"Failed to create CVE {cve_data.cve_id}")
                
        except Exception as e:
            if "duplicate key" in str(e).lower() or "already exists" in str(e).lower():
                logger.warning(f"CVE {cve_data.cve_id} already exists")
                raise ValueError(f"CVE {cve_data.cve_id} already exists")
            logger.error(f"Error creating CVE {cve_data.cve_id}", error=str(e))
            raise
    
    async def update_cve(self, cve_id: str, cve_data: CVEUpdate) -> Optional[CVEResponse]:
        """Update an existing CVE record using Supabase."""
        try:
            # Build update data based on provided fields
            update_data = {}
            
            for field, value in cve_data.dict(exclude_unset=True).items():
                # Convert datetime and Decimal objects for JSON serialization
                if isinstance(value, datetime):
                    update_data[field] = value.isoformat()
                elif isinstance(value, Decimal):
                    # Convert Decimal to float for JSON serialization
                    update_data[field] = float(value)
                else:
                    update_data[field] = value
            
            if not update_data:
                # No fields to update
                return await self.get_cve_by_id(cve_id)
            
            # Add updated_at timestamp
            update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
            
            # Update using Supabase
            result = db_manager.supabase.table("cves").update(update_data).eq("cve_id", cve_id).execute()
            
            if result.data:
                return self._row_to_cve_response(result.data[0])
            return None
            
        except Exception as e:
            logger.error(f"Error updating CVE {cve_id}", error=str(e))
            return None
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[CVEResponse]:
        """Get a CVE by its ID using Supabase client."""
        try:
            result = db_manager.supabase.table("cves").select("*").eq("cve_id", cve_id).execute()
            
            if result.data and len(result.data) > 0:
                return self._row_to_cve_response(result.data[0])
            return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}", error=str(e))
            return None
    
    async def get_cves(
        self, 
        filters: CVEFilters, 
        page: int = 1, 
        size: int = 20
    ) -> CVEListResponse:
        """Get CVEs with filtering and pagination using Supabase."""
        try:
            # Start with base query
            query = db_manager.supabase.table("cves").select("*")
            
            # Apply filters
            if filters.cve_id:
                query = query.eq("cve_id", filters.cve_id)
            
            if filters.year:
                # Note: This might need adjustment based on how dates are stored
                start_date = f"{filters.year}-01-01"
                end_date = f"{filters.year}-12-31"
                query = query.gte("published", start_date).lte("published", end_date)
            
            if filters.min_score is not None:
                # Simple filter on CVSS v3 score (can be enhanced later)
                query = query.gte("cvss_v3_score", filters.min_score)
            
            if filters.max_score is not None:
                query = query.lte("cvss_v3_score", filters.max_score)
            
            if filters.severity:
                query = query.eq("cvss_v3_severity", filters.severity.upper())
            
            if filters.vuln_status:
                query = query.eq("vuln_status", filters.vuln_status)
            
            if filters.modified_since:
                query = query.gte("last_modified", filters.modified_since.isoformat())
            
            if filters.published_since:
                query = query.gte("published", filters.published_since.isoformat())
            
            if filters.keyword:
                # Simple text search in description
                query = query.ilike("description", f"%{filters.keyword}%")
            
            # Apply sorting
            sort_field = filters.sort or "last_modified"
            sort_desc = (filters.order or "desc").lower() == "desc"
            query = query.order(sort_field, desc=sort_desc)
            
            # Apply pagination
            offset = (page - 1) * size
            query = query.range(offset, offset + size - 1)
            
            # Execute query
            result = query.execute()
            
            # Convert to response objects
            items = [self._row_to_cve_response(row) for row in result.data] if result.data else []
            
            # Get total count for pagination (simplified - could be optimized)
            count_result = db_manager.supabase.table("cves").select("count", count="exact").execute()
            total = count_result.count if count_result.count is not None else 0
            
            return CVEListResponse(
                items=items,
                total=total,
                page=page,
                size=size,
                has_next=(page * size) < total,
                has_prev=page > 1
            )
        except Exception as e:
            logger.error("Error fetching CVEs", error=str(e))
            return CVEListResponse(
                items=[],
                total=0,
                page=page,
                size=size,
                has_next=False,
                has_prev=False
            )
    
    async def get_cves_by_year(self, year: int) -> List[CVEResponse]:
        """Get all CVEs published in a specific year using Supabase."""
        try:
            start_date = f"{year}-01-01"
            end_date = f"{year}-12-31"
            
            result = db_manager.supabase.table("cves").select("*").gte("published", start_date).lte("published", end_date).order("published", desc=True).execute()
            
            return [self._row_to_cve_response(row) for row in result.data] if result.data else []
        except Exception as e:
            logger.error(f"Error fetching CVEs for year {year}", error=str(e))
            return []
    
    async def get_cves_by_score_range(
        self, 
        min_score: float, 
        max_score: float
    ) -> List[CVEResponse]:
        """Get CVEs within a CVSS score range using Supabase."""
        try:
            # Query for CVEs with v3 scores in range
            result = db_manager.supabase.table("cves").select("*").gte("cvss_v3_score", min_score).lte("cvss_v3_score", max_score).order("cvss_v3_score", desc=True).execute()
            
            return [self._row_to_cve_response(row) for row in result.data] if result.data else []
        except Exception as e:
            logger.error(f"Error fetching CVEs by score range {min_score}-{max_score}", error=str(e))
            return []
    
    async def get_recent_cves(self, days: int) -> List[CVEResponse]:
        """Get CVEs modified in the last N days using Supabase."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            result = db_manager.supabase.table("cves").select("*").gte("last_modified", cutoff_date.isoformat()).order("last_modified", desc=True).execute()
            
            return [self._row_to_cve_response(row) for row in result.data] if result.data else []
        except Exception as e:
            logger.error(f"Error fetching recent CVEs for {days} days", error=str(e))
            return []
    
    async def search_cves(self, search_term: str, limit: int = 100) -> List[CVEResponse]:
        """Full-text search for CVEs using Supabase."""
        try:
            # Simple text search in description field
            result = db_manager.supabase.table("cves").select("*").ilike("description", f"%{search_term}%").limit(limit).order("last_modified", desc=True).execute()
            
            return [self._row_to_cve_response(row) for row in result.data] if result.data else []
        except Exception as e:
            logger.error(f"Error searching CVEs for term '{search_term}'", error=str(e))
            return []
    
    async def delete_cve(self, cve_id: str) -> bool:
        """Delete a CVE record using Supabase."""
        try:
            result = db_manager.supabase.table("cves").delete().eq("cve_id", cve_id).execute()
            return bool(result.data)
        except Exception as e:
            logger.error(f"Error deleting CVE {cve_id}", error=str(e))
            return False
    
    async def get_statistics(self) -> CVEStatistics:
        """Get CVE statistics using Supabase."""
        try:
            # Get total count
            total_result = db_manager.supabase.table("cves").select("count", count="exact").execute()
            total_cves = total_result.count if total_result.count is not None else 0
            
            # For now, return basic stats - can be enhanced later with more complex queries
            return CVEStatistics(
                total_cves=total_cves, 
                critical_cves=0, 
                high_cves=0, 
                medium_cves=0,
                low_cves=0, 
                unscored_cves=0, 
                last_updated=datetime.now(timezone.utc),
                today_published=0, 
                week_published=0, 
                month_published=0
            )
        except Exception as e:
            logger.error("Error getting CVE statistics", error=str(e))
            return CVEStatistics(
                total_cves=0, critical_cves=0, high_cves=0, medium_cves=0,
                low_cves=0, unscored_cves=0, last_updated=None,
                today_published=0, week_published=0, month_published=0
            )
    
    async def upsert_cve_from_nvd(self, nvd_item: NVDCVEItem) -> Tuple[str, bool]:
        """
        Insert or update CVE from NVD data.
        Returns (cve_id, was_created).
        """
        try:
            cve_data = self._process_nvd_item(nvd_item)
            
            # Check if CVE exists
            existing_cve = await self.get_cve_by_id(cve_data.cve_id)
            
            if existing_cve:
                # Update if newer data
                if (cve_data.last_modified and existing_cve.last_modified and 
                    cve_data.last_modified > existing_cve.last_modified):
                    
                    update_data = CVEUpdate(**cve_data.dict(exclude={'cve_id'}))
                    await self.update_cve(cve_data.cve_id, update_data)
                    logger.debug(f"Updated CVE {cve_data.cve_id}")
                    return cve_data.cve_id, False
                else:
                    logger.debug(f"CVE {cve_data.cve_id} is up to date")
                    return cve_data.cve_id, False
            else:
                # Create new CVE
                await self.create_cve(cve_data)
                logger.debug(f"Created CVE {cve_data.cve_id}")
                return cve_data.cve_id, True
                
        except Exception as e:
            logger.error(f"Error upserting CVE from NVD data", error=str(e))
            raise
    
    async def upsert_cves_batch(self, nvd_items: List[NVDCVEItem]) -> Tuple[int, int]:
        """
        Batch upsert CVEs from NVD data.
        Returns (created_count, updated_count).
        """
        created_count = 0
        updated_count = 0
        
        # Process each CVE item (Supabase handles individual operations atomically)
        for nvd_item in nvd_items:
            try:
                cve_id, was_created = await self.upsert_cve_from_nvd(nvd_item)
                if was_created:
                    created_count += 1
                else:
                    updated_count += 1
            except Exception as e:
                logger.error(f"Error processing CVE in batch", error=str(e))
                continue
        
        return created_count, updated_count
    
    def _process_nvd_item(self, nvd_item: NVDCVEItem) -> CVECreate:
        """Process NVD CVE item into CVECreate model with data cleansing."""
        cve_data = nvd_item.cve
        cve_id = cve_data['id']
        
        # Extract basic information
        source_identifier = cve_data.get('sourceIdentifier', '')
        vuln_status = cve_data.get('vulnStatus', '')
        
        # Parse dates
        published = self._parse_date(cve_data.get('published'))
        last_modified = self._parse_date(cve_data.get('lastModified'))
        
        # Extract description (prefer English)
        description = self._extract_description(cve_data.get('descriptions', []))
        
        # Extract CVSS scores
        cvss_v2_score, cvss_v2_vector, cvss_v2_severity = self._extract_cvss_v2(cve_data.get('metrics', {}))
        cvss_v3_score, cvss_v3_vector, cvss_v3_severity = self._extract_cvss_v3(cve_data.get('metrics', {}))
        
        # Extract configurations (affected systems)
        configurations = cve_data.get('configurations', [])
        
        # Extract references
        references = cve_data.get('references', [])
        
        # Extract weaknesses (CWE)
        weaknesses = cve_data.get('weaknesses', [])
        
        return CVECreate(
            cve_id=cve_id,
            source_identifier=source_identifier,
            vuln_status=vuln_status,
            published=published,
            last_modified=last_modified,
            description=description,
            cvss_v2_score=Decimal(str(cvss_v2_score)) if cvss_v2_score else None,
            cvss_v3_score=Decimal(str(cvss_v3_score)) if cvss_v3_score else None,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v3_severity=cvss_v3_severity,
            cpe_configurations=configurations,
            references=references,
            weaknesses=weaknesses,
            configurations=configurations,
            raw_data=cve_data
        )
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime object."""
        if not date_str:
            return None
        try:
            # Handle NVD date format
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            # Ensure timezone-aware datetime
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse date: {date_str}")
            return None
    
    def _extract_description(self, descriptions: List[Dict[str, Any]]) -> Optional[str]:
        """Extract description, preferring English."""
        if not descriptions:
            return None
        
        # Look for English description first
        for desc in descriptions:
            if desc.get('lang', '').lower() == 'en':
                return desc.get('value', '').strip()
        
        # Fallback to first available description
        if descriptions:
            return descriptions[0].get('value', '').strip()
        
        return None
    
    def _extract_cvss_v2(self, metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
        """Extract CVSS v2 information."""
        cvss_v2_metrics = metrics.get('cvssMetricV2', [])
        if not cvss_v2_metrics:
            return None, None, None
        
        # Use the first (primary) metric
        metric = cvss_v2_metrics[0]
        cvss_data = metric.get('cvssData', {})
        
        score = cvss_data.get('baseScore')
        vector = cvss_data.get('vectorString')
        severity = cvss_data.get('baseSeverity', '').upper()
        
        return score, vector, severity
    
    def _extract_cvss_v3(self, metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
        """Extract CVSS v3 information."""
        # Try v3.1 first, then v3.0
        for version in ['cvssMetricV31', 'cvssMetricV30']:
            cvss_metrics = metrics.get(version, [])
            if cvss_metrics:
                # Use the first (primary) metric
                metric = cvss_metrics[0]
                cvss_data = metric.get('cvssData', {})
                
                score = cvss_data.get('baseScore')
                vector = cvss_data.get('vectorString')
                severity = cvss_data.get('baseSeverity', '').upper()
                
                return score, vector, severity
        
        return None, None, None
    
    def _row_to_cve_response(self, row: dict) -> CVEResponse:
        """Convert database row to CVEResponse model."""
        return CVEResponse(
            id=row['id'],
            cve_id=row['cve_id'],
            source_identifier=row['source_identifier'],
            vuln_status=row['vuln_status'],
            published=row['published'],
            last_modified=row['last_modified'],
            description=row['description'],
            cvss_v2_score=row['cvss_v2_score'],
            cvss_v3_score=row['cvss_v3_score'],
            cvss_v2_vector=row['cvss_v2_vector'],
            cvss_v3_vector=row['cvss_v3_vector'],
            cvss_v2_severity=row['cvss_v2_severity'],
            cvss_v3_severity=row['cvss_v3_severity'],
            cpe_configurations=row['cpe_configurations'],
            references=row['cve_references'],
            weaknesses=row['weaknesses'],
            configurations=row['configurations'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            descriptions=[]  # Will be populated from description field
        )
