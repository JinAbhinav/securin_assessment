"""
Pydantic models for CVE data structures.
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, ValidationInfo
from decimal import Decimal


class CVSSMetric(BaseModel):
    """CVSS metric information."""
    version: str
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    
    class Config:
        extra = "allow"


class CPEMatch(BaseModel):
    """CPE (Common Platform Enumeration) match criteria."""
    vulnerable: bool
    criteria: str
    version_start_excluding: Optional[str] = None
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    
    class Config:
        extra = "allow"


class Node(BaseModel):
    """Configuration node containing CPE matches."""
    operator: str
    negate: Optional[bool] = False
    cpe_match: List[CPEMatch] = []
    
    class Config:
        extra = "allow"


class Configuration(BaseModel):
    """CVE configuration containing affected systems."""
    nodes: List[Node] = []
    
    class Config:
        extra = "allow"


class Reference(BaseModel):
    """CVE reference information."""
    url: str
    source: Optional[str] = None
    tags: List[str] = []
    
    class Config:
        extra = "allow"


class WeaknessDescription(BaseModel):
    """CWE weakness description."""
    lang: str
    value: str


class Weakness(BaseModel):
    """CWE weakness information."""
    source: str
    type: str
    description: List[WeaknessDescription]
    
    class Config:
        extra = "allow"


class VendorComment(BaseModel):
    """Vendor comment on CVE."""
    organization: str
    comment: str
    last_modified: datetime


class CVEDescription(BaseModel):
    """CVE description in multiple languages."""
    lang: str
    value: str


class CVEBase(BaseModel):
    """Base CVE model with common fields."""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    descriptions: List[CVEDescription] = []
    
    @field_validator('cve_id')
    def validate_cve_id(cls, v):
        if not v.startswith('CVE-'):
            raise ValueError('CVE ID must start with "CVE-"')
        return v.upper()


class CVECreate(CVEBase):
    """Model for creating a new CVE record."""
    cvss_v2_score: Optional[Decimal] = Field(None, ge=0, le=10)
    cvss_v3_score: Optional[Decimal] = Field(None, ge=0, le=10)
    cvss_v2_vector: Optional[str] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_severity: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    description: Optional[str] = None
    cpe_configurations: Optional[List[Dict[str, Any]]] = None
    references: Optional[List[Dict[str, Any]]] = None
    weaknesses: Optional[List[Dict[str, Any]]] = None
    configurations: Optional[List[Dict[str, Any]]] = None
    raw_data: Optional[Dict[str, Any]] = None


class CVEUpdate(BaseModel):
    """Model for updating an existing CVE record."""
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    description: Optional[str] = None
    cvss_v2_score: Optional[Decimal] = Field(None, ge=0, le=10)
    cvss_v3_score: Optional[Decimal] = Field(None, ge=0, le=10)
    cvss_v2_vector: Optional[str] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_severity: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    cpe_configurations: Optional[List[Dict[str, Any]]] = None
    references: Optional[List[Dict[str, Any]]] = None
    weaknesses: Optional[List[Dict[str, Any]]] = None
    configurations: Optional[List[Dict[str, Any]]] = None
    raw_data: Optional[Dict[str, Any]] = None


class CVEResponse(CVEBase):
    """Model for CVE API responses."""
    id: int
    description: Optional[str] = None
    cvss_v2_score: Optional[Decimal] = None
    cvss_v3_score: Optional[Decimal] = None
    cvss_v2_vector: Optional[str] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_severity: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    cpe_configurations: Optional[List[Dict[str, Any]]] = None
    references: Optional[List[Dict[str, Any]]] = None
    weaknesses: Optional[List[Dict[str, Any]]] = None
    configurations: Optional[List[Dict[str, Any]]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CVEListResponse(BaseModel):
    """Model for paginated CVE list responses."""
    items: List[CVEResponse]
    total: int
    page: int
    size: int
    has_next: bool
    has_prev: bool


class CVEFilters(BaseModel):
    """Model for CVE filtering and sorting parameters."""
    cve_id: Optional[str] = None
    year: Optional[int] = Field(None, ge=1999, le=2030)
    min_score: Optional[float] = Field(None, ge=0, le=10)
    max_score: Optional[float] = Field(None, ge=0, le=10)
    severity: Optional[str] = None
    vuln_status: Optional[str] = None
    modified_since: Optional[datetime] = None
    published_since: Optional[datetime] = None
    keyword: Optional[str] = None
    sort: Optional[str] = "last_modified"
    order: Optional[str] = "desc"
    
    @field_validator('max_score')
    def validate_score_range(cls, v, info: ValidationInfo):
        min_score = info.data.get('min_score')
        if min_score is not None and v is not None and v < min_score:
            raise ValueError('max_score must be greater than or equal to min_score')
        return v


class SyncStatus(BaseModel):
    """Model for synchronization status."""
    id: int
    sync_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_records: int = 0
    processed_records: int = 0
    new_records: int = 0
    updated_records: int = 0
    error_message: Optional[str] = None
    last_modified_date: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class SyncTrigger(BaseModel):
    """Model for triggering synchronization."""
    sync_type: str = Field("incremental", pattern="^(full|incremental)$")
    force: bool = False


class CVEStatistics(BaseModel):
    """Model for CVE statistics."""
    total_cves: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    unscored_cves: int
    last_updated: Optional[datetime]
    today_published: int
    week_published: int
    month_published: int


class CVEYearlyStats(BaseModel):
    """Model for yearly CVE statistics."""
    year: int
    total_count: int
    avg_score: Optional[float]
    max_score: Optional[float]
    critical_count: int
    high_count: int


class HealthCheck(BaseModel):
    """Model for health check responses."""
    status: str
    timestamp: datetime
    database_connected: bool
    last_sync: Optional[datetime] = None
    total_cves: int = 0
    version: str = "1.0.0"


class ErrorResponse(BaseModel):
    """Model for error responses."""
    detail: str
    code: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# NVD API Response Models
class NVDCVEItem(BaseModel):
    """Model for individual CVE item from NVD API."""
    cve: Dict[str, Any]
    
    class Config:
        extra = "allow"


class NVDResponse(BaseModel):
    """Model for NVD API response."""
    result_count: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: List[NVDCVEItem] = []
    
    class Config:
        populate_by_name = True
        extra = "allow"
