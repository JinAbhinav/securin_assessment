"""
NVD (National Vulnerability Database) API client for fetching CVE data.
"""
import asyncio
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, AsyncGenerator
from urllib.parse import urljoin
import structlog

from app.core.config import settings
from app.models.cve import NVDResponse, NVDCVEItem

logger = structlog.get_logger(__name__)


class NVDAPIError(Exception):
    """Custom exception for NVD API errors."""
    pass


class RateLimitError(NVDAPIError):
    """Exception raised when rate limit is exceeded."""
    pass


class NVDClient:
    """Client for interacting with the NVD CVE API."""
    
    def __init__(self):
        self.base_url = settings.nvd_api_base_url
        self.api_key = settings.nvd_api_key
        self.rate_limit_delay = settings.nvd_rate_limit_delay
        self.max_retries = settings.nvd_max_retries
        self.results_per_page = settings.nvd_results_per_page
        self.timeout = settings.nvd_timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_session()
    
    async def create_session(self):
        """Create aiohttp session with appropriate headers."""
        headers = {
            'User-Agent': f'{settings.app_name}/{settings.app_version}',
            'Accept': 'application/json',
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        connector = aiohttp.TCPConnector(
            limit=10,  # Total connection pool size
            limit_per_host=5,  # Per-host connection limit
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=timeout
        )
        
        logger.info("NVD API client session created")
    
    async def close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None
            logger.info("NVD API client session closed")
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request to NVD API with error handling and retries."""
        if not self.session:
            await self.create_session()
        
        url = urljoin(self.base_url, endpoint)
        
        for attempt in range(self.max_retries + 1):
            try:
                # Apply rate limiting
                if attempt > 0:
                    delay = self.rate_limit_delay * (2 ** (attempt - 1))  # Exponential backoff
                    await asyncio.sleep(delay)
                
                logger.debug("Making NVD API request", url=url, params=params, attempt=attempt + 1)
                
                async with self.session.get(url, params=params) as response:
                    # Handle rate limiting
                    if response.status == 403:
                        rate_limit_delay = float(response.headers.get('X-RateLimit-Reset', self.rate_limit_delay))
                        if attempt < self.max_retries:
                            logger.warning(
                                "Rate limit exceeded, retrying",
                                delay=rate_limit_delay,
                                attempt=attempt + 1
                            )
                            await asyncio.sleep(rate_limit_delay)
                            continue
                        else:
                            raise RateLimitError("Rate limit exceeded and max retries reached")
                    
                    # Handle other HTTP errors
                    if response.status >= 400:
                        error_text = await response.text()
                        logger.error(
                            "NVD API request failed",
                            status=response.status,
                            response=error_text,
                            url=url
                        )
                        
                        if response.status >= 500 and attempt < self.max_retries:
                            # Retry on server errors
                            continue
                        
                        raise NVDAPIError(f"HTTP {response.status}: {error_text}")
                    
                    # Parse successful response
                    data = await response.json()
                    
                    logger.debug(
                        "NVD API request successful",
                        status=response.status,
                        total_results=data.get('totalResults', 0),
                        results_count=data.get('resultsPerPage', 0)
                    )
                    
                    return data
            
            except aiohttp.ClientError as e:
                logger.error("Network error during NVD API request", error=str(e), attempt=attempt + 1)
                if attempt < self.max_retries:
                    continue
                raise NVDAPIError(f"Network error after {self.max_retries + 1} attempts: {str(e)}")
            
            except asyncio.TimeoutError:
                logger.error("Timeout during NVD API request", attempt=attempt + 1)
                if attempt < self.max_retries:
                    continue
                raise NVDAPIError(f"Timeout after {self.max_retries + 1} attempts")
        
        raise NVDAPIError("Max retries exceeded")
    
    async def get_cves(
        self,
        start_index: int = 0,
        results_per_page: Optional[int] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        cve_id: Optional[str] = None,
        cpename: Optional[str] = None,
        cvss_v2_severity: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        keyword_search: Optional[str] = None,
        keyword_exact_match: bool = False,
        has_cert_alerts: Optional[bool] = None,
        has_cert_notes: Optional[bool] = None,
        has_kev: Optional[bool] = None,
        has_oval: Optional[bool] = None
    ) -> NVDResponse:
        """
        Fetch CVEs from NVD API with various filtering options.
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per page (max 2000)
            pub_start_date: Published start date filter
            pub_end_date: Published end date filter
            last_mod_start_date: Last modified start date filter
            last_mod_end_date: Last modified end date filter
            cve_id: Specific CVE ID to fetch
            cpename: CPE name filter
            cvss_v2_severity: CVSS v2 severity filter
            cvss_v3_severity: CVSS v3 severity filter
            keyword_search: Keyword search in description
            keyword_exact_match: Whether keyword search should be exact match
            has_cert_alerts: Filter for CVEs with CERT alerts
            has_cert_notes: Filter for CVEs with CERT notes
            has_kev: Filter for CVEs in KEV catalog
            has_oval: Filter for CVEs with OVAL data
        
        Returns:
            NVDResponse object containing CVE data
        """
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page or self.results_per_page
        }
        
        # Date filters
        if pub_start_date:
            params['pubStartDate'] = pub_start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        if pub_end_date:
            params['pubEndDate'] = pub_end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        if last_mod_start_date:
            params['lastModStartDate'] = last_mod_start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        if last_mod_end_date:
            params['lastModEndDate'] = last_mod_end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        # Other filters
        if cve_id:
            params['cveId'] = cve_id
        if cpename:
            params['cpeName'] = cpename
        if cvss_v2_severity:
            params['cvssV2Severity'] = cvss_v2_severity
        if cvss_v3_severity:
            params['cvssV3Severity'] = cvss_v3_severity
        if keyword_search:
            params['keywordSearch'] = keyword_search
            params['keywordExactMatch'] = keyword_exact_match
        if has_cert_alerts is not None:
            params['hasCertAlerts'] = str(has_cert_alerts).lower()
        if has_cert_notes is not None:
            params['hasCertNotes'] = str(has_cert_notes).lower()
        if has_kev is not None:
            params['hasKev'] = str(has_kev).lower()
        if has_oval is not None:
            params['hasOval'] = str(has_oval).lower()
        
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        data = await self._make_request('', params)
        return NVDResponse(**data)
    
    async def get_all_cves(
        self,
        max_results: Optional[int] = None,
        **kwargs
    ) -> AsyncGenerator[NVDCVEItem, None]:
        """
        Fetch all CVEs with pagination, yielding individual CVE items.
        
        Args:
            max_results: Maximum number of CVEs to fetch (None for all)
            **kwargs: Additional filters passed to get_cves
        
        Yields:
            Individual NVDCVEItem objects
        """
        start_index = 0
        fetched_count = 0
        
        while True:
            try:
                # Adjust results per page if max_results is specified
                if max_results and (max_results - fetched_count) < self.results_per_page:
                    kwargs['results_per_page'] = max_results - fetched_count
                
                response = await self.get_cves(start_index=start_index, **kwargs)
                
                if not response.vulnerabilities:
                    break
                
                for vuln in response.vulnerabilities:
                    yield vuln
                    fetched_count += 1
                    
                    if max_results and fetched_count >= max_results:
                        return
                
                # Check if we've fetched all available results
                if start_index + len(response.vulnerabilities) >= response.total_results:
                    break
                
                start_index += len(response.vulnerabilities)
                
                # Rate limiting between requests
                await asyncio.sleep(self.rate_limit_delay)
                
            except Exception as e:
                logger.error(
                    "Error fetching CVEs batch",
                    start_index=start_index,
                    error=str(e)
                )
                raise
        
        logger.info(f"Fetched {fetched_count} CVEs from NVD API")
    
    async def get_recent_cves(self, days: int = 7) -> AsyncGenerator[NVDCVEItem, None]:
        """
        Fetch CVEs modified in the last N days.
        
        Args:
            days: Number of days to look back
        
        Yields:
            Individual NVDCVEItem objects
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        logger.info(f"Fetching CVEs modified since {start_date.isoformat()}")
        
        async for cve in self.get_all_cves(
            last_mod_start_date=start_date,
            last_mod_end_date=end_date
        ):
            yield cve
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[NVDCVEItem]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
        
        Returns:
            NVDCVEItem if found, None otherwise
        """
        try:
            response = await self.get_cves(cve_id=cve_id)
            if response.vulnerabilities:
                return response.vulnerabilities[0]
            return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}", error=str(e))
            raise
    
    async def health_check(self) -> bool:
        """
        Perform a health check on the NVD API.
        
        Returns:
            True if API is accessible, False otherwise
        """
        try:
            # Fetch a small number of recent CVEs as a health check
            response = await self.get_cves(results_per_page=1)
            return response.total_results > 0
        except Exception as e:
            logger.error("NVD API health check failed", error=str(e))
            return False
