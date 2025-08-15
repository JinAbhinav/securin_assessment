"""
FastAPI application entry point for CVE Assessment API.
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
import structlog
import uvicorn

from app.core.config import settings
from app.core.database import init_database, close_database, HealthCheck
from app.api.v1.cves import router as cve_router
from app.api.v1.sync import router as sync_router
from app.services.sync_service import scheduled_sync_task
from app.models.cve import ErrorResponse, HealthCheck as HealthCheckModel
from datetime import datetime, timezone

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if settings.log_format == "json" else structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting CVE Assessment API", version=settings.app_version)
    
    try:
        # Initialize database
        await init_database()
        logger.info("Database initialized successfully")
        
        # Start background sync task if enabled (temporarily disabled for Supabase migration)
        sync_task = None
        logger.info("Background sync temporarily disabled - migrating to Supabase operations")
        
        yield
        
    except Exception as e:
        logger.error("Error during application startup", error=str(e))
        raise
    
    finally:
        # Shutdown
        logger.info("Shutting down CVE Assessment API")
        
        # Cancel background tasks
        if settings.sync_enabled and sync_task:
            sync_task.cancel()
            try:
                await sync_task
            except asyncio.CancelledError:
                pass
            logger.info("Background sync task stopped")
        
        # Close database connections
        await close_database()
        logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    A comprehensive CVE (Common Vulnerabilities and Exposures) management system 
    with real-time data synchronization from the National Vulnerability Database (NVD).
    
    ## Features
    
    * **CVE Management**: Complete CRUD operations for CVE records
    * **Advanced Filtering**: Filter CVEs by ID, year, CVSS score, and modification date
    * **Full-text Search**: Search CVEs by keywords in descriptions
    * **Data Synchronization**: Automated sync with NVD API
    * **Statistics**: Comprehensive CVE statistics and analytics
    * **RESTful API**: Clean, documented REST endpoints
    
    ## Data Sources
    
    * [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
    * [CVE API v2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
    """,
    contact={
        "name": "CVE Assessment API",
        "url": "https://github.com/your-repo/cve-assessment",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
    debug=settings.debug
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=settings.allowed_methods,
    allow_headers=settings.allowed_headers,
)

# Mount static files for frontend
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include API routers
app.include_router(cve_router, prefix="/api/v1")
app.include_router(sync_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to documentation."""
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthCheckModel, responses={500: {"model": ErrorResponse}}, tags=["Health"])
async def health_check():
    """
    Application health check endpoint.
    
    Returns the overall health status of the application including:
    - Database connectivity
    - Last synchronization status
    - Basic statistics
    """
    try:
        # Check database connectivity
        db_connected = await HealthCheck.check_supabase_connection()
        
        # Get database info
        db_info = await HealthCheck.get_database_info()
        
        status = "healthy" if db_connected else "unhealthy"
        
        return HealthCheckModel(
            status=status,
            timestamp=datetime.now(timezone.utc),
            database_connected=db_connected,
            last_sync=db_info.get("last_sync"),
            total_cves=db_info.get("total_cves", 0),
            version=settings.app_version
        )
    
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return HealthCheckModel(
            status="unhealthy",
            timestamp=datetime.now(timezone.utc),
            database_connected=False,
            total_cves=0,
            version=settings.app_version
        )


@app.get("/info", responses={500: {"model": ErrorResponse}}, tags=["Info"])
async def app_info():
    """
    Get application information and configuration.
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "debug": settings.debug,
        "sync_enabled": settings.sync_enabled,
        "sync_interval_hours": settings.sync_interval_hours,
        "nvd_api_url": settings.nvd_api_base_url,
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json"
        },
        "frontend": "/static/index.html"
    }


# Global exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    logger.warning("Request validation error", errors=exc.errors(), body=exc.body)
    
    error_details = []
    for error in exc.errors():
        error_details.append({
            "field": " -> ".join([str(loc) for loc in error["loc"]]),
            "message": error["msg"],
            "type": error["type"]
        })
    
    error_response = ErrorResponse(
        detail="Request validation failed",
        code="VALIDATION_ERROR"
    ).model_dump(mode='json')
    error_response["errors"] = error_details
    
    return JSONResponse(
        status_code=422,
        content=error_response
    )


@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors."""
    logger.error("Internal server error", error=str(exc), path=request.url.path)
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            detail="Internal server error",
            code="INTERNAL_ERROR"
        ).model_dump(mode='json')
    )


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Request/response logging middleware."""
    start_time = time.time()
    
    # Log request
    logger.info(
        "Request started",
        method=request.method,
        path=request.url.path,
        query_params=str(request.query_params)
    )
    
    # Process request
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(
        "Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=round(process_time, 4)
    )
    
    return response


# Required imports
from datetime import datetime
import time


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
