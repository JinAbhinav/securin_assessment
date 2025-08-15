"""
Application configuration settings.
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application Settings
    app_name: str = "CVE Assessment API"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "production"
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Supabase Configuration
    supabase_url: str
    supabase_key: str
    supabase_service_key: Optional[str] = None
    
    # Database Configuration (alternative direct connection)
    database_url: Optional[str] = None
    
    # NVD API Configuration
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: Optional[str] = None
    nvd_rate_limit_delay: float = 1.0
    nvd_max_retries: int = 3
    nvd_results_per_page: int = 2000
    nvd_timeout: int = 30
    
    # Sync Configuration
    sync_enabled: bool = True
    sync_interval_hours: int = 24
    sync_full_refresh_days: int = 7
    sync_batch_size: int = 1000
    

    
    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # CORS Settings
    allowed_origins: List[str] = ["*"]
    allowed_methods: List[str] = ["GET", "POST", "PUT", "DELETE"]
    allowed_headers: List[str] = ["*"]
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    # Monitoring
    sentry_dsn: Optional[str] = None
    health_check_timeout: int = 10  # seconds
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False
    }
    
    @field_validator("allowed_origins", mode='before')
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string from environment
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @field_validator("secret_key")
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"
    
    @property
    def database_connection_url(self) -> str:
        """Get the database connection URL."""
        if self.database_url:
            return self.database_url
        # Construct from Supabase URL if direct URL not provided
        return f"postgresql://postgres:[PASSWORD]@db.{self.supabase_url.split('//')[-1].split('.')[0]}.supabase.co:5432/postgres"


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()


# Global settings instance
settings = get_settings()
