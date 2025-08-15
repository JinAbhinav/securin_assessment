-- CVE Assessment Database Schema
-- Run this script in your Supabase SQL editor

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- CVEs table - main table for storing CVE information
CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    source_identifier VARCHAR(100),
    vuln_status VARCHAR(50),
    published TIMESTAMP WITH TIME ZONE,
    last_modified TIMESTAMP WITH TIME ZONE,
    description TEXT,
    cvss_v2_score DECIMAL(3,1),
    cvss_v3_score DECIMAL(3,1),
    cvss_v2_vector VARCHAR(100),
    cvss_v3_vector VARCHAR(100),
    cvss_v2_severity VARCHAR(20),
    cvss_v3_severity VARCHAR(20),
    cpe_configurations JSONB,
    references JSONB,
    weaknesses JSONB,
    configurations JSONB,
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves(last_modified);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v2_score ON cves(cvss_v2_score);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3_score ON cves(cvss_v3_score);
CREATE INDEX IF NOT EXISTS idx_cves_vuln_status ON cves(vuln_status);
CREATE INDEX IF NOT EXISTS idx_cves_year ON cves(EXTRACT(year FROM published));

-- Create a GIN index for full-text search on description
CREATE INDEX IF NOT EXISTS idx_cves_description_fts ON cves USING gin(to_tsvector('english', description));

-- Sync status table - tracks synchronization operations
CREATE TABLE IF NOT EXISTS sync_status (
    id SERIAL PRIMARY KEY,
    sync_type VARCHAR(20) NOT NULL, -- 'full' or 'incremental'
    status VARCHAR(20) NOT NULL, -- 'running', 'completed', 'failed'
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    total_records INTEGER DEFAULT 0,
    processed_records INTEGER DEFAULT 0,
    new_records INTEGER DEFAULT 0,
    updated_records INTEGER DEFAULT 0,
    error_message TEXT,
    last_modified_date TIMESTAMP WITH TIME ZONE -- for incremental sync tracking
);

-- Create index on sync_status
CREATE INDEX IF NOT EXISTS idx_sync_status_started_at ON sync_status(started_at);

-- CVE statistics view for dashboard
CREATE OR REPLACE VIEW cve_statistics AS
SELECT 
    COUNT(*) as total_cves,
    COUNT(CASE WHEN cvss_v3_score >= 9.0 THEN 1 END) as critical_cves,
    COUNT(CASE WHEN cvss_v3_score >= 7.0 AND cvss_v3_score < 9.0 THEN 1 END) as high_cves,
    COUNT(CASE WHEN cvss_v3_score >= 4.0 AND cvss_v3_score < 7.0 THEN 1 END) as medium_cves,
    COUNT(CASE WHEN cvss_v3_score >= 0.1 AND cvss_v3_score < 4.0 THEN 1 END) as low_cves,
    COUNT(CASE WHEN cvss_v3_score IS NULL OR cvss_v3_score = 0 THEN 1 END) as unscored_cves,
    MAX(last_modified) as last_updated,
    COUNT(CASE WHEN DATE(published) = CURRENT_DATE THEN 1 END) as today_published,
    COUNT(CASE WHEN published >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as week_published,
    COUNT(CASE WHEN published >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as month_published
FROM cves;

-- CVE yearly distribution view
CREATE OR REPLACE VIEW cve_yearly_stats AS
SELECT 
    EXTRACT(year FROM published) as year,
    COUNT(*) as total_count,
    AVG(COALESCE(cvss_v3_score, cvss_v2_score)) as avg_score,
    MAX(COALESCE(cvss_v3_score, cvss_v2_score)) as max_score,
    COUNT(CASE WHEN COALESCE(cvss_v3_score, cvss_v2_score) >= 9.0 THEN 1 END) as critical_count,
    COUNT(CASE WHEN COALESCE(cvss_v3_score, cvss_v2_score) >= 7.0 AND COALESCE(cvss_v3_score, cvss_v2_score) < 9.0 THEN 1 END) as high_count
FROM cves 
WHERE published IS NOT NULL
GROUP BY EXTRACT(year FROM published)
ORDER BY year DESC;

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_cves_updated_at ON cves;
CREATE TRIGGER update_cves_updated_at 
    BEFORE UPDATE ON cves 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create a function for full-text search
CREATE OR REPLACE FUNCTION search_cves(search_term TEXT)
RETURNS TABLE(
    id INTEGER,
    cve_id VARCHAR(20),
    description TEXT,
    cvss_v3_score DECIMAL(3,1),
    published TIMESTAMP WITH TIME ZONE,
    rank REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.id,
        c.cve_id,
        c.description,
        c.cvss_v3_score,
        c.published,
        ts_rank(to_tsvector('english', c.description), plainto_tsquery('english', search_term)) as rank
    FROM cves c
    WHERE to_tsvector('english', c.description) @@ plainto_tsquery('english', search_term)
    ORDER BY rank DESC;
END;
$$ LANGUAGE plpgsql;

-- Insert initial sync status record if table is empty
INSERT INTO sync_status (sync_type, status, total_records, processed_records)
SELECT 'initial', 'pending', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM sync_status);

-- Create RLS (Row Level Security) policies if needed
-- ALTER TABLE cves ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sync_status ENABLE ROW LEVEL SECURITY;

-- Grant permissions for service role
-- GRANT ALL ON cves TO service_role;
-- GRANT ALL ON sync_status TO service_role;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Sample data insertion (optional - for testing)
-- This can be commented out for production
/*
INSERT INTO cves (
    cve_id, 
    source_identifier, 
    vuln_status, 
    published, 
    last_modified, 
    description, 
    cvss_v3_score, 
    cvss_v3_severity
) VALUES (
    'CVE-2024-SAMPLE',
    'cna@example.com',
    'PUBLISHED',
    '2024-01-01 10:00:00+00',
    '2024-01-01 10:00:00+00',
    'Sample CVE for testing purposes',
    7.5,
    'HIGH'
) ON CONFLICT (cve_id) DO NOTHING;
*/
