-- PostgreSQL initialization script for broker-interceptor
-- This script runs automatically when the PostgreSQL container is first created

-- Create extensions that may be needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges to broker user (already owner, but ensuring full access)
GRANT ALL PRIVILEGES ON DATABASE broker TO broker;

-- Log successful initialization
DO $$
BEGIN
  RAISE NOTICE 'broker database initialized successfully';
END $$;
