-- Runs once on first PostgreSQL container start
-- Tables are created by SQLAlchemy migrate.py — this file handles extensions only

CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- fast text search
CREATE EXTENSION IF NOT EXISTS unaccent;  -- accent-insensitive search
