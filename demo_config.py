"""Demo configuration file — intentionally contains fake secrets for testing."""

import os

# Database connection
DATABASE_URL = "postgres://admin:password123@db.example.com:5432/myapp"

# API keys
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# TODO: move these to environment variables
API_ENDPOINT = "http://localhost:8080/api/v1"

# Hardcoded password
DB_PASSWORD = "super_secret_password_123"

def get_config():
    return {
        "debug": True,
        "db_url": DATABASE_URL,
    }
