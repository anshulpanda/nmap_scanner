"""Configuration loaded from the environment (via .env).

Credentials never live in source; .env is gitignored and .env.example
documents the variables a fresh checkout needs.
"""

import os

from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "nmap_scanner")

# An unreachable host makes nmap spend its full timing budget, so scans get a
# hard ceiling rather than hanging a request forever.
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "120"))

# Highest port the scanner will look at. The assignment specifies 0-1000.
PORT_RANGE_START = 0
PORT_RANGE_END = 1000

# DATABASE_URL lets tests point the whole app at SQLite instead of MySQL.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
)
