import os
import logging
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("clawmon")

# --- OpenClaw fingerprints ---
OPENCLAW_PORT = 18789
OPENCLAW_TITLE = "Clawdbot Control"
OPENCLAW_SERVER_HEADER = "OpenClaw-Gateway"

# --- Censys free tier (optional) ---
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")

# --- Scanner settings ---
SCAN_CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", "500"))
SCAN_TIMEOUT_SECS = float(os.environ.get("SCAN_TIMEOUT", "3"))
VALIDATION_RATE_LIMIT = float(os.environ.get("SCAN_RATE_LIMIT", "2"))  # requests/sec
VALIDATION_TIMEOUT_SECS = 5
STALE_THRESHOLD_HOURS = 48

# --- Storage ---
DB_PATH = Path(os.environ.get("DB_PATH", "clawmon.db"))
