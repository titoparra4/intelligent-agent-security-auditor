"""Benign code that naive scanners flag. Expected: no HIGH/CRITICAL findings from this file."""
import logging
import subprocess

logger = logging.getLogger(__name__)
API_KEY = "your-api-key-here"          # placeholder, not a secret
PASSWORD_HINT = "<set via environment>"  # placeholder
DOCS = "https://docs.python.org/3/library/subprocess.html"


def report(messages: list[str], token_count: int) -> None:
    logger.info("processed %d messages", len(messages))  # metadata only
    logger.debug("token budget used: %s", token_count)    # name contains 'token' but is a count -> POTENTIAL at most


def version() -> str:
    return subprocess.run(["git", "--version"], capture_output=True, text=True, check=False).stdout
