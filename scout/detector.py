"""
Secret detection routines, signature normalization, validation logic, and SQLite database parser.
"""

import re
import sqlite3
import tempfile

from scout.patterns import SECRET_PATTERNS
from scout.constants import RED, RESET, PLACEHOLDER_VALUES
from scout.github_api import fetch_file_bytes


def quote_sqlite_identifier(name: str) -> str:
    """Quotes an identifier for SQLite queries."""
    return '"' + name.replace('"', '""') + '"'


def normalize_secret(match, description: str):
    """Extracts the exact secret string from regex match tuples."""
    if not isinstance(match, tuple):
        return match
    if description == "SMTP Credentials" and len(match) > 2:
        return match[2]
    return match[-1]


def is_valid_secret(secret: str, description: str) -> bool:
    """
    Validates detected secret candidates against placeholder lists, length rules,
    and domain filtering to eliminate common false positives.
    """
    if not secret or not isinstance(secret, str):
        return False

    secret_stripped = secret.strip().strip("'\"")
    if not secret_stripped:
        return False

    lower = secret_stripped.lower()
    if lower in PLACEHOLDER_VALUES:
        return False
    if re.match(r'^[\*\.\-_]+$', secret_stripped):
        return False
    if '${' in secret_stripped or 'process.env' in secret_stripped:
        return False

    if description == "Email Address":
        if any(x in lower for x in ('example.com', 'example.org', 'test.com', 'localhost', 'your@', '@example')):
            return False
        return True

    if len(secret_stripped) < 8:
        return False

    return True


def detect_secrets_in_text(text: str) -> list:
    """Evaluates text against all registered regular expression signatures."""
    secrets = []
    seen = set()
    for pattern, description in SECRET_PATTERNS:
        for match in pattern.findall(text):
            secret = normalize_secret(match, description)
            if not is_valid_secret(secret, description):
                continue
            key = (secret, description)
            if key in seen:
                continue
            seen.add(key)
            secrets.append(key)
    return secrets


def fetch_and_process_db_file(
    headers: dict,
    file_url: str,
    store,
    logfile: str,
    filename: str,
    commit_sha: str,
    commit_web_url: str,
    stats: dict = None,
    logger_func=None
):
    """
    Downloads committed SQLite database files, inspects internal table schemas,
    and recursively scans text fields for unencrypted secrets.
    """
    raw = fetch_file_bytes(headers, file_url)
    if raw is None:
        return

    with tempfile.NamedTemporaryFile(suffix=".db") as temp_db:
        temp_db.write(raw)
        temp_db.flush()

        with open(temp_db.name, 'rb') as f:
            header = f.read(16)
            if not header.startswith(b'SQLite format 3'):
                print(f"{RED}    [-] File {file_url} is not a valid SQLite database.{RESET}")
                return

        conn = sqlite3.connect(temp_db.name)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()

            for table in tables:
                table_name = table[0]
                cursor.execute(f"SELECT * FROM {quote_sqlite_identifier(table_name)};")
                rows = cursor.fetchall()
                for row in rows:
                    for item in row:
                        if isinstance(item, str) and logger_func is not None:
                            logger_func(
                                item, store, logfile, filename, commit_sha, commit_web_url, stats
                            )
        except sqlite3.DatabaseError as e:
            print(f"{RED}    [-] Error processing database file {file_url}: {e}{RESET}")
        finally:
            conn.close()
