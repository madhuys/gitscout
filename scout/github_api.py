"""
GitHub REST API client, authentication helper, event polling, and raw content fetching routines.
"""

import argparse
import json
import os
from base64 import b64decode
import requests

from scout.db import get_default_db_path
from scout.constants import (
    RED, REQUEST_TIMEOUT, MAX_FILE_BYTES, MAX_SEEN_EVENTS,
    RESET, get_seen_events_path
)


def mask_token(token: str) -> str:
    """Masks a token string for safe terminal display."""
    if len(token) <= 8:
        return '***'
    return f'{token[:4]}...{token[-4:]}'


def parse_args():
    """Parses command-line arguments for GitScout scanner execution."""
    parser = argparse.ArgumentParser(description='GitScout: Monitor GitHub public events for leaked secrets in real-time')
    parser.add_argument('--github-token', type=str, help='GitHub access token (prefer GITHUB_ACCESS_TOKEN env var)')
    parser.add_argument('--logfile', type=str, help='Optional JSONL export path')
    parser.add_argument('--db', type=str, help='DuckDB database path (default: ./findings.duckdb)')
    return parser.parse_args()


def get_github_token(args) -> str:
    """Retrieves GitHub token from CLI argument or environment variable."""
    github_token = args.github_token or os.getenv('GITHUB_ACCESS_TOKEN')
    if not github_token:
        raise ValueError(
            "GitHub token not provided. Set GITHUB_ACCESS_TOKEN or pass --github-token."
        )
    return github_token


def get_headers(token: str) -> dict:
    """Constructs HTTP headers for GitHub API authentication."""
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
    }


def load_seen_events() -> set:
    """Loads previously processed event IDs from cache."""
    path = get_seen_events_path()
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding='utf-8') as f:
            return set(json.load(f))
    except (json.JSONDecodeError, OSError):
        return set()


def save_seen_events(seen_event_ids: set):
    """Saves trimmed history of processed event IDs to cache."""
    path = get_seen_events_path()
    trimmed = list(seen_event_ids)[-MAX_SEEN_EVENTS:]
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(trimmed, f)


def get_events(headers: dict, etag: str = None):
    """
    Fetch public events from the GitHub API using conditional ETag requests.
    Returns: (events_json, response_headers, new_etag, not_modified_flag)
    """
    url = 'https://api.github.com/events?per_page=100'
    req_headers = dict(headers)
    if etag:
        req_headers['If-None-Match'] = etag

    response = requests.get(url, headers=req_headers, timeout=REQUEST_TIMEOUT)
    if response.status_code == 304:
        return [], response.headers, etag, True
    response.raise_for_status()
    new_etag = response.headers.get('ETag', etag)
    return response.json(), response.headers, new_etag, False


def fetch_commit_files(headers: dict, commit_url: str) -> list:
    """Fetches the list of modified files in a specific commit."""
    response = requests.get(commit_url, headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json().get('files', [])


def fetch_file_bytes(headers: dict, file_url: str):
    """Downloads raw file bytes from GitHub contents URL (Base64 decoded)."""
    response = requests.get(file_url, headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()

    if payload.get('encoding') != 'base64':
        print(f"{RED}    [-] Unsupported encoding for {file_url}{RESET}")
        return None

    content = payload.get('content', '')
    if not content:
        return None

    raw = b64decode(content)
    if len(raw) > MAX_FILE_BYTES:
        print(f"{RED}    [-] File exceeds {MAX_FILE_BYTES} byte limit: {file_url}{RESET}")
        return None
    return raw


def fetch_file_content(headers: dict, file_url: str) -> str:
    """Fetches and decodes text content from a GitHub file URL."""
    raw = fetch_file_bytes(headers, file_url)
    if raw is None:
        return ""

    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        print(f"{RED}    [-] Failed to decode file content as UTF-8 for {file_url}{RESET}")
        return ""
