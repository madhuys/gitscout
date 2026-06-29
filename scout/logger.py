"""
Logging handlers for writing findings to DuckDB storage and JSONL export logs.
"""

import json
from scout.constants import RED, GREEN, YELLOW, CYAN, RESET
from scout.detector import detect_secrets_in_text


def log_secret_json(logfile: str, filename: str, commit_sha: str, commit_url: str, secret: str, secret_type: str):
    """Writes a single finding record formatted as JSON to logfile."""
    log_entry = {
        "filename": filename,
        "commit_sha": commit_sha,
        "commit_url": commit_url,
        "secret": secret,
        "secret_type": secret_type,
    }

    with open(logfile, "a", encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + "\n")


def log_finding(store, logfile: str, filename: str, commit_sha: str, commit_url: str, secret: str, secret_type: str):
    """Persists a single finding to DuckDB and optional JSONL file."""
    store.log_finding(filename, commit_sha, commit_url, secret, secret_type)
    if logfile:
        log_secret_json(logfile, filename, commit_sha, commit_url, secret, secret_type)


def log_detected_secrets(content: str, store, logfile: str, filename: str, commit_sha: str, commit_web_url: str, stats: dict = None):
    """Scans text content and logs all identified secret matches to terminal and storage."""
    detected_secrets = detect_secrets_in_text(content)
    if not detected_secrets:
        return

    if stats is not None:
        stats['secrets'] += len(detected_secrets)

    print(f"{GREEN}[+]{RESET} Secrets detected in {GREEN}{filename}{RESET} at commit {GREEN}{commit_sha}{RESET}")
    print(f"{GREEN}[+]{RESET} URL: {GREEN}{commit_web_url}{RESET}")

    secrets_by_type = {}
    for secret, secret_type in detected_secrets:
        secrets_by_type.setdefault(secret_type, []).append(secret)

    for secret_type, secrets in secrets_by_type.items():
        print(f"{CYAN}[*]{RESET} Secret Type: {CYAN}{secret_type}{RESET}")
        for secret in secrets:
            print(f"{GREEN}[+]{RESET} Secret: {GREEN}{secret}{RESET}")
            log_finding(store, logfile, filename, commit_sha, commit_web_url, secret, secret_type)
