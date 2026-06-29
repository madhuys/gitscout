"""
GitHub event stream event processing, commit inspection workflows, and terminal banners.
"""

import requests
from scout.constants import RED, GREEN, YELLOW, CYAN, RESET, REQUEST_TIMEOUT
from scout.github_api import fetch_commit_files, fetch_file_content
from scout.detector import fetch_and_process_db_file, detect_secrets_in_text
from scout.logger import log_detected_secrets


def banner():
    """Prints the ASCII terminal header banner for GitScout."""
    print(f"""


  ██████╗ ████████╗████████╗███████╗██████╗ ██████╗ ██║   ██║████████╗
 ██╔════╝ ╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║   ██║╚══██╔══╝
 ██║  ███╗   ██║      ██║   ███████╗██║  ╚═╝██║  ██║██║   ██║   ██║   
 ██║   ██║   ██║      ██║   ╚════██║██║  ██╗██║  ██║██║   ██║   ██║   
 ╚██████╔╝   ██║      ██║   ███████║╚██████╔╝╚██████╔╝╚██████╔╝   ██║   
{RED}  ╚═════╝    ╚═╝      ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝{RESET}

        Developer: {CYAN}@madhuys{RESET}
        Github: {YELLOW}https://github.com/madhuys{RESET}
        Real-time GitHub Secret Recon & Reconnaissance

        """)


def normalize_commit(commit: dict, repo_name: str) -> dict:
    """Normalizes commit payload structures into uniform SHA and URL dictionary."""
    sha = commit['sha']
    url = commit.get('url') or f'https://api.github.com/repos/{repo_name}/commits/{sha}'
    return {'sha': sha, 'url': url}


def get_push_commits(event: dict) -> list:
    """
    Extracts commit list from PushEvent payloads.
    Falls back to head SHA if payload commits array is omitted by GitHub API.
    """
    payload = event['payload']
    repo_name = event['repo']['name']
    commits = payload.get('commits') or []

    if commits:
        return [normalize_commit(c, repo_name) for c in commits]

    head = payload.get('head')
    if head:
        return [normalize_commit({'sha': head}, repo_name)]

    return []


def process_event(headers: dict, event: dict, store, logfile: str, stats: dict = None):
    """Parses individual GitHub events, fetching and scanning modified commits and files."""
    event_type = event['type']
    repo_name = event['repo']['name']
    print(f"{YELLOW}[!]{RESET} Processing event: {YELLOW}{event['id']}{RESET} - {YELLOW}{event_type}{RESET}")
    store.log_progress(f"Event `{event['id']}` ({event_type}) in `{repo_name}`")
    if stats is not None:
        stats['events'] += 1

    absolutes = (
        'wp-config.php',
        'phpmailer.php',
        'config.php',
        'config.inc.php',
        'database.php',
        '.env.local',
    )

    extensions = (
        '.env', '.ini', '.cfg', '.conf',
        '.json', '.yaml', '.yml',
        '.py', '.js', '.ts', '.php', '.rb', '.go', '.java', '.cs',
        '.sh', '.bash', '.zsh', '.ps1', '.bat',
        '.pem', '.cer', '.crt', '.p12', '.pfx', '.key', '.rsa', '.jks',
        '.tf', '.tfvars',
        '.sql', '.sqlite', '.xml', '.properties',
        '.gradle', '.pom',
        '.md', '.markdown',
    )

    if event['type'] not in ('PushEvent', 'PullRequestEvent'):
        return

    commits = []

    if event['type'] == 'PushEvent':
        commits = get_push_commits(event)
        if not commits:
            store.log_progress(f"No commits in PushEvent for `{repo_name}`")

    elif event['type'] == 'PullRequestEvent':
        pr = event['payload'].get('pull_request', {})
        commits_url = pr.get('commits_url')
        if commits_url:
            try:
                response = requests.get(commits_url, headers=headers, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                commits = [normalize_commit(c, repo_name) for c in response.json()]
            except requests.RequestException as e:
                print(f"{RED}    [-] Failed to fetch PR commits: {e}{RESET}")
                return

    for commit in commits:
        commit_sha = commit['sha']
        commit_url = commit['url']
        commit_web_url = f"https://github.com/{repo_name}/commit/{commit_sha}"
        print(f"{YELLOW}[!]{RESET} Processing commit: {YELLOW}{commit_sha}{RESET}")
        store.log_progress(f"Commit `{commit_sha[:7]}` in `{repo_name}`")
        if stats is not None:
            stats['commits'] += 1
        files = fetch_commit_files(headers, commit_url)

        for file in files:
            filename = file['filename'].lower()

            if 'wp-config-sample.php' in filename:
                continue

            if filename.endswith('.db'):
                file_url = file['contents_url']
                print(f"{YELLOW}    [*] Fetching file: {file['filename']}{RESET}")
                store.log_progress(f"Scanning db `{file['filename']}`")
                if stats is not None:
                    stats['files'] += 1
                fetch_and_process_db_file(
                    headers, file_url, store, logfile, file['filename'], commit_sha, commit_web_url, stats, logger_func=log_detected_secrets
                )
                continue

            if filename == 'dockerfile' or any(hvf in filename for hvf in absolutes) or filename.endswith(extensions):
                file_url = file['contents_url']
                print(f"{YELLOW}    [*] Fetching file: {file['filename']}{RESET}")
                store.log_progress(f"Scanning `{file['filename']}`")
                if stats is not None:
                    stats['files'] += 1
                file_content = fetch_file_content(headers, file_url)

                if not file_content:
                    print(f"{RED}    [-] Failed to fetch file content for {file['filename']}{RESET}")
                    store.log_progress(f"No content for `{file['filename']}`")
                    continue

                if not detect_secrets_in_text(file_content):
                    print(f"{RED}    [-] No secrets found in {file['filename']}{RESET}")
                    continue

                log_detected_secrets(
                    file_content, store, logfile, file['filename'], commit_sha, commit_web_url, stats
                )
