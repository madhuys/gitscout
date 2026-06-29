import json
import os
import re
from datetime import datetime, timezone

import duckdb

FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    detected_at TIMESTAMP NOT NULL,
    secret_type VARCHAR NOT NULL,
    secret VARCHAR NOT NULL,
    filename VARCHAR NOT NULL,
    repo VARCHAR,
    commit_sha VARCHAR NOT NULL,
    commit_url VARCHAR NOT NULL,
    PRIMARY KEY (secret_type, secret, filename, commit_sha)
);

CREATE TABLE IF NOT EXISTS scan_progress (
    logged_at TIMESTAMP NOT NULL,
    message VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS poll_summaries (
    polled_at TIMESTAMP NOT NULL,
    events INTEGER NOT NULL,
    commits INTEGER NOT NULL,
    files INTEGER NOT NULL,
    secrets INTEGER NOT NULL
);
"""

_CORE_HIGH_SIGNAL_TYPES = {
    'Anthropic API Key', 'OpenAI API Key', 'OpenAI Project API Key', 'OpenAI Live API Key',
    'OpenRouter API Key', 'Together AI API Key', 'Groq API Key', 'Hugging Face API Key',
    'Google API Key', 'AWS Access Key ID', 'AWS Secret Access Key', 'Private Key', 'SSH Key',
    'PostgreSQL Connection String', 'MySQL Connection String', 'MongoDB Connection String',
    'LLM Provider ENV Key', 'API Key', 'Auth Key', 'Secret Key', 'Generic Token',
    'SMTP Credentials', 'ENV Variable Credential', 'wp-config.php Credentials',
    'Data Provider ENV Key', 'RapidAPI Header Key', 'X-API-Key Header', 'Bearer Token',
}


def _load_data_api_labels():
    try:
        from scout.patterns import DATA_API_LABELS
        return DATA_API_LABELS
    except ImportError:
        return set()


HIGH_SIGNAL_TYPES = _CORE_HIGH_SIGNAL_TYPES | _load_data_api_labels()


def is_high_signal_type(secret_type):
    if secret_type in HIGH_SIGNAL_TYPES:
        return True
    return secret_type.endswith(' API Key') or secret_type.endswith(' API Token')


def get_project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_default_db_path():
    return os.path.join(get_project_root(), 'findings.duckdb')


def get_snapshot_db_path():
    base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    return os.path.join(base, 'gitscout', 'findings.snapshot.duckdb')


_SNAPSHOT_CACHE = {'path': None, 'source_mtime': None, 'copied_at': 0.0}
SNAPSHOT_TTL_SEC = 8


def resolve_readable_db_path(db_path, *, force_refresh=False):
    try:
        conn = duckdb.connect(db_path, read_only=True)
        conn.close()
        return db_path, False
    except duckdb.IOException:
        import shutil
        import time

        snapshot = get_snapshot_db_path()
        now = time.time()
        try:
            source_mtime = os.path.getmtime(db_path)
            wal_path = f'{db_path}.wal'
            if os.path.isfile(wal_path):
                source_mtime = max(source_mtime, os.path.getmtime(wal_path))
        except OSError:
            source_mtime = 0

        cached = _SNAPSHOT_CACHE
        if (
            not force_refresh
            and cached['path'] == snapshot
            and cached['source_mtime'] == source_mtime
            and now - cached['copied_at'] < SNAPSHOT_TTL_SEC
            and os.path.isfile(snapshot)
        ):
            return snapshot, True

        os.makedirs(os.path.dirname(snapshot), exist_ok=True)
        shutil.copy2(db_path, snapshot)
        wal_path = f'{db_path}.wal'
        snapshot_wal = f'{snapshot}.wal'
        if os.path.isfile(wal_path):
            shutil.copy2(wal_path, snapshot_wal)
        elif os.path.isfile(snapshot_wal):
            os.remove(snapshot_wal)
        cached.update(path=snapshot, source_mtime=source_mtime, copied_at=now)
        return snapshot, True


def parse_repo_from_commit_url(commit_url):
    match = re.match(r'https://github\.com/([^/]+/[^/]+)/commit/', commit_url)
    return match.group(1) if match else None


class FindingsStore:
    def __init__(self, db_path=None):
        self.db_path = db_path or get_default_db_path()
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self.conn = duckdb.connect(self.db_path)
        self.conn.execute(FINDINGS_SCHEMA)

    def close(self):
        self.conn.close()

    def start_session(self):
        self.log_progress('GitScout session started')

    def log_progress(self, message):
        now = datetime.now(timezone.utc)
        self.conn.execute(
            'INSERT INTO scan_progress (logged_at, message) VALUES (?, ?)',
            [now, message],
        )

    def log_poll_summary(self, stats):
        now = datetime.now(timezone.utc)
        self.conn.execute(
            '''
            INSERT INTO poll_summaries (polled_at, events, commits, files, secrets)
            VALUES (?, ?, ?, ?, ?)
            ''',
            [now, stats['events'], stats['commits'], stats['files'], stats['secrets']],
        )
        self.log_progress(
            f"Poll summary: {stats['events']} events, {stats['commits']} commits, "
            f"{stats['files']} files, {stats['secrets']} secrets"
        )

    def log_finding(self, filename, commit_sha, commit_url, secret, secret_type):
        now = datetime.now(timezone.utc)
        repo = parse_repo_from_commit_url(commit_url)
        before = self.count_findings()
        self.conn.execute(
            '''
            INSERT INTO findings (
                detected_at, secret_type, secret, filename, repo, commit_sha, commit_url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            ''',
            [now, secret_type, secret, filename, repo, commit_sha, commit_url],
        )
        inserted = self.count_findings() > before
        if inserted:
            self.log_progress(
                f"Finding: {secret_type} in `{filename}` ({repo or 'unknown'})"
            )
        return inserted

    def migrate_jsonl(self, jsonl_path):
        if not os.path.exists(jsonl_path):
            return 0
        imported = 0
        with open(jsonl_path, encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                now = datetime.now(timezone.utc)
                repo = parse_repo_from_commit_url(row['commit_url'])
                before = self.count_findings()
                self.conn.execute(
                    '''
                    INSERT INTO findings (
                        detected_at, secret_type, secret, filename, repo, commit_sha, commit_url
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    ''',
                    [
                        now,
                        row['secret_type'],
                        row['secret'],
                        row['filename'],
                        repo,
                        row['commit_sha'],
                        row['commit_url'],
                    ],
                )
                if self.count_findings() > before:
                    imported += 1
        if imported:
            self.log_progress(f'Migrated {imported} findings from {jsonl_path}')
        return imported

    def count_findings(self):
        return self.conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]

    def summary_by_type(self):
        return self.conn.execute(
            '''
            SELECT secret_type, COUNT(*) AS count
            FROM findings
            GROUP BY secret_type
            ORDER BY count DESC
            '''
        ).fetchall()

    def interesting_findings(self, limit=50):
        placeholders = ', '.join(['?'] * len(HIGH_SIGNAL_TYPES))
        return self.conn.execute(
            f'''
            SELECT detected_at, secret_type, repo, filename, commit_url,
                   LEFT(secret, 80) AS secret_preview
            FROM findings
            WHERE secret_type IN ({placeholders})
            ORDER BY detected_at DESC
            LIMIT ?
            ''',
            list(HIGH_SIGNAL_TYPES) + [limit],
        ).fetchall()