#!/usr/bin/env python3
import argparse
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import duckdb

from scout.db import get_default_db_path, get_project_root, resolve_readable_db_path

UI_DIR = os.path.join(get_project_root(), 'ui', 'static')
UI_DIST_DIR = os.path.join(get_project_root(), 'ui', 'react-app', 'dist')


def get_ui_index_path():
    dist_index = os.path.join(UI_DIST_DIR, 'index.html')
    if os.path.exists(dist_index):
        return dist_index, UI_DIST_DIR
    return os.path.join(UI_DIR, 'index.html'), UI_DIR
ALLOWED_SORT = {'detected_at', 'secret_type', 'repo', 'filename'}


def connect_readonly(db_path):
    readable_path, _ = resolve_readable_db_path(db_path)
    return duckdb.connect(readable_path, read_only=True)


def query_summary(conn):
    total = conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
    by_type = [
        {'type': row[0], 'count': row[1]}
        for row in conn.execute(
            '''
            SELECT secret_type, COUNT(*) AS count
            FROM findings
            GROUP BY secret_type
            ORDER BY count DESC
            '''
        ).fetchall()
    ]
    high_signal = conn.execute(
        '''
        SELECT COUNT(*) FROM findings
        WHERE secret_type LIKE '% API Key'
           OR secret_type LIKE '% API Token'
           OR secret_type IN (
               'Anthropic API Key', 'OpenAI API Key', 'OpenAI Project API Key', 'OpenAI Live API Key',
               'OpenRouter API Key', 'Together AI API Key', 'Groq API Key', 'Hugging Face API Key',
               'Google API Key', 'AWS Access Key ID', 'AWS Secret Access Key', 'Private Key', 'SSH Key',
               'PostgreSQL Connection String', 'MySQL Connection String', 'MongoDB Connection String',
               'LLM Provider ENV Key', 'API Key', 'Auth Key', 'Secret Key', 'Generic Token',
               'SMTP Credentials', 'ENV Variable Credential', 'wp-config.php Credentials',
               'Data Provider ENV Key', 'RapidAPI Header Key', 'X-API-Key Header', 'Bearer Token',
               'NewsAPI Key', 'RapidAPI Key'
           )
        '''
    ).fetchone()[0]
    last_poll = conn.execute(
        '''
        SELECT polled_at, events, commits, files, secrets
        FROM poll_summaries
        ORDER BY polled_at DESC
        LIMIT 1
        '''
    ).fetchone()
    return {
        'total': total,
        'high_signal': high_signal,
        'by_type': by_type,
        'last_poll': {
            'at': str(last_poll[0]) if last_poll else None,
            'events': last_poll[1] if last_poll else 0,
            'commits': last_poll[2] if last_poll else 0,
            'files': last_poll[3] if last_poll else 0,
            'secrets': last_poll[4] if last_poll else 0,
        },
    }


def query_findings(conn, params):
    secret_type = params.get('type', [''])[0]
    repo = params.get('repo', [''])[0]
    search = params.get('q', [''])[0]
    high_only = params.get('high_signal', ['0'])[0] == '1'
    limit = min(max(int(params.get('limit', ['100'])[0]), 1), 5000)
    offset = max(int(params.get('offset', ['0'])[0]), 0)
    sort = params.get('sort', ['detected_at'])[0]
    order = params.get('order', ['desc'])[0].lower()

    if sort not in ALLOWED_SORT:
        sort = 'detected_at'
    if order not in {'asc', 'desc'}:
        order = 'desc'

    clauses = []
    values = []

    if secret_type:
        clauses.append('secret_type = ?')
        values.append(secret_type)
    if repo:
        clauses.append('repo ILIKE ?')
        values.append(f'%{repo}%')
    if search:
        clauses.append(
            '(secret ILIKE ? OR filename ILIKE ? OR repo ILIKE ? OR commit_sha ILIKE ?)'
        )
        like = f'%{search}%'
        values.extend([like, like, like, like])
    if high_only:
        clauses.append(
            "(secret_type LIKE '% API Key' OR secret_type LIKE '% API Token' "
            "OR secret_type IN ('API Key', 'Auth Key', 'Secret Key', 'Generic Token', "
            "'LLM Provider ENV Key', 'Data Provider ENV Key', 'RapidAPI Header Key', "
            "'X-API-Key Header', 'Bearer Token', 'NewsAPI Key', 'RapidAPI Key', "
            "'AWS Access Key ID', 'AWS Secret Access Key', 'Private Key', 'SSH Key', "
            "'PostgreSQL Connection String', 'MySQL Connection String', 'MongoDB Connection String', "
            "'SMTP Credentials', 'ENV Variable Credential', 'wp-config.php Credentials'))"
        )

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    count_sql = f'SELECT COUNT(*) FROM findings {where}'
    total = conn.execute(count_sql, values).fetchone()[0]

    data_sql = f'''
        SELECT detected_at, secret_type, repo, filename, commit_sha, commit_url, secret
        FROM findings
        {where}
        ORDER BY {sort} {order}
        LIMIT ? OFFSET ?
    '''
    rows = conn.execute(data_sql, values + [limit, offset]).fetchall()
    items = [
        {
            'detected_at': str(row[0]),
            'secret_type': row[1],
            'repo': row[2],
            'filename': row[3],
            'commit_sha': row[4],
            'commit_url': row[5],
            'secret': row[6],
        }
        for row in rows
    ]
    return {'total': total, 'limit': limit, 'offset': offset, 'items': items}


class FindingsHandler(BaseHTTPRequestHandler):
    db_path = get_default_db_path()

    def log_message(self, format, *args):
        return

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        with open(path, 'rb') as handle:
            body = handle.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path

        try:
            conn = connect_readonly(self.db_path)
        except duckdb.IOException as exc:
            self._send_json({'error': str(exc)}, status=503)
            return

        try:
            if route in {'/', '/index.html'}:
                index_path, _ = get_ui_index_path()
                self._send_file(index_path, 'text/html; charset=utf-8')
                return
            if route.startswith('/assets/'):
                _, static_root = get_ui_index_path()
                asset_path = os.path.join(static_root, route.lstrip('/'))
                if os.path.isfile(asset_path):
                    if asset_path.endswith('.js'):
                        content_type = 'application/javascript'
                    elif asset_path.endswith('.css'):
                        content_type = 'text/css; charset=utf-8'
                    else:
                        content_type = 'application/octet-stream'
                    self._send_file(asset_path, content_type)
                    return
            if route == '/api/summary':
                self._send_json(query_summary(conn))
                return
            if route == '/api/types':
                types = [
                    row[0]
                    for row in conn.execute(
                        'SELECT DISTINCT secret_type FROM findings ORDER BY secret_type'
                    ).fetchall()
                ]
                self._send_json({'types': types})
                return
            if route == '/api/findings':
                params = urllib.parse.parse_qs(parsed.query)
                self._send_json(query_findings(conn, params))
                return
            self._send_json({'error': 'Not found'}, status=404)
        finally:
            conn.close()


def main():
    parser = argparse.ArgumentParser(description='GitScout findings web UI')
    parser.add_argument('--db', default=get_default_db_path())
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()

    FindingsHandler.db_path = args.db
    server = ThreadingHTTPServer((args.host, args.port), FindingsHandler)
    print(f'GitScout findings UI: http://{args.host}:{args.port}')
    print('Press Ctrl+C to stop.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()