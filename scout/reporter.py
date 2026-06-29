#!/usr/bin/env python3
import argparse
from datetime import datetime, timezone

import duckdb

from scout.db import HIGH_SIGNAL_TYPES, get_default_db_path, get_project_root, resolve_readable_db_path


def truncate(text, limit=120):
    text = str(text).replace('\n', ' ')
    if len(text) <= limit:
        return text
    return text[: limit - 3] + '...'


def generate_report(db_path, output_path):
    readable_path, snapshot = resolve_readable_db_path(db_path)
    if snapshot:
        print(f'Using snapshot: {readable_path}')
    conn = duckdb.connect(readable_path, read_only=True)
    try:
        total = conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
        by_type = conn.execute(
            '''
            SELECT secret_type, COUNT(*) AS count
            FROM findings
            GROUP BY secret_type
            ORDER BY count DESC
            '''
        ).fetchall()
        high_signal = conn.execute(
            f'''
            SELECT COUNT(*) FROM findings
            WHERE secret_type IN ({', '.join(['?'] * len(HIGH_SIGNAL_TYPES))})
            ''',
            list(HIGH_SIGNAL_TYPES),
        ).fetchone()[0]
        recent_poll = conn.execute(
            '''
            SELECT polled_at, events, commits, files, secrets
            FROM poll_summaries
            ORDER BY polled_at DESC
            LIMIT 1
            '''
        ).fetchone()
        placeholders = ', '.join(['?'] * len(HIGH_SIGNAL_TYPES))
        interesting = conn.execute(
            f'''
            SELECT detected_at, secret_type, repo, filename, commit_url,
                   LEFT(secret, 80) AS secret_preview
            FROM findings
            WHERE secret_type IN ({placeholders})
            ORDER BY detected_at DESC
            LIMIT 100
            ''',
            list(HIGH_SIGNAL_TYPES),
        ).fetchall()

        generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        lines = [
            '# GitScout Findings Report',
            '',
            f'> Generated {generated} from `{db_path}`',
            '',
            '> **Warning:** Contains live third-party credentials. Do not commit or share.',
            '',
            '## Summary',
            '',
            f'- **Total findings:** {total}',
            f'- **High-signal findings:** {high_signal}',
        ]
        if recent_poll:
            lines.append(
                f'- **Last poll:** {recent_poll[0]} — '
                f'{recent_poll[1]} events, {recent_poll[2]} commits, '
                f'{recent_poll[3]} files, {recent_poll[4]} secrets'
            )
        lines.extend(['', '### By type', '', '| Type | Count |', '| --- | ---: |'])
        for secret_type, count in by_type:
            lines.append(f'| {secret_type} | {count} |')

        lines.extend(['', '## High-signal findings', ''])
        if not interesting:
            lines.append('_No high-signal findings._')
        else:
            lines.extend([
                '| When | Type | Repo | File | Secret (preview) | Commit |',
                '| --- | --- | --- | --- | --- | --- |',
            ])
            for row in interesting:
                detected_at, secret_type, repo, filename, commit_url, secret_preview = row
                commit_sha = commit_url.rstrip('/').split('/')[-1][:7]
                link = f'[view]({commit_url})'
                lines.append(
                    f'| {detected_at} | {secret_type} | `{repo or "-"}` | '
                    f'`{filename}` | `{truncate(secret_preview, 60)}` | {link} |'
                )

        lines.extend([
            '',
            '## Query the database',
            '',
            '```bash',
            'python3 findings_server.py',
            '# open http://127.0.0.1:8765',
            '',
            'python3 query_findings.py summary',
            'python3 query_findings.py interesting',
            '```',
            '',
        ])

        with open(output_path, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines))
        return output_path
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Generate markdown findings report')
    parser.add_argument('--db', default=get_default_db_path())
    parser.add_argument(
        '--output',
        default=f'{get_project_root()}/FINDINGS_REPORT.md',
    )
    args = parser.parse_args()
    path = generate_report(args.db, args.output)
    print(f'Wrote {path}')


if __name__ == '__main__':
    main()