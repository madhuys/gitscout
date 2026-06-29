#!/usr/bin/env python3
import argparse
import sys

from scout.db import FindingsStore, get_default_db_path


def print_summary(store):
    total = store.count_findings()
    print(f'Total findings: {total}\n')
    print('By type:')
    for secret_type, count in store.summary_by_type():
        print(f'  {count:5d}  {secret_type}')


def print_interesting(store, limit):
    rows = store.interesting_findings(limit=limit)
    print(f'High-signal findings ({len(rows)} shown):\n')
    for row in rows:
        detected_at, secret_type, repo, filename, commit_url, secret_preview = row
        print(f'- {detected_at} | {secret_type}')
        print(f'  repo:   {repo}')
        print(f'  file:   {filename}')
        print(f'  secret: {secret_preview}')
        print(f'  url:    {commit_url}')
        print()


def run_sql(store, query):
    result = store.conn.execute(query)
    rows = result.fetchall()
    columns = [col[0] for col in result.description]
    print('\t'.join(columns))
    for row in rows:
        print('\t'.join(str(value) for value in row))


def main():
    parser = argparse.ArgumentParser(description='Query GitScout DuckDB findings')
    parser.add_argument('--db', default=get_default_db_path(), help='Path to findings.duckdb')
    parser.add_argument('--migrate-jsonl', metavar='PATH', help='Import findings from JSONL')
    parser.add_argument('--limit', type=int, default=30, help='Limit for interesting output')
    parser.add_argument('command', nargs='?', default='summary',
                        choices=['summary', 'interesting', 'sql'],
                        help='Query command')
    parser.add_argument('sql', nargs='?', help='SQL query when command=sql')
    args = parser.parse_args()

    store = FindingsStore(args.db)
    try:
        if args.migrate_jsonl:
            imported = store.migrate_jsonl(args.migrate_jsonl)
            print(f'Imported {imported} new findings into {args.db}')
            return

        if args.command == 'summary':
            print_summary(store)
        elif args.command == 'interesting':
            print_interesting(store, args.limit)
        elif args.command == 'sql':
            if not args.sql:
                print('Provide a SQL query.', file=sys.stderr)
                sys.exit(1)
            run_sql(store, args.sql)
    finally:
        store.close()


if __name__ == '__main__':
    main()