#!/usr/bin/env python3
"""
GitScout CLI Wrapper & Telemetry Event Stream Orchestrator
"""

import os
import sys
import time
import requests

from scout.db import FindingsStore, get_default_db_path
from scout.constants import RED, YELLOW, DEFAULT_POLL_INTERVAL
from scout.github_api import (
    parse_args, get_github_token, get_headers, mask_token,
    load_seen_events, save_seen_events, get_events
)
from scout.processor import banner, process_event


def main():
    retry_count = 0
    max_retries = 5
    events_etag = None
    seen_event_ids = load_seen_events()

    args = parse_args()
    store = None
    try:
        token = get_github_token(args)
        logfile = args.logfile
        db_path = args.db or get_default_db_path()
        if logfile:
            log_dir = os.path.dirname(logfile)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
        store = FindingsStore(db_path)
        store.start_session()
        headers = get_headers(token)
        print(f'{YELLOW}[*] Using GitHub token: {mask_token(token)}')
        print(f'{YELLOW}[*] DuckDB: {db_path}')
        if logfile:
            print(f'{YELLOW}[*] JSONL export: {logfile}')
    except ValueError as e:
        print(f"{RED}[-] Error: {e}")
        sys.exit(1)

    try:
        while True:
            try:
                print(f"{YELLOW}[*] Fetching events...")
                store.log_progress("Fetching events from GitHub API")
                events, response_headers, events_etag, not_modified = get_events(headers, etag=events_etag)
                poll_stats = {'events': 0, 'commits': 0, 'files': 0, 'secrets': 0}

                if not_modified:
                    print(f"{YELLOW}[*] No new events (304 Not Modified).")
                    store.log_progress("No new events (304 Not Modified)")
                elif events:
                    new_events = 0
                    for event in reversed(events):
                        event_id = event['id']
                        if event_id in seen_event_ids:
                            continue
                        seen_event_ids.add(event_id)
                        new_events += 1
                        process_event(headers, event, store, logfile, poll_stats)
                    save_seen_events(seen_event_ids)
                    if new_events == 0:
                        print(f"{YELLOW}[*] No new events since last run.")
                        store.log_progress("No new events since last run")
                    else:
                        store.log_poll_summary(poll_stats)
                else:
                    print(f"{RED}[!] No events returned.")
                    store.log_progress("No events returned")

                remaining_requests = int(response_headers.get('X-RateLimit-Remaining', 0))
                reset_time = int(response_headers.get('X-RateLimit-Reset', time.time()))
                poll_interval = int(response_headers.get('X-Poll-Interval', DEFAULT_POLL_INTERVAL))

                if 'Retry-After' in response_headers:
                    retry_after = int(response_headers['Retry-After'])
                    print(f"{YELLOW}[*] Rate limit hit. Retrying after {retry_after} seconds.")
                    time.sleep(retry_after)
                elif remaining_requests == 0:
                    sleep_time = max(0, reset_time - int(time.time()))
                    print(f"{YELLOW}[*] Rate limit exceeded. Waiting for {sleep_time} seconds.")
                    time.sleep(sleep_time)
                else:
                    print(f"{YELLOW}[*] Remaining requests: {remaining_requests}")
                    print(f"{YELLOW}[*] Waiting {poll_interval}s for next poll...")
                    store.log_progress(
                        f"Waiting {poll_interval}s (rate limit: {remaining_requests} left)"
                    )
                    time.sleep(poll_interval)

                retry_count = 0

            except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                print(f"{RED}[-] Error: {e}")
                if retry_count < max_retries:
                    retry_count += 1
                    sleep_time = min(2 ** retry_count, 60)
                    print(f"{RED}[-] Retrying in {sleep_time} seconds... (Retry {retry_count}/{max_retries})")
                    time.sleep(sleep_time)
                else:
                    print(f"{RED}[-] Max retries reached. Exiting.")
                    break
            except KeyboardInterrupt:
                print(f"{RED}[-] Exiting...")
                break
    finally:
        if store is not None:
            store.close()


if __name__ == '__main__':
    banner()
    main()