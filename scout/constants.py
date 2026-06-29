"""
Constants, configuration limits, ANSI color formatting, and path helper utilities for GitScout.
"""

import os

# ANSI Color Codes for Terminal Output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Scanner Network & File Limits
REQUEST_TIMEOUT = 30
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB limit per fetched file
DEFAULT_POLL_INTERVAL = 60       # Standard poll interval in seconds
MAX_SEEN_EVENTS = 10000          # Max event history cache limit

# False Positive Filtering Set
PLACEHOLDER_VALUES = {
    'password', 'changeme', 'your_password', 'your-password', 'xxx', 'todo',
    'null', 'none', 'undefined', 'example', 'test', 'secret', 'placeholder',
    'your_api_key', 'your-api-key', 'insert_here', 'fake', 'dummy', 'sample',
}


def get_data_dir():
    """Returns the user data storage directory for GitScout (~/.local/share/gitscout)."""
    base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    data_dir = os.path.join(base, 'gitscout')
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def get_project_root():
    """Returns the root directory path of the GitScout repository."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_default_logfile():
    """Returns the default JSONL export file path."""
    return os.path.join(get_data_dir(), 'goodie_bag.jsonl')


def get_seen_events_path():
    """Returns the JSON tracking path for processed event IDs."""
    return os.path.join(get_data_dir(), 'seen_events.json')
