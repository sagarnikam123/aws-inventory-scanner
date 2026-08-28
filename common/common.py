"""
Common utilities for AWS inventory scripts.
Handles account loading, session creation, region discovery, and output management.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml
import boto3
import botocore.exceptions
from botocore.config import Config

# Boto3 client config with timeouts
BOTO_CONFIG = Config(
    connect_timeout=10,
    read_timeout=30,
    retries={'max_attempts': 2}
)

# Paths
ROOT_DIR = Path(__file__).parent.parent
ACCOUNTS_FILE = ROOT_DIR / "conf" / "accounts.yaml"
OUTPUT_DIR = ROOT_DIR / "output"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_accounts(accounts_file: Path = ACCOUNTS_FILE) -> Dict[str, Any]:
    """Load account registry from YAML."""
    if not accounts_file.exists():
        logger.error(f"Accounts file not found: {accounts_file}")
        sys.exit(1)

    with open(accounts_file) as f:
        config = yaml.safe_load(f)

    return config


def get_accounts(filter_account: Optional[str] = None) -> List[Dict[str, str]]:
    """Get account list, optionally filtered by account_id or name."""
    config = load_accounts()
    accounts = config.get("accounts", [])

    if filter_account:
        accounts = [
            a for a in accounts
            if filter_account in (a["account_id"], a["name"], a["profile"])
        ]
        if not accounts:
            logger.error(f"Account '{filter_account}' not found in accounts.yaml")
            sys.exit(1)

    return accounts


def get_regions(service: str = None) -> List[str]:
    """Get regions to scan.
    If service is provided, returns only regions where that service is available.
    Otherwise returns all AWS regions dynamically from EC2 describe_regions."""
    if service:
        try:
            session = boto3.Session()
            available = session.get_available_regions(service)
            if available:
                return available
        except Exception:
            pass

    # Fallback: get all regions dynamically
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions(AllRegions=False)
        return [r['RegionName'] for r in response['Regions']]
    except Exception:
        # Final fallback: use accounts.yaml static list
        config = load_accounts()
        return config.get("regions", ["us-east-1"])


def _validate_profile_exists(profile: str) -> bool:
    """Check if AWS profile exists in ~/.aws/credentials or ~/.aws/config."""
    # ponytail: let boto3 handle profile resolution — it checks both files,
    # supports SSO profiles, and raises ProfileNotFound with a clear message.
    # Manual configparser parsing breaks on SSO config format in Python 3.14+.
    return True


def create_session(profile: str) -> Optional[boto3.Session]:
    """Create a boto3 session for the given profile.
    Validates profile exists in ~/.aws/credentials first — stops if not found."""
    if not _validate_profile_exists(profile):
        return None

    try:
        session = boto3.Session(profile_name=profile)
        # Validate credentials via STS
        sts = session.client('sts', config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        logger.info(f"✅ Authenticated as {identity['Arn']} (Account: {identity['Account']})")
        return session
    except botocore.exceptions.ProfileNotFound:
        logger.error(f"❌ Profile '{profile}' not found in ~/.aws/config")
        return None
    except botocore.exceptions.ClientError as e:
        logger.error(f"❌ Auth failed for profile '{profile}': {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Session creation failed for '{profile}': {e}")
        return None


def get_output_dir(account_id: str, service: str) -> Path:
    """Get output directory for a specific account and service. Creates if needed."""
    output_path = OUTPUT_DIR / account_id / service
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def make_output_filename(service: str, account_id: str, timestamp: str) -> str:
    """Build a standard output filename with account ID embedded.
    Example: cost-inventory-111111111111-20260827-160839.json"""
    return f"{service}-inventory-{account_id}-{timestamp}.json"


def save_json(data: Any, output_path: Path, filename: str) -> Path:
    """Save data as JSON file. Returns the file path."""
    filepath = output_path / filename
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"📄 Saved: {filepath}")
    return filepath


class IncrementalWriter:
    """Writes inventory data incrementally — per region or per account — so nothing is lost on crash."""

    def __init__(self, output_path: Path, filename: str):
        self.filepath = output_path / filename
        output_path.mkdir(parents=True, exist_ok=True)
        self.data = {}

    def update(self, data: dict):
        """Merge new data into the inventory and flush to disk immediately."""
        self._deep_merge(self.data, data)
        self._flush()

    def set(self, key: str, value: Any):
        """Set a top-level key and flush."""
        self.data[key] = value
        self._flush()

    def set_nested(self, *keys, value: Any):
        """Set a nested key path and flush. E.g. set_nested('accounts', '12345', 'regions', 'us-east-1', value=[...])"""
        d = self.data
        for key in keys[:-1]:
            if key not in d:
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value
        self._flush()

    def get_data(self) -> dict:
        """Return current accumulated data."""
        return self.data

    def _flush(self):
        """Write current state to disk."""
        with open(self.filepath, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)

    def _deep_merge(self, base: dict, override: dict):
        """Recursively merge override into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value


def get_timestamp() -> str:
    """Get current timestamp for filenames."""
    return time.strftime("%Y%m%d-%H%M%S")


def get_disabled_regions(session: boto3.Session) -> List[str]:
    """Get regions that are disabled for the account."""
    try:
        account_client = session.client('account', config=BOTO_CONFIG)
        response = account_client.list_regions()
        disabled = [
            r['RegionName'] for r in response['Regions']
            if r['RegionOptStatus'] == 'DISABLED'
        ]
        return disabled
    except Exception as e:
        logger.warning(f"Could not check region status: {e}")
        return []


def create_session_with_identity(profile: str) -> tuple:
    """Create a session from a raw profile and return (session, account_id, arn).
    Auto-detects account ID via STS — no accounts.yaml lookup needed.
    Validates profile exists in ~/.aws/credentials first — stops if not found."""
    if not _validate_profile_exists(profile):
        return None, None, None

    try:
        session = boto3.Session(profile_name=profile)
        sts = session.client('sts', config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
        logger.info(f"✅ Authenticated as {arn} (Account: {account_id})")
        return session, account_id, arn
    except Exception as e:
        logger.error(f"❌ Auth failed for profile '{profile}': {e}")
        return None, None, None


def add_common_args(parser):
    """Add common CLI arguments to an argparse parser."""
    parser.add_argument(
        '--account', '-a',
        help='Filter to specific account (ID, name, or profile) from accounts.yaml. Omit to scan all.',
        default=None
    )
    parser.add_argument(
        '--profile', '-p',
        help='Use a specific AWS profile directly (bypasses accounts.yaml). Account ID auto-detected via STS.',
        default=None
    )
    parser.add_argument(
        '--region', '-r',
        help='Filter to specific region. Omit to scan all available regions for the service.',
        default=None
    )
    parser.add_argument(
        '--output-dir', '-o',
        help='Custom output directory (default: ./output/<account_id>/<service>)',
        default=None
    )
    return parser


def is_region_unsupported_error(error) -> bool:
    """Check if an AWS error indicates the region doesn't support the service."""
    error_str = str(error)
    unsupported_indicators = [
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "AuthFailure",
        "OptInRequired",
        "not available in this region",
        "Could not connect to the endpoint URL",
        "EndpointConnectionError",
    ]
    return any(indicator in error_str for indicator in unsupported_indicators)


def log_region_skip(region: str, service: str, error: str = None):
    """Log that a region is being skipped for a service."""
    if error:
        logger.debug(f"  ⏭️  {region}: {service} not supported — {error[:80]}")
    else:
        logger.debug(f"  ⏭️  {region}: {service} not supported")


def format_elapsed(seconds: float) -> str:
    """Format elapsed seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s"


def run_with_timer(main_func):
    """Wrap a main() function with elapsed time logging."""
    start = time.time()
    success = False
    skip_log = False
    try:
        main_func()
        success = True
    except SystemExit as e:
        if e.code is None or e.code == 0:
            skip_log = True
        raise
    finally:
        if not skip_log:
            elapsed = time.time() - start
            script_name = Path(sys.argv[0]).name
            status = "completed" if success else "failed after"
            logger.info(f"\n⏱️  {script_name} {status} {format_elapsed(elapsed)}")
