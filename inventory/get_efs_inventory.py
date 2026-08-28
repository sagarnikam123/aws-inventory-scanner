#!/usr/bin/env python3
"""
EFS (Elastic File System) Inventory Scanner
Scans file systems with size, throughput mode, and mount targets.

Usage:
    python get_efs_inventory.py                     # All accounts, all regions
    python get_efs_inventory.py -a "TQ Hosted"      # Single account
    python get_efs_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def scan_efs(session, regions, writer):
    """Scan EFS file systems across all specified regions."""
    total_filesystems = 0
    total_size_gb = 0

    for region in regions:
        try:
            efs = session.client('efs', region_name=region, config=BOTO_CONFIG)
            resp = efs.describe_file_systems()
            filesystems = []

            for fs in resp.get('FileSystems', []):
                size_bytes = fs.get('SizeInBytes', {}).get('Value', 0)
                size_gb = round(size_bytes / (1024**3), 2)

                # Get mount targets
                mt_count = fs.get('NumberOfMountTargets', 0)

                fs_info = {
                    "file_system_id": fs['FileSystemId'],
                    "name": fs.get('Name', 'N/A'),
                    "lifecycle_state": fs['LifeCycleState'],
                    "performance_mode": fs.get('PerformanceMode', 'generalPurpose'),
                    "throughput_mode": fs.get('ThroughputMode', 'bursting'),
                    "provisioned_throughput_mibps": fs.get('ProvisionedThroughputInMibps', 0),
                    "size_gb": size_gb,
                    "mount_targets": mt_count,
                    "encrypted": fs.get('Encrypted', False),
                    "created_at": fs.get('CreationTime', ''),
                    "tags": fs.get('Tags', []),
                }
                filesystems.append(fs_info)
                total_size_gb += size_gb

            writer.set_nested("regions", region, value=filesystems)
            total_filesystems += len(filesystems)

            if filesystems:
                region_size = sum(f['size_gb'] for f in filesystems)
                logger.info(f"  {region}: {len(filesystems)} file systems ({region_size:.1f} GB)")

        except Exception as e:
            logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_filesystems, total_size_gb


def main():
    parser = argparse.ArgumentParser(description='EFS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('efs')
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_filesystems": 0, "total_size_gb": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"\n🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "regions": {}}
            continue

        output_dir = get_output_dir(account_id, "efs")
        writer = IncrementalWriter(output_dir, make_output_filename("efs", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        fs_count, size_gb = scan_efs(session, regions, writer)

        writer.set("total_filesystems", fs_count)
        writer.set("total_size_gb", round(size_gb, 2))
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        inventory["summary"]["total_filesystems"] += fs_count
        inventory["summary"]["total_size_gb"] += size_gb

    logger.info("\n" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total EFS File Systems: {inventory['summary']['total_filesystems']}")
    logger.info(f"  Total Size: {inventory['summary']['total_size_gb']:.1f} GB (💰 ~${inventory['summary']['total_size_gb'] * 0.30:.0f}/mo at $0.30/GB)")


if __name__ == "__main__":
    run_with_timer(main)
