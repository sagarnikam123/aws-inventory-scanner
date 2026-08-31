#!/usr/bin/env python3
"""
RDS Inventory Scanner
Scans all configured AWS accounts/regions for RDS clusters and instances.

Usage:
    python get_rds_inventory.py                     # All accounts, all regions
    python get_rds_inventory.py -a "TQ OPS"         # Single account
    python get_rds_inventory.py -r us-east-1        # Single region
"""

import sys
import argparse
from pathlib import Path

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def scan_rds(session, regions, writer):
    """Scan RDS clusters and instances across all specified regions."""
    total_clusters = 0
    total_instances = 0

    for region in regions:
        try:
            rds_client = session.client('rds', region_name=region, config=BOTO_CONFIG)

            # Get clusters
            clusters = []
            try:
                cluster_response = rds_client.describe_db_clusters()
                for cluster in cluster_response.get('DBClusters', []):
                    clusters.append({
                        "identifier": cluster['DBClusterIdentifier'],
                        "engine": cluster['Engine'],
                        "engine_version": cluster.get('EngineVersion', 'N/A'),
                        "status": cluster['Status'],
                        "endpoint": cluster.get('Endpoint', 'N/A'),
                        "multi_az": cluster.get('MultiAZ', False),
                        "created_at": cluster.get('ClusterCreateTime', ''),
                    })
            except Exception as e:
                logger.warning(f"  {region}: Error listing clusters — {e}")

            # Get instances
            instances = []
            try:
                instance_response = rds_client.describe_db_instances()
                for instance in instance_response.get('DBInstances', []):
                    instances.append({
                        "identifier": instance['DBInstanceIdentifier'],
                        "engine": instance['Engine'],
                        "engine_version": instance.get('EngineVersion', 'N/A'),
                        "status": instance['DBInstanceStatus'],
                        "instance_class": instance['DBInstanceClass'],
                        "endpoint": instance.get('Endpoint', {}).get('Address', 'N/A'),
                        "multi_az": instance.get('MultiAZ', False),
                        "storage_gb": instance.get('AllocatedStorage', 0),
                        "created_at": instance.get('InstanceCreateTime', ''),
                    })
            except Exception as e:
                logger.warning(f"  {region}: Error listing instances — {e}")

            writer.set_nested("regions", region, value={"clusters": clusters, "instances": instances})
            total_clusters += len(clusters)
            total_instances += len(instances)

            if clusters or instances:
                logger.info(f"  {region}: {len(clusters)} clusters, {len(instances)} instances")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'rds', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"clusters": [], "instances": []})

    return total_clusters, total_instances


def main():
    parser = argparse.ArgumentParser(description='RDS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('rds')
    timestamp = get_timestamp()

    # If --profile is used, bypass accounts.yaml entirely
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
        "summary": {
            "total_accounts_scanned": len(accounts),
            "total_clusters": 0,
            "total_instances": 0,
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "regions": {}
            }
            continue

        output_dir = get_output_dir(account_id, "rds")
        writer = IncrementalWriter(output_dir, make_output_filename("rds", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        clusters, instances = scan_rds(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_instances", instances)
        writer.set("status", "ok")

        inventory["summary"]["total_clusters"] += clusters
        inventory["summary"]["total_instances"] += instances

    # Summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total RDS Clusters: {inventory['summary']['total_clusters']}")
    logger.info(f"  Total RDS Instances: {inventory['summary']['total_instances']}")


if __name__ == "__main__":
    run_with_timer(main)
