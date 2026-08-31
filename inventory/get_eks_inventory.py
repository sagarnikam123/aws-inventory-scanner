#!/usr/bin/env python3
"""
EKS Cluster Inventory Scanner
Scans all configured AWS accounts/regions and produces a JSON inventory.

Usage:
    python get_eks_inventory.py                    # All accounts, all regions
    python get_eks_inventory.py -a "TQ Primary"    # Single account
    python get_eks_inventory.py -r us-east-1       # Single region across all accounts
"""

import sys
import argparse
from pathlib import Path

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, save_json, get_timestamp, get_disabled_regions, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)


def scan_eks_clusters(session, regions, disabled_regions):
    """Scan EKS clusters across all specified regions."""
    results = {}
    total_clusters = 0

    for region in regions:
        if region in disabled_regions:
            results[region] = {"status": "disabled", "clusters": []}
            continue

        try:
            eks_client = session.client('eks', region_name=region, config=BOTO_CONFIG)
            response = eks_client.list_clusters()
            clusters = response.get('clusters', [])
            eks_client.close()

            results[region] = {"status": "ok", "clusters": clusters}
            total_clusters += len(clusters)

            if clusters:
                logger.info(f"  {region}: {len(clusters)} clusters")

        except Exception as e:
            error_type = type(e).__name__
            if "UnrecognizedClientException" in str(e):
                results[region] = {"status": "auth_error", "clusters": [], "error": "Region not enabled"}
            elif "Timeout" in error_type:
                results[region] = {"status": "timeout", "clusters": [], "error": str(e)}
            else:
                results[region] = {"status": "error", "clusters": [], "error": str(e)}

    return results, total_clusters


def scan_cluster_details(session, region, cluster_name):
    """Get detailed info for a single EKS cluster."""
    try:
        eks_client = session.client('eks', region_name=region, config=BOTO_CONFIG)
        response = eks_client.describe_cluster(name=cluster_name)
        cluster = response['cluster']
        eks_client.close()

        return {
            "name": cluster['name'],
            "version": cluster.get('version', 'unknown'),
            "status": cluster.get('status', 'unknown'),
            "platform_version": cluster.get('platformVersion', ''),
            "vpc_config": {
                "vpc_id": cluster.get('resourcesVpcConfig', {}).get('vpcId', ''),
                "subnet_ids": cluster.get('resourcesVpcConfig', {}).get('subnetIds', []),
                "security_group_ids": cluster.get('resourcesVpcConfig', {}).get('securityGroupIds', []),
                "endpoint_public": cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False),
                "endpoint_private": cluster.get('resourcesVpcConfig', {}).get('endpointPrivateAccess', False),
                "public_access_cidrs": cluster.get('resourcesVpcConfig', {}).get('publicAccessCidrs', []),
            },
            "kubernetes_network_config": {
                "service_ipv4_cidr": cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv4Cidr', ''),
                "ip_family": cluster.get('kubernetesNetworkConfig', {}).get('ipFamily', ''),
            },
            "tags": cluster.get('tags', {}),
        }
    except Exception as e:
        logger.warning(f"  Could not describe cluster {cluster_name}: {e}")
        return {"name": cluster_name, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description='EKS Cluster Inventory Scanner')
    add_common_args(parser)
    parser.add_argument('--details', '-d', action='store_true',
                        help='Include cluster details (version, status, tags). Slower but richer.')
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    # If --profile is used, bypass accounts.yaml entirely
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else get_regions('eks')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    # Incremental writer for combined output — flushes after every region
    combined_output = get_output_dir("combined", "eks")
    combined_data = {
        "generated": timestamp,
        "note": "EKS clusters per AWS account per region.",
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "accounts_with_clusters": 0,
            "total_eks_clusters_found": 0,
            "clusters_by_account": {}
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
            combined_data["accounts"][account_id] = {
                "status": "auth_failed", "total_clusters": 0, "regions": {}
            }
            continue

        # Per-account incremental writer
        account_output = get_output_dir(account_id, "eks")
        account_writer = IncrementalWriter(account_output, make_output_filename("eks", account_id, timestamp))
        account_writer.update({
            "name": name, "profile_used": profile, "status": "ok",
            "total_clusters": 0, "regions": {}
        })

        disabled = get_disabled_regions(session)
        total = 0

        for region in regions:
            if region in disabled:
                account_writer.set_nested("regions", region, value=[])
                continue

            try:
                eks_client = session.client('eks', region_name=region, config=BOTO_CONFIG)
                response = eks_client.list_clusters()
                clusters = response.get('clusters', [])
                eks_client.close()

                if clusters:
                    logger.info(f"  {region}: {len(clusters)} clusters")

                if args.details and clusters:
                    detailed = [scan_cluster_details(session, region, c) for c in clusters]
                    account_writer.set_nested("regions", region, value=detailed)
                else:
                    # Always include k8s version + vpc_id — cheap single API call per cluster
                    enriched = []
                    for c in clusters:
                        try:
                            desc = session.client('eks', region_name=region, config=BOTO_CONFIG).describe_cluster(name=c)
                            cluster_info = desc['cluster']
                            enriched.append({
                                "name": c,
                                "version": cluster_info.get('version', 'unknown'),
                                "vpc_id": cluster_info.get('resourcesVpcConfig', {}).get('vpcId', ''),
                            })
                        except Exception:
                            enriched.append({"name": c, "version": "unknown", "vpc_id": ""})
                    account_writer.set_nested("regions", region, value=enriched)

                total += len(clusters)
                account_writer.set("total_clusters", total)

            except Exception as e:
                if is_region_unsupported_error(e):
                    log_region_skip(region, 'eks', str(e))
                else:
                    logger.warning(f"  {region}: Error — {e}")
                account_writer.set_nested("regions", region, value=[])

        # Update combined with this account's data
        combined_data["accounts"][account_id] = account_writer.get_data()
        combined_data["summary"]["clusters_by_account"][account_id] = total

        # Update summary totals
        summary = combined_data["summary"]
        summary["total_eks_clusters_found"] += total
        if total > 0:
            summary["accounts_with_clusters"] += 1

        logger.info(f"  📄 Flushed: {account_id} ({total} clusters)")

    # Print summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    final = combined_data
    for acct_id, count in final["summary"]["clusters_by_account"].items():
        acct_name = final["accounts"][acct_id].get("name", acct_id)
        logger.info(f"  {acct_name} ({acct_id}): {count} clusters")
    logger.info(f"  TOTAL: {final['summary']['total_eks_clusters_found']} clusters")


if __name__ == "__main__":
    run_with_timer(main)
