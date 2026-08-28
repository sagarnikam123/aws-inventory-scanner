#!/usr/bin/env python3
"""
NAT Gateway Inventory Scanner
NAT Gateways are the #1 VPC cost driver at $9.4k/mo. This script lists all NATs
with their associated VPCs, data processing estimates, and cost breakdown.

Usage:
    python get_nat_gateway_inventory.py -p <profile>
    python get_nat_gateway_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)


def get_name_tag(tags):
    if not tags:
        return 'N/A'
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'N/A'


def scan_nat_gateways(session, regions):
    """Scan all NAT Gateways across regions."""
    results = {}
    totals = {"nat_gateways": 0, "estimated_monthly_cost": 0}

    NAT_HOURLY_COST = 0.045  # $/hr per NAT gateway
    HOURS_PER_MONTH = 720

    for region in regions:
        region_data = []

        try:
            ec2 = session.client('ec2', region_name=region, config=BOTO_CONFIG)

            paginator = ec2.get_paginator('describe_nat_gateways')
            for page in paginator.paginate(Filter=[{'Name': 'state', 'Values': ['available']}]):
                for nat in page.get('NatGateways', []):
                    nat_info = {
                        "nat_gateway_id": nat['NatGatewayId'],
                        "name": get_name_tag(nat.get('Tags')),
                        "state": nat['State'],
                        "vpc_id": nat.get('VpcId', ''),
                        "subnet_id": nat.get('SubnetId', ''),
                        "connectivity_type": nat.get('ConnectivityType', 'public'),
                        "public_ip": nat.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A',
                        "private_ip": nat.get('NatGatewayAddresses', [{}])[0].get('PrivateIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A',
                        "created_at": nat.get('CreateTime', ''),
                        "monthly_base_cost_usd": round(NAT_HOURLY_COST * HOURS_PER_MONTH, 2),
                    }
                    region_data.append(nat_info)

        except Exception as e:
            if is_region_unsupported_error(e):
                continue
            logger.warning(f"  {region}: Error — {e}")
            continue

        count = len(region_data)
        if count > 0:
            logger.info(f"  {region}: {count} NAT gateway(s) (💰 ~${count * NAT_HOURLY_COST * HOURS_PER_MONTH:.0f}/mo base)")

        results[region] = region_data
        totals["nat_gateways"] += count
        totals["estimated_monthly_cost"] += count * NAT_HOURLY_COST * HOURS_PER_MONTH

    return results, totals


def main():
    parser = argparse.ArgumentParser(description='NAT Gateway Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('ec2')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"\n🔍 {name} ({account_id})")

        if not args.profile:
            # Reuse session from --profile if already authenticated
            session = account.get("_session") or create_session(profile)
            if not session:
                continue

        output_dir = get_output_dir(account_id, "nat-gateways")
        writer = IncrementalWriter(output_dir, make_output_filename("nat-gateway", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "ok"})

        results, totals = scan_nat_gateways(session, regions)

        writer.update({
            "total_nat_gateways": totals["nat_gateways"],
            "estimated_monthly_base_cost_usd": round(totals["estimated_monthly_cost"], 2),
            "note": "Base cost only ($0.045/hr per NAT). Data processing adds $0.045/GB on top.",
            "regions": results,
        })

        logger.info(f"\n📊 {name}: {totals['nat_gateways']} NAT gateways, "
                    f"~${totals['estimated_monthly_cost']:.0f}/mo base cost")


if __name__ == "__main__":
    run_with_timer(main)
