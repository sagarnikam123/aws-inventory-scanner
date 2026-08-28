#!/usr/bin/env python3
"""
Lambda Inventory Scanner
Scans Lambda functions across all regions.

Usage:
    python get_lambda_inventory.py -p <profile>
    python get_lambda_inventory.py -p <profile> -r us-east-1
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


def scan_lambda(session, regions, writer):
    """Scan Lambda functions, writing incrementally per region."""
    totals = {"functions": 0}

    for region in regions:
        region_data = []

        try:
            lam = session.client('lambda', region_name=region, config=BOTO_CONFIG)
            cw = session.client('cloudwatch', region_name=region, config=BOTO_CONFIG)

            # Time window for invocation check (last 30 days)
            from datetime import datetime, timezone, timedelta
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=30)

            paginator = lam.get_paginator('list_functions')
            for page in paginator.paginate():
                for fn in page.get('Functions', []):
                    fn_name = fn['FunctionName']
                    entry = {
                        "name": fn_name,
                        "runtime": fn.get('Runtime', 'N/A'),
                        "memory_mb": fn.get('MemorySize', 0),
                        "timeout_sec": fn.get('Timeout', 0),
                        "code_size_mb": round(fn.get('CodeSize', 0) / (1024*1024), 2),
                        "handler": fn.get('Handler', ''),
                        "last_modified": fn.get('LastModified', ''),
                        "architectures": fn.get('Architectures', []),
                        "last_invocation_time": None,
                        "invocations_last_30d": 0,
                    }

                    # Query CloudWatch for last invocation
                    try:
                        resp = cw.get_metric_statistics(
                            Namespace='AWS/Lambda',
                            MetricName='Invocations',
                            Dimensions=[{'Name': 'FunctionName', 'Value': fn_name}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,  # 1 day granularity
                            Statistics=['Sum'],
                        )
                        datapoints = resp.get('Datapoints', [])
                        if datapoints:
                            # Sort by timestamp descending
                            datapoints.sort(key=lambda d: d['Timestamp'], reverse=True)
                            entry["last_invocation_time"] = datapoints[0]['Timestamp'].isoformat()
                            entry["invocations_last_30d"] = int(sum(d['Sum'] for d in datapoints))
                    except Exception:
                        pass  # ponytail: CloudWatch throttle — skip gracefully

                    region_data.append(entry)

        except Exception as e:
            if is_region_unsupported_error(e):
                continue
            logger.warning(f"  {region}: Error — {e}")
            continue

        count = len(region_data)
        if count > 0:
            logger.info(f"  {region}: {count} function(s)")
            writer.set_nested('regions', region, value=region_data)

        totals["functions"] += count

    return totals


def main():
    parser = argparse.ArgumentParser(description='Lambda Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('lambda')
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

        output_dir = get_output_dir(account_id, "lambda")
        writer = IncrementalWriter(output_dir, make_output_filename("lambda", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "ok"})

        totals = scan_lambda(session, regions, writer)
        writer.update({"total_functions": totals["functions"]})

        logger.info(f"\n📊 {name}: {totals['functions']} Lambda functions total")


if __name__ == "__main__":
    run_with_timer(main)
