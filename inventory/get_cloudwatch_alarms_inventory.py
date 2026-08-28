#!/usr/bin/env python3
"""
CloudWatch Inventory Scanner
Scans alarms, log groups, and dashboards. CloudWatch is $6.7k/mo — worth understanding.

Usage:
    python get_cloudwatch_alarms_inventory.py -p <profile>
    python get_cloudwatch_alarms_inventory.py -p <profile> -r us-east-1
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


def scan_cloudwatch(session, regions):
    """Scan CloudWatch alarms, log groups, and dashboards."""
    results = {}
    totals = {"alarms": 0, "log_groups": 0, "log_storage_bytes": 0, "dashboards": 0}

    for region in regions:
        region_data = {"alarms": [], "log_groups": [], "dashboards": []}

        try:
            cw = session.client('cloudwatch', region_name=region, config=BOTO_CONFIG)
            logs = session.client('logs', region_name=region, config=BOTO_CONFIG)

            # Alarms
            paginator = cw.get_paginator('describe_alarms')
            for page in paginator.paginate():
                for alarm in page.get('MetricAlarms', []):
                    region_data["alarms"].append({
                        "name": alarm['AlarmName'],
                        "state": alarm['StateValue'],
                        "metric": alarm.get('MetricName', ''),
                        "namespace": alarm.get('Namespace', ''),
                        "statistic": alarm.get('Statistic', ''),
                        "period": alarm.get('Period', 0),
                        "threshold": alarm.get('Threshold', 0),
                        "actions": alarm.get('AlarmActions', []),
                    })

            # Log Groups (biggest cost driver — storage + ingestion)
            paginator = logs.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for lg in page.get('logGroups', []):
                    stored_bytes = lg.get('storedBytes', 0)
                    region_data["log_groups"].append({
                        "name": lg['logGroupName'],
                        "stored_bytes": stored_bytes,
                        "stored_gb": round(stored_bytes / (1024**3), 2),
                        "retention_days": lg.get('retentionInDays', 'Never expires'),
                        "created": lg.get('creationTime', ''),
                    })
                    totals["log_storage_bytes"] += stored_bytes

            # Dashboards (only in us-east-1 typically but check all)
            try:
                dash_resp = cw.list_dashboards()
                for d in dash_resp.get('DashboardEntries', []):
                    region_data["dashboards"].append({
                        "name": d['DashboardName'],
                        "size": d.get('Size', 0),
                    })
            except Exception:
                pass

        except Exception as e:
            if is_region_unsupported_error(e):
                continue
            logger.warning(f"  {region}: Error — {e}")
            continue

        alarm_count = len(region_data["alarms"])
        lg_count = len(region_data["log_groups"])

        if alarm_count > 0 or lg_count > 0:
            logger.info(f"  {region}: {alarm_count} alarms, {lg_count} log groups")

        results[region] = region_data
        totals["alarms"] += alarm_count
        totals["log_groups"] += lg_count
        totals["dashboards"] += len(region_data["dashboards"])

    return results, totals


def main():
    parser = argparse.ArgumentParser(description='CloudWatch Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('logs')
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

        output_dir = get_output_dir(account_id, "cloudwatch")
        writer = IncrementalWriter(output_dir, make_output_filename("cloudwatch", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "ok"})

        results, totals = scan_cloudwatch(session, regions)

        writer.update({
            "total_alarms": totals["alarms"],
            "total_log_groups": totals["log_groups"],
            "total_log_storage_gb": round(totals["log_storage_bytes"] / (1024**3), 2),
            "total_dashboards": totals["dashboards"],
            "regions": results,
        })

        logger.info(f"\n📊 {name}: {totals['alarms']} alarms, {totals['log_groups']} log groups, "
                    f"{round(totals['log_storage_bytes']/(1024**3), 1)} GB stored")


if __name__ == "__main__":
    run_with_timer(main)
