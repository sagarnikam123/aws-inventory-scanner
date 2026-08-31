#!/usr/bin/env python3
"""
CloudWatch Inventory Scanner
Scans for log groups, alarms, and dashboards across all configured accounts/regions.
Data is flushed to disk incrementally per region — partial results are saved on crash.

Usage:
    python get_cloudwatch_inventory.py                     # All accounts
    python get_cloudwatch_inventory.py -a "TQ Hosted"      # Single account
    python get_cloudwatch_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

SERVICE = "cloudwatch"


def scan_region(session, region):
    """Scan a single region for CloudWatch resources. Returns dict."""
    region_data = {"log_groups": [], "alarms": [], "dashboards": [], "status": "ok"}

    try:
        logs_client = session.client('logs', region_name=region, config=BOTO_CONFIG)
        cw_client = session.client('cloudwatch', region_name=region, config=BOTO_CONFIG)

        # Log Groups
        paginator = logs_client.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for lg in page['logGroups']:
                stored_bytes = lg.get('storedBytes', 0)
                region_data["log_groups"].append({
                    "name": lg['logGroupName'],
                    "stored_bytes": stored_bytes,
                    "stored_gb": round(stored_bytes / (1024**3), 2),
                    "retention_days": lg.get('retentionInDays', 'Never expire'),
                    "created_at": lg.get('creationTime', 0),
                })

        # Alarms
        paginator = cw_client.get_paginator('describe_alarms')
        for page in paginator.paginate():
            for alarm in page.get('MetricAlarms', []):
                region_data["alarms"].append({
                    "name": alarm['AlarmName'],
                    "state": alarm['StateValue'],
                    "metric": alarm.get('MetricName', 'N/A'),
                    "namespace": alarm.get('Namespace', 'N/A'),
                    "statistic": alarm.get('Statistic', ''),
                    "period": alarm.get('Period', 0),
                    "comparison": alarm.get('ComparisonOperator', ''),
                    "threshold": alarm.get('Threshold', 0),
                    "actions": alarm.get('AlarmActions', []),
                })

        # Dashboards
        try:
            dash_resp = cw_client.list_dashboards()
            for dash in dash_resp.get('DashboardEntries', []):
                region_data["dashboards"].append({
                    "name": dash['DashboardName'],
                    "size": dash.get('Size', 0),
                })
        except Exception:
            pass

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
            region_data["status"] = "unsupported"
        else:
            logger.warning(f"  {region}: Error — {e}")
            region_data["status"] = "error"
            region_data["error"] = str(e)

    # Compute region totals
    region_data["total_log_groups"] = len(region_data["log_groups"])
    region_data["total_alarms"] = len(region_data["alarms"])
    region_data["total_dashboards"] = len(region_data["dashboards"])
    region_data["stored_bytes"] = sum(lg.get('stored_bytes', 0) for lg in region_data["log_groups"])

    return region_data


def main():
    parser = argparse.ArgumentParser(description='CloudWatch Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('logs')
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    # Combined incremental writer
    combined_data = {
        "generated": timestamp,
        "note": "CloudWatch log groups, alarms, and dashboards per account per region.",
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "total_log_groups": 0,
            "total_alarms": 0,
            "total_dashboards": 0,
            "total_stored_gb": 0,
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        if account.get('enabled') is False:
            logger.info(f"\n⏭️  {name} ({account_id}) — skipped (no credentials)")
            continue

        logger.info(f"\n🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            combined_data["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "regions": {}
            }
            continue

        # Per-account incremental writer
        account_output = get_output_dir(account_id, SERVICE)
        account_writer = IncrementalWriter(account_output, make_output_filename(SERVICE, account_id, timestamp))
        account_writer.update({
            "name": name, "profile_used": profile, "status": "ok",
            "total_log_groups": 0, "total_alarms": 0, "total_dashboards": 0, "total_stored_gb": 0,
            "regions": {}
        })

        acct_totals = {"log_groups": 0, "alarms": 0, "dashboards": 0, "stored_bytes": 0}

        for region in regions:
            region_data = scan_region(session, region)

            # Flush this region immediately
            account_writer.set_nested("regions", region, value=region_data)

            lg_count = region_data["total_log_groups"]
            alarm_count = region_data["total_alarms"]
            stored = region_data["stored_bytes"]

            if lg_count > 0 or alarm_count > 0:
                logger.info(f"  {region}: {lg_count} log groups ({stored / (1024**3):.2f} GB), {alarm_count} alarms")

            acct_totals["log_groups"] += lg_count
            acct_totals["alarms"] += alarm_count
            acct_totals["dashboards"] += region_data["total_dashboards"]
            acct_totals["stored_bytes"] += stored

            # Update running totals in account file
            account_writer.set("total_log_groups", acct_totals["log_groups"])
            account_writer.set("total_alarms", acct_totals["alarms"])
            account_writer.set("total_dashboards", acct_totals["dashboards"])
            account_writer.set("total_stored_gb", round(acct_totals["stored_bytes"] / (1024**3), 2))

        # Update combined with this account
        combined_data["accounts"][account_id] = account_writer.get_data()

        summary = combined_data["summary"]
        summary["total_log_groups"] += acct_totals["log_groups"]
        summary["total_alarms"] += acct_totals["alarms"]
        summary["total_dashboards"] += acct_totals["dashboards"]
        summary["total_stored_gb"] += round(acct_totals["stored_bytes"] / (1024**3), 2)

        logger.info(f"  📄 Flushed: {account_id} ({acct_totals['log_groups']} log groups, {acct_totals['alarms']} alarms)")

    # Final summary
    logger.info("\n" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    final = combined_data["summary"]
    logger.info(f"  Total Log Groups:  {final['total_log_groups']}")
    logger.info(f"  Total Stored:      {final['total_stored_gb']:.2f} GB")
    logger.info(f"  Total Alarms:      {final['total_alarms']}")
    logger.info(f"  Total Dashboards:  {final['total_dashboards']}")


if __name__ == "__main__":
    run_with_timer(main)
