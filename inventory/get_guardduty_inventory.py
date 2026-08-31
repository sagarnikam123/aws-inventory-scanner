#!/usr/bin/env python3
"""
GuardDuty Inventory Scanner
Scans detectors, findings summary, and coverage. GuardDuty is $2.8k/mo.

Usage:
    python get_guardduty_inventory.py -p <profile>
    python get_guardduty_inventory.py -p <profile> -r us-east-1
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


def scan_guardduty(session, regions):
    """Scan GuardDuty detectors and findings."""
    results = {}
    totals = {"detectors": 0, "findings_high": 0, "findings_medium": 0, "findings_low": 0}

    for region in regions:
        region_data = {"detectors": []}

        try:
            gd = session.client('guardduty', region_name=region, config=BOTO_CONFIG)

            detector_ids = gd.list_detectors().get('DetectorIds', [])

            for det_id in detector_ids:
                det = gd.get_detector(DetectorId=det_id)

                # Get findings statistics
                stats = gd.get_findings_statistics(
                    DetectorId=det_id,
                    FindingStatisticTypes=['COUNT_BY_SEVERITY']
                )
                severity_counts = stats.get('FindingStatistics', {}).get('CountBySeverity', {})

                detector_info = {
                    "detector_id": det_id,
                    "status": det.get('Status', ''),
                    "service_role": det.get('ServiceRole', ''),
                    "created_at": det.get('CreatedAt', ''),
                    "updated_at": det.get('UpdatedAt', ''),
                    "features": [f.get('Name') for f in det.get('Features', []) if f.get('Status') == 'ENABLED'],
                    "findings_by_severity": severity_counts,
                }
                region_data["detectors"].append(detector_info)

                # Tally findings
                for sev, count in severity_counts.items():
                    sev_val = float(sev)
                    if sev_val >= 7.0:
                        totals["findings_high"] += count
                    elif sev_val >= 4.0:
                        totals["findings_medium"] += count
                    else:
                        totals["findings_low"] += count

        except Exception as e:
            if is_region_unsupported_error(e):
                continue
            logger.warning(f"  {region}: Error — {e}")
            continue

        det_count = len(region_data["detectors"])
        if det_count > 0:
            logger.info(f"  {region}: {det_count} detector(s)")

        results[region] = region_data
        totals["detectors"] += det_count

    return results, totals


def main():
    parser = argparse.ArgumentParser(description='GuardDuty Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('guardduty')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        if not args.profile:
            # Reuse session from --profile if already authenticated
            session = account.get("_session") or create_session(profile)
            if not session:
                continue

        output_dir = get_output_dir(account_id, "guardduty")
        writer = IncrementalWriter(output_dir, make_output_filename("guardduty", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "ok"})

        results, totals = scan_guardduty(session, regions)

        writer.update({
            "total_detectors": totals["detectors"],
            "findings_high": totals["findings_high"],
            "findings_medium": totals["findings_medium"],
            "findings_low": totals["findings_low"],
            "regions": results,
        })

        logger.info(f"📊 {name}: {totals['detectors']} detectors, "
                    f"Findings: {totals['findings_high']} high, {totals['findings_medium']} medium")


if __name__ == "__main__":
    run_with_timer(main)
