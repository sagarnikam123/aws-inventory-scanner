#!/usr/bin/env python3
"""
Global Accelerator Inventory Scanner
Scans accelerators, listeners, and endpoint groups (Global Accelerator is global, queried from us-west-2).

Usage:
    python get_globalaccelerator_inventory.py                     # All accounts
    python get_globalaccelerator_inventory.py -a "TQ Hosted"      # Single account
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, save_json, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename,
)


def scan_global_accelerator(session):
    """Scan Global Accelerator resources (global service, query from us-west-2)."""
    accelerators = []

    try:
        ga = session.client('globalaccelerator', region_name='us-west-2', config=BOTO_CONFIG)
        resp = ga.list_accelerators()

        for accel in resp.get('Accelerators', []):
            accel_arn = accel['AcceleratorArn']

            # Get listeners
            listeners = []
            try:
                lr = ga.list_listeners(AcceleratorArn=accel_arn)
                for listener in lr.get('Listeners', []):
                    listeners.append({
                        "listener_arn": listener['ListenerArn'],
                        "protocol": listener.get('Protocol', 'TCP'),
                        "port_ranges": listener.get('PortRanges', []),
                    })
            except Exception:
                pass

            accel_info = {
                "name": accel['Name'],
                "arn": accel_arn,
                "status": accel.get('Status', 'unknown'),
                "enabled": accel.get('Enabled', False),
                "ip_address_type": accel.get('IpAddressType', ''),
                "ip_addresses": [ip.get('IpAddress', '') for ip in accel.get('IpSets', [])],
                "dns_name": accel.get('DnsName', ''),
                "listeners": listeners,
                "created_at": accel.get('CreatedTime', ''),
            }
            accelerators.append(accel_info)

        if accelerators:
            logger.info(f"  {len(accelerators)} accelerators found")

    except Exception as e:
        logger.warning(f"  Error: {e}")

    return accelerators


def main():
    parser = argparse.ArgumentParser(description='Global Accelerator Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) (Global Accelerator is global)")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_accelerators": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"\n🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "accelerators": []}
            continue

        accelerators = scan_global_accelerator(session)

        account_entry = {
            "name": name, "profile_used": profile, "status": "ok",
            "total_accelerators": len(accelerators), "accelerators": accelerators
        }

        inventory["accounts"][account_id] = account_entry
        inventory["summary"]["total_accelerators"] += len(accelerators)

        output_dir = get_output_dir(account_id, "globalaccelerator")
        save_json(account_entry, output_dir, make_output_filename("globalaccelerator", account_id, timestamp))

    logger.info("\n" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total Accelerators: {inventory['summary']['total_accelerators']} (💰 ~${inventory['summary']['total_accelerators'] * 18:.0f}/mo fixed + data transfer)")


if __name__ == "__main__":
    run_with_timer(main)
