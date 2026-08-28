#!/usr/bin/env python3
"""
Amazon SQS Inventory Scanner
Scans all configured AWS accounts/regions for SQS queues.

Usage:
    python get_sqs_inventory.py
    python get_sqs_inventory.py -a "TQ Primary"
    python get_sqs_inventory.py -r us-east-1
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

import argparse

SERVICE = "sqs"


def scan_sqs(session, regions, writer):
    """Scan SQS queues across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('sqs', region_name=region, config=BOTO_CONFIG)
            queues = []

            paginator = client.get_paginator('list_queues')
            for page in paginator.paginate():
                for url in page.get('QueueUrls', []):
                    try:
                        attrs = client.get_queue_attributes(
                            QueueUrl=url,
                            AttributeNames=['All']
                        ).get('Attributes', {})

                        queues.append({
                            "queue_url": url,
                            "queue_name": url.rsplit('/', 1)[-1],
                            "arn": attrs.get('QueueArn', 'N/A'),
                            "type": "FIFO" if url.endswith('.fifo') else "Standard",
                            "approximate_messages": int(attrs.get('ApproximateNumberOfMessages', 0)),
                            "approximate_messages_delayed": int(attrs.get('ApproximateNumberOfMessagesDelayed', 0)),
                            "approximate_messages_not_visible": int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0)),
                            "visibility_timeout_sec": int(attrs.get('VisibilityTimeout', 0)),
                            "message_retention_sec": int(attrs.get('MessageRetentionPeriod', 0)),
                            "max_message_size_bytes": int(attrs.get('MaximumMessageSize', 0)),
                            "delay_seconds": int(attrs.get('DelaySeconds', 0)),
                            "created_timestamp": attrs.get('CreatedTimestamp', ''),
                            "last_modified_timestamp": attrs.get('LastModifiedTimestamp', ''),
                            "redrive_policy": attrs.get('RedrivePolicy', ''),
                            "kms_key_id": attrs.get('KmsMasterKeyId', ''),
                        })
                    except Exception as e:
                        logger.warning(f"  {region}: Error getting attrs for {url} — {e}")

            writer.set_nested("regions", region, value=queues)
            total += len(queues)

            if queues:
                logger.info(f"  {region}: {len(queues)} queues")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='SQS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('sqs')
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"\n🔍 {name} ({account_id}) — profile: {profile}")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress"})

        total = scan_sqs(session, regions, writer)
        writer.set("total_queues", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} queues")

    logger.info("\n" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
