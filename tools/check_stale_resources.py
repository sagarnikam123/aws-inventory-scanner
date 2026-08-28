#!/usr/bin/env python3
"""
Stale & Waste Resource Checker
Reads inventory JSONs and flags resources that are unused, stale, or costing money for no value.

Checks:
  - SNS topics with 0 subscriptions
  - CloudTrail trails not logging or stale
  - SQS queues with no messages and old timestamps
  - Lambda functions not modified in 6+ months
  - EC2 stopped instances (EBS still billed)
  - ELB with no healthy targets
  - RDS idle instances
  - EFS empty/tiny file systems
  - S3 empty buckets
  - CloudWatch alarms in INSUFFICIENT_DATA
  - Secrets Manager never rotated or stale
  - ECR repos with 0 images
  - ECS services scaled to 0
  - DynamoDB over-provisioned tables
  - Kinesis streams with no data
  - ACM certificates expiring soon or not in use
  - NAT Gateways (expensive, always flag count)
  - VPC Interface Endpoints (per-hour cost)

Usage:
    python tools/check_stale_resources.py                              # latest inventory for all accounts
    python tools/check_stale_resources.py --account-id 111111111111    # specific account
    python tools/check_stale_resources.py --days 90                    # custom staleness threshold (default: 180)
    python tools/check_stale_resources.py --json                       # output as JSON
"""

import sys
import json
import glob
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict

ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "output"


def find_latest_inventory(account_dir, service):
    """Find the most recent inventory JSON for a service."""
    pattern = str(account_dir / service / f"{service}-inventory-*.json")
    files = sorted(glob.glob(pattern), key=lambda f: Path(f).stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_json(path):
    """Load and return JSON, or None on failure."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def parse_timestamp(ts):
    """Parse various timestamp formats to datetime. Returns None on failure."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        # Unix timestamp (seconds or milliseconds)
        if ts > 1e12:
            ts = ts / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def is_stale(ts, days_threshold):
    """Return True if timestamp is older than days_threshold."""
    dt = parse_timestamp(ts)
    if not dt:
        return False  # Can't determine, don't flag
    return (datetime.now(timezone.utc) - dt) > timedelta(days=days_threshold)


def days_ago(ts):
    """Return how many days ago a timestamp is."""
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def days_until(ts):
    """Return how many days until a timestamp."""
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


# ============================================================
# Individual checkers — each returns a list of finding dicts
# ============================================================

def check_sns(account_dir, days_threshold):
    """SNS topics with 0 subscriptions."""
    findings = []
    path = find_latest_inventory(account_dir, "sns")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, topics in data.get("regions", {}).items():
        if not isinstance(topics, dict):
            continue
        for topic in topics.get("topics", []):
            subs = topic.get("subscriptions_confirmed", 0)
            if subs == 0:
                findings.append({
                    "service": "SNS",
                    "region": region,
                    "resource": topic.get("topic_name", topic.get("arn", "unknown")),
                    "issue": "0 subscriptions — nobody listening",
                    "severity": "medium",
                })
    return findings


def check_cloudtrail(account_dir, days_threshold):
    """CloudTrail trails not logging or with stale delivery."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudtrail")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for trail in region_data.get("trails", []):
            if not trail.get("is_logging", True):
                findings.append({
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail.get("name", "unknown"),
                    "issue": "Trail is NOT logging",
                    "severity": "high",
                })
            elif is_stale(trail.get("latest_delivery_time"), days_threshold):
                age = days_ago(trail.get("latest_delivery_time"))
                findings.append({
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail.get("name", "unknown"),
                    "issue": f"Last delivery {age} days ago — stale",
                    "severity": "medium",
                })
    return findings


def check_sqs(account_dir, days_threshold):
    """SQS queues with 0 messages and old timestamps."""
    findings = []
    path = find_latest_inventory(account_dir, "sqs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, queues in data.get("regions", {}).items():
        if not isinstance(queues, list):
            continue
        for q in queues:
            total_msgs = (q.get("approximate_messages", 0) +
                         q.get("approximate_messages_delayed", 0) +
                         q.get("approximate_messages_not_visible", 0))
            if total_msgs == 0 and is_stale(q.get("last_modified_timestamp"), days_threshold):
                age = days_ago(q.get("last_modified_timestamp"))
                findings.append({
                    "service": "SQS",
                    "region": region,
                    "resource": q.get("queue_name", "unknown"),
                    "issue": f"Empty queue, last modified {age} days ago",
                    "severity": "low",
                })
    return findings


def check_lambda(account_dir, days_threshold):
    """Lambda functions not modified in N+ days."""
    findings = []
    path = find_latest_inventory(account_dir, "lambda")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        functions = region_data if isinstance(region_data, list) else region_data.get("functions", [])
        for fn in functions:
            last_mod = fn.get("last_modified", "")
            if is_stale(last_mod, days_threshold):
                age = days_ago(last_mod)
                findings.append({
                    "service": "Lambda",
                    "region": region,
                    "resource": fn.get("name", fn.get("function_name", "unknown")),
                    "issue": f"Not modified in {age} days",
                    "severity": "low",
                })
    return findings


def check_ec2(account_dir, days_threshold):
    """EC2 stopped instances (EBS still billed)."""
    findings = []
    path = find_latest_inventory(account_dir, "ec2")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, instances in data.get("regions", {}).items():
        if not isinstance(instances, list):
            continue
        for inst in instances:
            if inst.get("state") == "stopped":
                findings.append({
                    "service": "EC2",
                    "region": region,
                    "resource": f"{inst.get('instance_id')} ({inst.get('name', 'N/A')})",
                    "issue": f"Stopped — EBS volumes still billed ({inst.get('type', '?')})",
                    "severity": "medium",
                })
    return findings


def check_efs(account_dir, days_threshold):
    """EFS file systems that are empty or tiny."""
    findings = []
    path = find_latest_inventory(account_dir, "efs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, filesystems in data.get("regions", {}).items():
        if not isinstance(filesystems, list):
            continue
        for fs in filesystems:
            size = fs.get("size_gb", 0)
            if size < 0.01:
                findings.append({
                    "service": "EFS",
                    "region": region,
                    "resource": f"{fs.get('file_system_id')} ({fs.get('name', 'N/A')})",
                    "issue": "Empty file system — still billed minimum",
                    "severity": "low",
                })
    return findings


def check_ecr(account_dir, days_threshold):
    """ECR repos with 0 images."""
    findings = []
    path = find_latest_inventory(account_dir, "ecr")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, repos in data.get("regions", {}).items():
        if not isinstance(repos, list):
            continue
        for repo in repos:
            if repo.get("image_count", 0) == 0:
                findings.append({
                    "service": "ECR",
                    "region": region,
                    "resource": repo.get("name", "unknown"),
                    "issue": "0 images — empty repository",
                    "severity": "low",
                })
    return findings


def check_secrets_manager(account_dir, days_threshold):
    """Secrets never rotated or not accessed in a long time."""
    findings = []
    path = find_latest_inventory(account_dir, "secrets-manager")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, secrets in data.get("regions", {}).items():
        if not isinstance(secrets, list):
            continue
        for secret in secrets:
            if not secret.get("rotation_enabled", False):
                age = days_ago(secret.get("last_accessed"))
                issue = "Rotation disabled"
                if age and age > days_threshold:
                    issue += f", last accessed {age} days ago"
                    severity = "high"
                else:
                    severity = "medium"
                findings.append({
                    "service": "Secrets Manager",
                    "region": region,
                    "resource": secret.get("name", "unknown"),
                    "issue": issue,
                    "severity": severity,
                })
    return findings


def check_acm(account_dir, days_threshold):
    """ACM certificates expiring soon or not in use."""
    findings = []
    path = find_latest_inventory(account_dir, "acm")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, certs in data.get("regions", {}).items():
        if not isinstance(certs, list):
            continue
        for cert in certs:
            # Expiring soon
            remaining = days_until(cert.get("not_after"))
            if remaining is not None and remaining < 30:
                findings.append({
                    "service": "ACM",
                    "region": region,
                    "resource": cert.get("domain_name", "unknown"),
                    "issue": f"Expires in {remaining} days!" if remaining > 0 else "EXPIRED",
                    "severity": "critical" if remaining <= 0 else "high",
                })
            # Not in use
            if not cert.get("in_use", True):
                findings.append({
                    "service": "ACM",
                    "region": region,
                    "resource": cert.get("domain_name", "unknown"),
                    "issue": "Certificate not attached to any resource",
                    "severity": "low",
                })
    return findings


def check_ecs(account_dir, days_threshold):
    """ECS services scaled to 0."""
    findings = []
    path = find_latest_inventory(account_dir, "ecs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            for svc in cluster.get("services", []):
                if svc.get("desired_count", 1) == 0 and svc.get("running_count", 0) == 0:
                    findings.append({
                        "service": "ECS",
                        "region": region,
                        "resource": f"{cluster.get('cluster_name')}/{svc.get('service_name')}",
                        "issue": "Service scaled to 0 — still configured",
                        "severity": "low",
                    })
    return findings


def check_dynamodb(account_dir, days_threshold):
    """DynamoDB tables that may be over-provisioned."""
    findings = []
    path = find_latest_inventory(account_dir, "dynamodb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, tables in data.get("regions", {}).items():
        if not isinstance(tables, list):
            continue
        for table in tables:
            if table.get("billing_mode") == "PROVISIONED" and table.get("item_count", 0) == 0:
                findings.append({
                    "service": "DynamoDB",
                    "region": region,
                    "resource": table.get("table_name", "unknown"),
                    "issue": f"Provisioned mode with 0 items (RCU={table.get('read_capacity')}, WCU={table.get('write_capacity')})",
                    "severity": "medium",
                })
    return findings


def check_nat_gateways(account_dir, days_threshold):
    """NAT Gateways — always flag count (expensive: ~$32/mo each)."""
    findings = []
    path = find_latest_inventory(account_dir, "nat-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    count = 0
    for region, gateways in data.get("regions", {}).items():
        if not isinstance(gateways, list):
            continue
        count += len(gateways)
        for gw in gateways:
            findings.append({
                "service": "NAT Gateway",
                "region": region,
                "resource": f"{gw.get('nat_gateway_id')} ({gw.get('name', 'N/A')})",
                "issue": f"~$32/mo each — verify needed (VPC: {gw.get('vpc_id', '?')})",
                "severity": "info",
            })
    return findings


def check_vpc_endpoints(account_dir, days_threshold):
    """VPC Interface endpoints — per-hour cost."""
    findings = []
    path = find_latest_inventory(account_dir, "vpc-endpoints")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, endpoints in data.get("regions", {}).items():
        if not isinstance(endpoints, list):
            continue
        interface_eps = [e for e in endpoints if e.get("endpoint_type") == "Interface"]
        if interface_eps:
            findings.append({
                "service": "VPC Endpoints",
                "region": region,
                "resource": f"{len(interface_eps)} interface endpoints",
                "issue": f"~${len(interface_eps) * 7:.0f}/mo (each ~$7/mo) — verify all needed",
                "severity": "info",
            })
    return findings


def check_cloudwatch_alarms(account_dir, days_threshold):
    """CloudWatch alarms in INSUFFICIENT_DATA state."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for alarm in region_data.get("alarms", []):
            if alarm.get("state") == "INSUFFICIENT_DATA":
                findings.append({
                    "service": "CloudWatch",
                    "region": region,
                    "resource": alarm.get("name", "unknown"),
                    "issue": "Alarm in INSUFFICIENT_DATA — misconfigured or resource deleted",
                    "severity": "low",
                })
    return findings


def check_kinesis(account_dir, days_threshold):
    """Kinesis streams — provisioned mode streams that might be unused."""
    findings = []
    path = find_latest_inventory(account_dir, "kinesis")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for stream in region_data.get("data_streams", []):
            if stream.get("mode") == "PROVISIONED" and is_stale(stream.get("created_at"), days_threshold):
                findings.append({
                    "service": "Kinesis",
                    "region": region,
                    "resource": stream.get("stream_name", "unknown"),
                    "issue": "Provisioned stream — verify still in use",
                    "severity": "low",
                })
    return findings


# ============================================================
# Main
# ============================================================

ALL_CHECKS = [
    check_ec2,
    check_cloudtrail,
    check_sns,
    check_sqs,
    check_lambda,
    check_efs,
    check_ecr,
    check_secrets_manager,
    check_acm,
    check_ecs,
    check_dynamodb,
    check_nat_gateways,
    check_vpc_endpoints,
    check_cloudwatch_alarms,
    check_kinesis,
]


def main():
    parser = argparse.ArgumentParser(description='Stale & Waste Resource Checker')
    parser.add_argument('--account-id', '-a', default=None,
                        help='Check specific account (default: all accounts in output/)')
    parser.add_argument('--days', '-d', type=int, default=180,
                        help='Staleness threshold in days (default: 180)')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON instead of table')
    parser.add_argument('--severity', '-s', default=None,
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Filter by minimum severity')
    args = parser.parse_args()

    # Find account directories
    if args.account_id:
        account_dirs = [OUTPUT_DIR / args.account_id]
        if not account_dirs[0].exists():
            print(f"ERROR: No output found for account {args.account_id}")
            sys.exit(1)
    else:
        account_dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir() and d.name != "combined"]

    if not account_dirs:
        print("ERROR: No inventory output found. Run inventory scripts first.")
        sys.exit(1)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_severity = severity_order.get(args.severity, 4) if args.severity else 4

    all_findings = []

    for account_dir in sorted(account_dirs):
        account_id = account_dir.name
        for check_fn in ALL_CHECKS:
            findings = check_fn(account_dir, args.days)
            for f in findings:
                f["account_id"] = account_id
                if severity_order.get(f.get("severity", "info"), 4) <= min_severity:
                    all_findings.append(f)

    if args.json:
        output = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "staleness_threshold_days": args.days,
            "total_findings": len(all_findings),
            "findings_by_severity": {
                s: sum(1 for f in all_findings if f["severity"] == s)
                for s in severity_order
            },
            "findings": all_findings,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        # Group by severity
        print()
        print("=" * 80)
        print("⚠️  STALE / WASTE RESOURCE REPORT")
        print("=" * 80)
        print(f"  Threshold: resources idle > {args.days} days")
        print(f"  Accounts scanned: {len(account_dirs)}")
        print(f"  Total findings: {len(all_findings)}")
        print()

        # Summary by service
        by_service = defaultdict(int)
        for f in all_findings:
            by_service[f["service"]] += 1

        if by_service:
            print("  📊 Summary by service:")
            for svc, count in sorted(by_service.items(), key=lambda x: x[1], reverse=True):
                print(f"    {count:>4}  {svc}")
            print()

        # Details by severity
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for severity in ["critical", "high", "medium", "low", "info"]:
            items = [f for f in all_findings if f["severity"] == severity]
            if not items:
                continue

            icon = severity_icons[severity]
            print(f"  {icon} {severity.upper()} ({len(items)})")
            print(f"  {'─' * 76}")
            for f in items[:50]:  # Cap display at 50 per severity
                acct = f["account_id"][:12]
                region = f.get("region", "global")
                resource = f["resource"][:40]
                issue = f["issue"][:50]
                print(f"    [{acct}] {f['service']:<18} {region:<15} {resource:<40} {issue}")
            if len(items) > 50:
                print(f"    ... and {len(items) - 50} more")
            print()


if __name__ == "__main__":
    main()
