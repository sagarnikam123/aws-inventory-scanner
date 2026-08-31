#!/usr/bin/env python3
"""
AWS Resource Audit Tool — Security, Cost, Reliability & Drift
Reads inventory JSONs and produces a comprehensive findings report.

Categories:
  🔒 SECURITY      — Exposed resources, missing encryption, stale credentials
  💰 COST          — Waste, idle resources, over-provisioning
  ⚙️ RELIABILITY   — Single points of failure, missing backups, outdated versions
  🧹 DRIFT/HYGIENE — Untagged resources, disabled rules, misconfiguration

Usage:
    python tools/audit_aws_resources.py                                 # audit all accounts in output/
    python tools/audit_aws_resources.py -a 111111111111                 # specific account
    python tools/audit_aws_resources.py --days 90                       # staleness threshold
    python tools/audit_aws_resources.py --category security             # filter by category
    python tools/audit_aws_resources.py --json                          # JSON to stdout
    python tools/audit_aws_resources.py -a 111111111111 --live-pricing -p myprofile
                                                                        # real Pricing API cost rates
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

# Lambda runtimes that are deprecated/EOL
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0",
    "ruby2.5", "ruby2.7",
    "java8", "go1.x",
}

# EKS versions considered outdated (< 1.28)
EKS_MIN_SUPPORTED = "1.28"

# AWS opt-in (disabled-by-default) regions. A regional security service being
# "not enabled" here is expected, not a finding — the account never opted in.
# ponytail: static list; AWS adds ~1-2/yr. Upgrade path: append new opt-in
# regions, or switch to account.describe_regions(AllRegions filter) if this drifts.
OPT_IN_REGIONS = {
    "af-south-1", "ap-east-1", "ap-east-2", "ap-south-2",
    "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",
    "ca-west-1", "eu-central-2", "eu-south-1", "eu-south-2",
    "il-central-1", "me-central-1", "me-south-1", "mx-central-1",
}


def find_latest_inventory(account_dir, service):
    """Find the most recent inventory JSON for a service."""
    pattern = str(account_dir / service / f"{service}-inventory-*.json")
    files = sorted(glob.glob(pattern), key=lambda f: Path(f).stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def parse_timestamp(ts):
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        if ts > 1e12:
            ts = ts / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        # fromisoformat handles both 'T' and space separators, microseconds,
        # and colon tz offsets (+05:30) — covers most boto3 str timestamps.
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
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
    dt = parse_timestamp(ts)
    if not dt:
        return False
    return (datetime.now(timezone.utc) - dt) > timedelta(days=days_threshold)


def days_ago(ts):
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def days_until(ts):
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


def finding(category, service, region, resource, issue, severity, est_monthly_cost=None):
    """Create a standardized finding dict."""
    f = {
        "category": category,
        "service": service,
        "region": region,
        "resource": resource,
        "issue": issue,
        "severity": severity,
    }
    if est_monthly_cost is not None:
        f["est_monthly_waste_usd"] = est_monthly_cost
    return f


# ============================================================
# Live pricing (optional) — filled by main() when --live-pricing is set.
# When off, checks fall back to the hardcoded rates below.
# ============================================================

_SESSION = None  # boto3 session when live pricing enabled, else None

# Fallback per-GB-month EBS rates (us-east-1 list prices)
EBS_FALLBACK_RATE = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}
HOURS_PER_MONTH = 730


def ebs_rate(region, volume_type):
    """Per-GB-month price for an EBS volume type — live if available, else fallback."""
    vt = volume_type or "gp3"
    if _SESSION is not None:
        from common import get_ebs_gb_month_price
        price = get_ebs_gb_month_price(_SESSION, region, vt)
        if price is not None:
            return price
    return EBS_FALLBACK_RATE.get(vt, 0.08)


def ec2_monthly(region, instance_type):
    """Monthly on-demand price for an EC2 instance type — live only (None if unavailable)."""
    if _SESSION is not None and instance_type:
        from common import get_ec2_hourly_price
        hourly = get_ec2_hourly_price(_SESSION, region, instance_type)
        if hourly is not None:
            return round(hourly * HOURS_PER_MONTH, 2)
    return None


# ============================================================
# 🔒 SECURITY CHECKS
# ============================================================

def check_security_ec2_public_ips(account_dir, days_threshold):
    """EC2 instances with public IPs — potential exposure."""
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
            if inst.get("public_ip") and inst["public_ip"] != "N/A" and inst.get("state") == "running":
                findings.append(finding(
                    "security", "EC2", region,
                    f"{inst.get('instance_id')} ({inst.get('name', 'N/A')})",
                    f"Public IP {inst['public_ip']} — verify intentional",
                    "medium"
                ))
    return findings


def check_security_rds(account_dir, days_threshold):
    """RDS instances that are publicly accessible."""
    findings = []
    path = find_latest_inventory(account_dir, "rds")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for inst in region_data.get("instances", []):
            if inst.get("publicly_accessible"):
                findings.append(finding(
                    "security", "RDS", region,
                    inst.get("identifier", "unknown"),
                    "Publicly accessible — database exposed to internet",
                    "critical"
                ))
    return findings


def check_security_redshift(account_dir, days_threshold):
    """Redshift clusters that are publicly accessible."""
    findings = []
    path = find_latest_inventory(account_dir, "redshift")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for cluster in region_data.get("clusters", []):
            if cluster.get("publicly_accessible"):
                findings.append(finding(
                    "security", "Redshift", region,
                    cluster.get("cluster_id", "unknown"),
                    "Publicly accessible — data warehouse exposed",
                    "critical"
                ))
    return findings


def check_security_cloudtrail(account_dir, days_threshold):
    """CloudTrail trails not logging or without log validation."""
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
                findings.append(finding(
                    "security", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    "Trail is NOT logging — no audit trail",
                    "critical"
                ))
            if not trail.get("log_file_validation", True):
                findings.append(finding(
                    "security", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    "Log file validation disabled — tampering undetectable",
                    "high"
                ))
    return findings


def check_security_kms(account_dir, days_threshold):
    """KMS keys pending deletion."""
    findings = []
    path = find_latest_inventory(account_dir, "kms")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        keys = region_data if isinstance(region_data, list) else region_data.get("keys", [])
        for key in keys:
            state = key.get("state", key.get("key_state", ""))
            if state == "PendingDeletion":
                findings.append(finding(
                    "security", "KMS", region,
                    key.get("key_id", key.get("alias", "unknown")),
                    "Key pending deletion — encrypted data will become inaccessible",
                    "critical"
                ))
    return findings


def check_security_secrets(account_dir, days_threshold):
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
                if age and age > days_threshold:
                    findings.append(finding(
                        "security", "Secrets Manager", region,
                        secret.get("name", "unknown"),
                        f"No rotation, last accessed {age} days ago — stale credential risk",
                        "high"
                    ))
                else:
                    findings.append(finding(
                        "security", "Secrets Manager", region,
                        secret.get("name", "unknown"),
                        "Rotation disabled — credential compromise risk",
                        "medium"
                    ))
    return findings


def check_security_iam(account_dir, days_threshold):
    """IAM users with old password use or no recent activity."""
    findings = []
    path = find_latest_inventory(account_dir, "iam")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for user in data.get("users", []):
        last_used = user.get("password_last_used", "")
        if last_used and is_stale(last_used, days_threshold):
            age = days_ago(last_used)
            findings.append(finding(
                "security", "IAM", "global",
                user.get("user_name", "unknown"),
                f"Password last used {age} days ago — dormant account",
                "high"
            ))
        elif not last_used and is_stale(user.get("created_at"), days_threshold):
            findings.append(finding(
                "security", "IAM", "global",
                user.get("user_name", "unknown"),
                "Never logged in — unused account",
                "medium"
            ))
    return findings


def check_security_guardduty(account_dir, days_threshold):
    """GuardDuty not enabled."""
    findings = []
    path = find_latest_inventory(account_dir, "guardduty")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        detectors = region_data if isinstance(region_data, list) else region_data.get("detectors", [])
        if not detectors:
            findings.append(finding(
                "security", "GuardDuty", region,
                "N/A",
                "No GuardDuty detector — no threat detection",
                "high"
            ))
    return findings


def check_security_inspector(account_dir, days_threshold):
    """Inspector not enabled."""
    findings = []
    path = find_latest_inventory(account_dir, "inspector")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        if not isinstance(region_data, dict):
            continue
        if not region_data.get("enabled", False):
            findings.append(finding(
                "security", "Inspector", region,
                "N/A",
                "Inspector not enabled — no vulnerability scanning",
                "medium"
            ))
    return findings


def check_security_hub(account_dir, days_threshold):
    """Security Hub not enabled, or enabled with no standards subscribed."""
    findings = []
    path = find_latest_inventory(account_dir, "security-hub")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        if not isinstance(region_data, dict):
            continue
        if not region_data.get("enabled", False):
            findings.append(finding(
                "security", "Security Hub", region,
                "N/A",
                "Security Hub not enabled — no aggregated findings / posture score",
                "medium"
            ))
        elif not region_data.get("standards"):
            # Enabled but no benchmark subscribed = paying for ingestion with
            # no compliance checks running against it.
            findings.append(finding(
                "security", "Security Hub", region,
                "N/A",
                "Enabled but 0 standards subscribed — no compliance checks running",
                "low"
            ))
    return findings


def check_security_documentdb(account_dir, days_threshold):
    """DocumentDB clusters without encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "documentdb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for cluster in region_data.get("clusters", []):
            if not cluster.get("storage_encrypted", True):
                findings.append(finding(
                    "security", "DocumentDB", region,
                    cluster.get("cluster_id", "unknown"),
                    "Storage NOT encrypted — compliance risk",
                    "high"
                ))
    return findings


# ============================================================
# 💰 COST CHECKS
# ============================================================

def check_cost_ec2_stopped(account_dir, days_threshold):
    """EC2 stopped instances — EBS still billed."""
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
                findings.append(finding(
                    "cost", "EC2", region,
                    f"{inst.get('instance_id')} ({inst.get('name', 'N/A')})",
                    f"Stopped — EBS still billed ({inst.get('type', '?')})",
                    "medium",
                    est_monthly_cost=10  # conservative estimate per stopped instance EBS
                ))
    return findings


def check_cost_nat_gateways(account_dir, days_threshold):
    """NAT Gateways — ~$32/mo each."""
    findings = []
    path = find_latest_inventory(account_dir, "nat-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, gateways in data.get("regions", {}).items():
        if not isinstance(gateways, list):
            continue
        for gw in gateways:
            findings.append(finding(
                "cost", "NAT Gateway", region,
                f"{gw.get('nat_gateway_id')} ({gw.get('name', 'N/A')})",
                f"~$32/mo + data transfer — verify needed (VPC: {gw.get('vpc_id', '?')})",
                "info",
                est_monthly_cost=32
            ))
    return findings


def check_cost_vpc_endpoints(account_dir, days_threshold):
    """VPC Interface endpoints — ~$7/mo each."""
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
            cost = len(interface_eps) * 7
            findings.append(finding(
                "cost", "VPC Endpoints", region,
                f"{len(interface_eps)} interface endpoints",
                f"~${cost}/mo total — verify all in use",
                "info",
                est_monthly_cost=cost
            ))
    return findings


def check_cost_sns_unused(account_dir, days_threshold):
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
            if topic.get("subscriptions_confirmed", 0) == 0:
                findings.append(finding(
                    "cost", "SNS", region,
                    topic.get("topic_name", topic.get("arn", "unknown")),
                    "0 subscriptions — nobody listening",
                    "low"
                ))
    return findings


def check_cost_sqs_dead(account_dir, days_threshold):
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
                findings.append(finding(
                    "cost", "SQS", region,
                    q.get("queue_name", "unknown"),
                    f"Empty queue, last modified {age} days ago",
                    "low"
                ))
    return findings


def check_cost_lambda_stale(account_dir, days_threshold):
    """Lambda functions not invoked or modified in N+ days."""
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
            fn_name = fn.get("name", fn.get("function_name", "unknown"))
            last_invoked = fn.get("last_invocation_time")
            invocations = fn.get("invocations_last_30d", None)

            # Best signal: 0 invocations in last 30 days
            if invocations is not None and invocations == 0:
                last_mod = fn.get("last_modified", "")
                age = days_ago(last_mod)
                issue = "0 invocations in 30 days"
                if age:
                    issue += f", code {age} days old"
                findings.append(finding(
                    "cost", "Lambda", region, fn_name,
                    issue + " — dead function",
                    "medium"
                ))
            # Fallback: just check last_modified if no invocation data
            elif invocations is None:
                last_mod = fn.get("last_modified", "")
                if is_stale(last_mod, days_threshold):
                    age = days_ago(last_mod)
                    findings.append(finding(
                        "cost", "Lambda", region, fn_name,
                        f"Not modified in {age} days — possibly unused",
                        "low"
                    ))
    return findings


def check_cost_efs_empty(account_dir, days_threshold):
    """EFS file systems that are empty."""
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
            if fs.get("size_gb", 0) < 0.01:
                findings.append(finding(
                    "cost", "EFS", region,
                    f"{fs.get('file_system_id')} ({fs.get('name', 'N/A')})",
                    "Empty file system — minimum charges apply",
                    "low",
                    est_monthly_cost=1
                ))
    return findings


def check_cost_ecr_empty(account_dir, days_threshold):
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
                findings.append(finding(
                    "cost", "ECR", region,
                    repo.get("name", "unknown"),
                    "0 images — empty repository, can delete",
                    "low"
                ))
    return findings


def check_cost_dynamodb_overprovisioned(account_dir, days_threshold):
    """DynamoDB provisioned tables with 0 items."""
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
                rcu = table.get("read_capacity", 0)
                wcu = table.get("write_capacity", 0)
                # ponytail: rough cost — $0.00065/RCU/hr + $0.00065/WCU/hr
                monthly = (rcu + wcu) * 0.00065 * 730
                findings.append(finding(
                    "cost", "DynamoDB", region,
                    table.get("table_name", "unknown"),
                    f"Provisioned with 0 items (RCU={rcu}, WCU={wcu}) — switch to on-demand or delete",
                    "medium",
                    est_monthly_cost=round(monthly, 2)
                ))
    return findings


def check_cost_elb_idle(account_dir, days_threshold):
    """ELB with 0 target groups or targets."""
    findings = []
    path = find_latest_inventory(account_dir, "elb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        lbs = region_data.get("load_balancers", [])
        tgs = region_data.get("target_groups", [])

        # Find LBs not referenced by any target group
        lb_arns_with_tg = set()
        for tg in tgs:
            for arn in tg.get("lb_arns", []):
                lb_arns_with_tg.add(arn)

        for lb in lbs:
            if lb.get("arn") not in lb_arns_with_tg:
                findings.append(finding(
                    "cost", "ELB", region,
                    lb.get("name", "unknown"),
                    f"No target groups attached — idle ({lb.get('type', '?')})",
                    "medium",
                    est_monthly_cost=16
                ))
    return findings


def check_cost_ebs_waste(account_dir, days_threshold):
    """Unattached EBS volumes and unassociated Elastic IPs."""
    findings = []
    path = find_latest_inventory(account_dir, "ebs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        # Unattached volumes
        for vol in region_data.get("unattached_volumes", []):
            size = vol.get("size_gb", 0)
            rate = ebs_rate(region, vol.get("volume_type", "gp3"))
            monthly = round(size * rate, 2)
            findings.append(finding(
                "cost", "EBS", region,
                f"{vol.get('volume_id')} ({vol.get('name') or 'unnamed'})",
                f"Unattached {vol.get('volume_type', '?')} {size} GB — pure waste",
                "medium" if monthly > 5 else "low",
                est_monthly_cost=monthly
            ))
        # Unassociated Elastic IPs
        for eip in region_data.get("elastic_ips", []):
            if not eip.get("associated", True):
                findings.append(finding(
                    "cost", "Elastic IP", region,
                    eip.get("public_ip", "unknown"),
                    "Unassociated EIP — $3.65/mo waste",
                    "low",
                    est_monthly_cost=3.65
                ))
    return findings


def check_cost_kinesis(account_dir, days_threshold):
    """Kinesis provisioned streams that may be unused."""
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
                findings.append(finding(
                    "cost", "Kinesis", region,
                    stream.get("stream_name", "unknown"),
                    "Provisioned stream, old — verify still in use or switch to on-demand",
                    "low",
                    est_monthly_cost=15
                ))
    return findings


def check_cost_acm_unused(account_dir, days_threshold):
    """ACM certificates not in use or expiring."""
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
            remaining = days_until(cert.get("not_after"))
            if remaining is not None and remaining < 30:
                findings.append(finding(
                    "cost", "ACM", region,
                    cert.get("domain_name", "unknown"),
                    f"Expires in {remaining} days!" if remaining > 0 else "EXPIRED",
                    "critical" if remaining <= 0 else "high"
                ))
            if not cert.get("in_use", True):
                findings.append(finding(
                    "cost", "ACM", region,
                    cert.get("domain_name", "unknown"),
                    "Not attached to any resource — orphaned",
                    "low"
                ))
    return findings


def check_cost_ecs_scaled_zero(account_dir, days_threshold):
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
                    findings.append(finding(
                        "cost", "ECS", region,
                        f"{cluster.get('cluster_name')}/{svc.get('service_name')}",
                        "Service scaled to 0 — delete if no longer needed",
                        "low"
                    ))
    return findings


# ============================================================
# ⚙️ RELIABILITY CHECKS
# ============================================================

def check_reliability_rds(account_dir, days_threshold):
    """RDS without Multi-AZ or backups."""
    findings = []
    path = find_latest_inventory(account_dir, "rds")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for inst in region_data.get("instances", []):
            if not inst.get("multi_az", True):
                findings.append(finding(
                    "reliability", "RDS", region,
                    inst.get("identifier", "unknown"),
                    f"No Multi-AZ — single point of failure ({inst.get('instance_class', '?')})",
                    "high"
                ))
    return findings


def check_reliability_eks_version(account_dir, days_threshold):
    """EKS clusters on outdated Kubernetes versions."""
    findings = []
    path = find_latest_inventory(account_dir, "eks")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            version = cluster.get("version", cluster.get("kubernetes_version", ""))
            if version and version < EKS_MIN_SUPPORTED:
                findings.append(finding(
                    "reliability", "EKS", region,
                    cluster.get("name", "unknown"),
                    f"Kubernetes {version} — outdated (min supported: {EKS_MIN_SUPPORTED})",
                    "high"
                ))
    return findings


def check_reliability_lambda_runtime(account_dir, days_threshold):
    """Lambda functions using deprecated runtimes."""
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
            runtime = fn.get("runtime", "")
            if runtime in DEPRECATED_RUNTIMES:
                findings.append(finding(
                    "reliability", "Lambda", region,
                    fn.get("name", fn.get("function_name", "unknown")),
                    f"Deprecated runtime: {runtime} — will lose security patches",
                    "high"
                ))
    return findings


def check_reliability_opensearch(account_dir, days_threshold):
    """OpenSearch single-node clusters (no HA)."""
    findings = []
    path = find_latest_inventory(account_dir, "opensearch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, domains in data.get("regions", {}).items():
        if not isinstance(domains, list):
            continue
        for d in domains:
            if d.get("instance_count", 1) == 1 and not d.get("zone_awareness", False):
                findings.append(finding(
                    "reliability", "OpenSearch", region,
                    d.get("name", "unknown"),
                    f"Single node, no zone awareness — no HA ({d.get('instance_type', '?')})",
                    "medium"
                ))
    return findings


def check_reliability_ecs_failing(account_dir, days_threshold):
    """ECS services where running < desired."""
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
                desired = svc.get("desired_count", 0)
                running = svc.get("running_count", 0)
                if desired > 0 and running < desired:
                    findings.append(finding(
                        "reliability", "ECS", region,
                        f"{cluster.get('cluster_name')}/{svc.get('service_name')}",
                        f"Running {running}/{desired} — deployment may be failing",
                        "high"
                    ))
    return findings


def check_reliability_dynamodb_no_protection(account_dir, days_threshold):
    """DynamoDB tables without deletion protection."""
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
            if not table.get("deletion_protection", False) and table.get("item_count", 0) > 0:
                findings.append(finding(
                    "reliability", "DynamoDB", region,
                    table.get("table_name", "unknown"),
                    f"No deletion protection ({table.get('item_count', 0)} items) — accidental delete risk",
                    "medium"
                ))
    return findings


def check_reliability_backup_empty(account_dir, days_threshold):
    """Backup vaults with 0 recovery points."""
    findings = []
    path = find_latest_inventory(account_dir, "backup")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for vault in region_data.get("vaults", []):
            if vault.get("recovery_points", 0) == 0:
                findings.append(finding(
                    "reliability", "Backup", region,
                    vault.get("vault_name", "unknown"),
                    "0 recovery points — backups not running",
                    "high"
                ))
    return findings


# ============================================================
# 🧹 DRIFT / HYGIENE CHECKS
# ============================================================

def check_drift_untagged_ec2(account_dir, days_threshold):
    """EC2 instances without a Name tag."""
    findings = []
    path = find_latest_inventory(account_dir, "ec2")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    count = 0
    for region, instances in data.get("regions", {}).items():
        if not isinstance(instances, list):
            continue
        for inst in instances:
            if inst.get("name") in ("N/A", "", None) and inst.get("state") == "running":
                count += 1
    if count > 0:
        findings.append(finding(
            "drift", "EC2", "all",
            f"{count} instances",
            "Running instances without Name tag — unmanaged/untagged",
            "low"
        ))
    return findings


def check_drift_eventbridge_disabled(account_dir, days_threshold):
    """EventBridge rules that are disabled."""
    findings = []
    path = find_latest_inventory(account_dir, "eventbridge")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for rule in region_data.get("rules", []):
            if rule.get("state") == "DISABLED":
                findings.append(finding(
                    "drift", "EventBridge", region,
                    rule.get("name", "unknown"),
                    "Rule disabled — automation not running",
                    "low"
                ))
    return findings


def check_drift_config_not_recording(account_dir, days_threshold):
    """AWS Config recorders not recording."""
    findings = []
    path = find_latest_inventory(account_dir, "config")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for recorder in region_data.get("recorders", []):
            if not recorder.get("recording", True):
                findings.append(finding(
                    "drift", "AWS Config", region,
                    recorder.get("name", "default"),
                    "Config recorder NOT recording — compliance blind spot",
                    "high"
                ))
    return findings


def check_drift_cloudwatch_alarms(account_dir, days_threshold):
    """CloudWatch alarms in INSUFFICIENT_DATA."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    count = 0
    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for alarm in region_data.get("alarms", []):
            if alarm.get("state") == "INSUFFICIENT_DATA":
                count += 1
    if count > 0:
        findings.append(finding(
            "drift", "CloudWatch", "all",
            f"{count} alarms",
            "INSUFFICIENT_DATA — misconfigured or monitoring deleted resources",
            "medium"
        ))
    return findings


def check_drift_step_functions_no_logging(account_dir, days_threshold):
    """Step Functions with logging OFF."""
    findings = []
    path = find_latest_inventory(account_dir, "step-functions")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, state_machines in data.get("regions", {}).items():
        if not isinstance(state_machines, list):
            continue
        for sm in state_machines:
            if sm.get("logging_level", "OFF") == "OFF":
                findings.append(finding(
                    "drift", "Step Functions", region,
                    sm.get("name", "unknown"),
                    "Logging OFF — no execution visibility for debugging",
                    "low"
                ))
    return findings


def check_drift_cloudtrail_stale(account_dir, days_threshold):
    """CloudTrail trails that haven't delivered logs recently."""
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
            if trail.get("is_logging") and is_stale(trail.get("latest_delivery_time"), 7):
                age = days_ago(trail.get("latest_delivery_time"))
                findings.append(finding(
                    "drift", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    f"Last log delivery {age} days ago — trail may be broken",
                    "high"
                ))
    return findings


# ============================================================
# 💰 COST CHECKS — Additional services
# ============================================================

def check_cost_sagemaker(account_dir, days_threshold):
    """SageMaker endpoints running — very expensive if idle."""
    findings = []
    path = find_latest_inventory(account_dir, "sagemaker")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for ep in region_data.get("endpoints", []):
            if ep.get("status") == "InService":
                findings.append(finding(
                    "cost", "SageMaker", region,
                    ep.get("endpoint_name", "unknown"),
                    "Inference endpoint running — verify active usage (expensive)",
                    "medium",
                    est_monthly_cost=100  # ponytail: conservative, ml instances $50-500+/mo
                ))
    return findings


def check_cost_bedrock_provisioned(account_dir, days_threshold):
    """Bedrock provisioned throughput left running."""
    findings = []
    path = find_latest_inventory(account_dir, "bedrock")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for pt in region_data.get("provisioned_throughputs", []):
            if pt.get("status") in ("InService", "ACTIVE"):
                units = pt.get("model_units", 0)
                findings.append(finding(
                    "cost", "Bedrock", region,
                    pt.get("name", "unknown"),
                    f"Provisioned throughput active ({units} model units) — verify needed",
                    "high",
                    est_monthly_cost=units * 500  # ponytail: rough, varies by model
                ))
    return findings


def check_cost_dms_idle(account_dir, days_threshold):
    """DMS replication instances running with no active tasks."""
    findings = []
    path = find_latest_inventory(account_dir, "dms")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        instances = region_data.get("replication_instances", [])
        tasks = region_data.get("replication_tasks", [])

        # Build set of instance ARNs that have active tasks
        active_instance_arns = {t.get("replication_instance_arn") for t in tasks if t.get("status") in ("running", "starting")}

        for inst in instances:
            if inst.get("arn") not in active_instance_arns and inst.get("status") == "available":
                findings.append(finding(
                    "cost", "DMS", region,
                    inst.get("identifier", "unknown"),
                    f"Replication instance running, no active tasks ({inst.get('instance_class', '?')})",
                    "medium",
                    est_monthly_cost=50  # ponytail: dms.t3.medium ~$50/mo
                ))
    return findings


def check_cost_msk(account_dir, days_threshold):
    """MSK clusters — always expensive, flag for verification."""
    findings = []
    path = find_latest_inventory(account_dir, "msk")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            if cluster.get("state") == "ACTIVE":
                brokers = cluster.get("num_brokers", 0)
                instance_type = cluster.get("broker_instance_type", "?")
                storage = cluster.get("storage_gb_per_broker", 0)
                # ponytail: kafka.m5.large ~$175/mo per broker + storage
                est = brokers * 175
                findings.append(finding(
                    "cost", "MSK", region,
                    cluster.get("cluster_name", "unknown"),
                    f"{brokers}x {instance_type}, {storage}GB/broker — verify utilization",
                    "info",
                    est_monthly_cost=est
                ))
    return findings


def check_cost_mwaa(account_dir, days_threshold):
    """MWAA environments — expensive base cost."""
    findings = []
    path = find_latest_inventory(account_dir, "mwaa")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, envs in data.get("regions", {}).items():
        if not isinstance(envs, list):
            continue
        for env in envs:
            if env.get("status") == "AVAILABLE":
                env_class = env.get("environment_class", "mw1.small")
                # ponytail: mw1.small ~$0.49/hr=$360/mo, mw1.medium ~$720/mo
                cost_map = {"mw1.small": 360, "mw1.medium": 720, "mw1.large": 1440}
                est = cost_map.get(env_class, 360)
                findings.append(finding(
                    "cost", "MWAA", region,
                    env.get("name", "unknown"),
                    f"Airflow running ({env_class}) — verify DAGs active",
                    "info",
                    est_monthly_cost=est
                ))
    return findings


def check_cost_glue_stale(account_dir, days_threshold):
    """Glue jobs not run in months."""
    findings = []
    path = find_latest_inventory(account_dir, "glue")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for job in region_data.get("jobs", []):
            last_mod = job.get("last_modified", job.get("created_at", ""))
            if is_stale(last_mod, days_threshold):
                age = days_ago(last_mod)
                findings.append(finding(
                    "cost", "Glue", region,
                    job.get("name", "unknown"),
                    f"Job not modified in {age} days — possibly abandoned",
                    "low"
                ))
    return findings


def check_cost_emr_no_autoterminate(account_dir, days_threshold):
    """EMR clusters without auto-terminate."""
    findings = []
    path = find_latest_inventory(account_dir, "emr")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            if not cluster.get("auto_terminate", True) and cluster.get("state") in ("RUNNING", "WAITING"):
                findings.append(finding(
                    "cost", "EMR", region,
                    cluster.get("name", cluster.get("cluster_id", "unknown")),
                    "Auto-terminate disabled — will run (and charge) indefinitely",
                    "medium",
                    est_monthly_cost=200  # ponytail: varies wildly, conservative baseline
                ))
    return findings


def check_cost_s3_no_lifecycle(account_dir, days_threshold):
    """S3 buckets with no lifecycle, retention > 1yr, or no Glacier transition."""
    findings = []
    path = find_latest_inventory(account_dir, "s3")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    buckets = data.get("buckets", [])
    for bucket in buckets:
        lifecycle = bucket.get("lifecycle", {})
        size_gb = bucket.get("size_gb", 0)
        name = bucket.get("bucket_name", bucket.get("name", "unknown"))
        region = bucket.get("region", "global")

        if not lifecycle or lifecycle.get("error"):
            continue

        retention_configured = lifecycle.get("retention_configured", False)
        retention_days_list = lifecycle.get("retention_days") or []
        transitions = lifecycle.get("transitions", [])

        # Check 1: No lifecycle at all on a bucket > 10 GB
        if not retention_configured and not transitions and size_gb > 10:
            findings.append(finding(
                "cost", "S3", region, name,
                f"No lifecycle policy ({size_gb:.0f} GB) — storage grows indefinitely",
                "low" if size_gb < 100 else "medium",
                est_monthly_cost=round(size_gb * 0.023, 2)
            ))
            continue

        # Check 2: Retention > 365 days (keeping data > 1 year)
        long_retention = [d for d in retention_days_list if d > 365]
        if long_retention and size_gb > 10:
            max_days = max(long_retention)
            findings.append(finding(
                "cost", "S3", region, name,
                f"Retention {max_days} days (>{max_days // 365} yr) on {size_gb:.0f} GB — review if needed that long",
                "low",
            ))

        # Check 3: Has retention/lifecycle but no Glacier transition on large buckets
        has_glacier = any("GLACIER" in t.upper() or "DEEP_ARCHIVE" in t.upper() for t in transitions)
        if not has_glacier and size_gb > 50 and retention_configured:
            findings.append(finding(
                "cost", "S3", region, name,
                f"No Glacier/Deep Archive transition ({size_gb:.0f} GB) — tiering could save 60-80%",
                "medium" if size_gb > 500 else "low",
                est_monthly_cost=round(size_gb * 0.019, 2)  # savings vs staying in Standard
            ))

    return findings


def check_cost_cloudfront_disabled(account_dir, days_threshold):
    """CloudFront distributions that are disabled but still exist."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudfront")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for dist in data.get("distributions", []):
        if not dist.get("enabled", True):
            findings.append(finding(
                "cost", "CloudFront", "global",
                f"{dist.get('distribution_id')} ({dist.get('comment', '') or dist.get('domain_name', '')})",
                "Distribution disabled — can delete if no longer needed",
                "low"
            ))
    return findings


def check_cost_waf_empty(account_dir, days_threshold):
    """WAF Web ACLs with 0 rules — paying base cost for nothing."""
    findings = []
    path = find_latest_inventory(account_dir, "waf")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, acls in data.get("regions", {}).items():
        if not isinstance(acls, list):
            continue
        for acl in acls:
            if acl.get("rule_count", 1) == 0:
                findings.append(finding(
                    "cost", "WAF", region,
                    acl.get("name", "unknown"),
                    "Web ACL with 0 rules — paying $5/mo base for nothing",
                    "low",
                    est_monthly_cost=5
                ))
    return findings


def check_cost_elasticache(account_dir, days_threshold):
    """ElastiCache clusters — flag for utilization review."""
    findings = []
    path = find_latest_inventory(account_dir, "elasticache")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for cluster in region_data.get("clusters", []):
            node_type = cluster.get("node_type", "?")
            num_nodes = cluster.get("num_nodes", 1)
            if is_stale(cluster.get("created_at"), days_threshold):
                findings.append(finding(
                    "cost", "ElastiCache", region,
                    cluster.get("cluster_id", "unknown"),
                    f"{num_nodes}x {node_type} — old cluster, verify still needed",
                    "info",
                    est_monthly_cost=num_nodes * 25  # ponytail: cache.t3.micro ~$12, t3.medium ~$50
                ))
    return findings


def check_cost_transit_gateway(account_dir, days_threshold):
    """Transit Gateway attachments — per-hour + per-GB charges."""
    findings = []
    path = find_latest_inventory(account_dir, "transit-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        attachments = region_data.get("attachments", [])
        if attachments:
            # $0.05/hr per attachment = ~$36/mo
            est = len(attachments) * 36
            findings.append(finding(
                "cost", "Transit Gateway", region,
                f"{len(attachments)} TGW attachments",
                f"~${est}/mo ({len(attachments)} x $36/mo) — verify all needed",
                "info",
                est_monthly_cost=est
            ))
    return findings


# ============================================================
# ALL CHECKS REGISTRY
# ============================================================

def check_cost_workspaces_idle(account_dir, days_threshold):
    """WorkSpaces on ALWAYS_ON that look idle, plus long-stopped ones still billed."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            ws_id = ws.get("workspace_id", "unknown")
            user = ws.get("user_name", "?")
            resource = f"{ws_id} ({user})"
            mode = ws.get("running_mode", "")
            last = ws.get("last_active", "")
            idle_days = days_ago(last) if last else None

            # ALWAYS_ON bills a flat monthly rate (~$21-64/mo by bundle) even
            # when unused. Idle ALWAYS_ON is the classic WorkSpaces waste.
            if mode == "ALWAYS_ON":
                if idle_days is None or idle_days >= days_threshold:
                    when = f"no login in {idle_days}d" if idle_days is not None else "never connected"
                    findings.append(finding(
                        "cost", "WorkSpaces", region, resource,
                        f"ALWAYS_ON but {when} — switch to AUTO_STOP or terminate",
                        "medium",
                        est_monthly_cost=35  # ponytail: mid-bundle avg; varies $21-64 by type
                    ))
            # Any workspace with a real user that hasn't connected in a long
            # time is a decommission candidate regardless of running mode.
            elif idle_days is not None and idle_days >= days_threshold:
                findings.append(finding(
                    "cost", "WorkSpaces", region, resource,
                    f"No login in {idle_days}d — decommission candidate",
                    "low",
                    est_monthly_cost=10  # ponytail: AUTO_STOP still bills storage + occasional use
                ))
    return findings


def check_security_workspaces_unencrypted(account_dir, days_threshold):
    """WorkSpaces user volumes without encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            if not ws.get("encrypted", False):
                findings.append(finding(
                    "security", "WorkSpaces", region,
                    f"{ws.get('workspace_id', 'unknown')} ({ws.get('user_name', '?')})",
                    "User volume NOT encrypted — data-at-rest exposure",
                    "high"
                ))
    return findings


def check_reliability_workspaces_unhealthy(account_dir, days_threshold):
    """WorkSpaces stuck in an error/unhealthy state."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    bad_states = {"ERROR", "UNHEALTHY", "IMPAIRED", "MAINTENANCE"}
    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            state = ws.get("state", "")
            if state in bad_states:
                findings.append(finding(
                    "reliability", "WorkSpaces", region,
                    f"{ws.get('workspace_id', 'unknown')} ({ws.get('user_name', '?')})",
                    f"State {state} — user cannot work / needs rebuild",
                    "high"
                ))
    return findings


def check_cost_amplify_stale(account_dir, days_threshold):
    """Amplify apps not updated in months, or apps with no branches."""
    findings = []
    path = find_latest_inventory(account_dir, "amplify")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, apps in data.get("regions", {}).items():
        if not isinstance(apps, list):
            continue
        for app in apps:
            name = app.get("name", app.get("app_id", "unknown"))
            if app.get("branch_count", 0) == 0:
                findings.append(finding(
                    "cost", "Amplify", region, name,
                    "App has 0 branches — orphaned, delete",
                    "low"
                ))
                continue
            age = days_ago(app.get("updated_at", ""))
            if age is not None and age >= days_threshold:
                findings.append(finding(
                    "cost", "Amplify", region, name,
                    f"Not updated in {age}d — possibly abandoned hosting",
                    "low"
                ))
    return findings


def check_reliability_security_lake(account_dir, days_threshold):
    """Security Lake posture: weak encryption, no replication, no retention, dead subscribers."""
    findings = []
    path = find_latest_inventory(account_dir, "security-lake")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, rd in data.get("regions", {}).items():
        if not isinstance(rd, dict):
            continue

        for dl in rd.get("data_lakes", []):
            arn = dl.get("arn", "data-lake")

            # S3-managed key instead of a customer KMS key — weaker control
            if dl.get("kms_key_id") in ("S3_MANAGED_KEY", "", None):
                findings.append(finding(
                    "security", "Security Lake", region, arn,
                    "Data lake uses S3-managed key, not a customer KMS CMK",
                    "medium"
                ))

            # Single-region SIEM store with no replication = SPOF for security data
            if not dl.get("replication_enabled", False):
                findings.append(finding(
                    "reliability", "Security Lake", region, arn,
                    "Replication disabled — security data has no cross-region copy",
                    "medium"
                ))

            # No lifecycle transitions/expiration → S3 grows forever (real cost)
            if not dl.get("retention_settings") and not dl.get("expiration_days"):
                findings.append(finding(
                    "cost", "Security Lake", region, arn,
                    "No retention/lifecycle — log storage grows unbounded",
                    "medium"
                ))

        for sub in rd.get("subscribers", []):
            if sub.get("status") not in ("ACTIVE", ""):
                findings.append(finding(
                    "drift", "Security Lake", region,
                    sub.get("name", sub.get("subscriber_id", "unknown")),
                    f"Subscriber status {sub.get('status')} — not consuming data",
                    "low"
                ))
    return findings


def check_reliability_synthetics(account_dir, days_threshold):
    """Canaries that are broken (last run failed), stopped, or on an EOL runtime."""
    findings = []
    path = find_latest_inventory(account_dir, "synthetics")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, canaries in data.get("regions", {}).items():
        if not isinstance(canaries, list):
            continue
        for c in canaries:
            name = c.get("name", "unknown")
            state = c.get("state", "")
            last_run = (c.get("last_run_state") or "").upper()
            runtime = c.get("runtime_version", "")

            # Broken canary = monitoring blind spot (thinks it's covered, isn't)
            if last_run in ("FAILED", "ERROR"):
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    f"Last run {last_run} — monitoring blind spot, alerts won't fire correctly",
                    "high"
                ))

            # Stopped canary = configured monitoring that isn't running
            if state == "STOPPED":
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    "Canary STOPPED — not monitoring; delete or restart",
                    "medium"
                ))

            # EOL runtime. ponytail: prefix heuristic, not an exhaustive AWS
            # list — syn-1.0 and puppeteer-3.x/selenium-1.x are long deprecated.
            # Upgrade path: check AWS Synthetics runtime deprecation page and
            # extend these prefixes when new versions age out.
            if (runtime == "syn-1.0"
                    or runtime.startswith("syn-nodejs-puppeteer-3.")
                    or runtime.startswith("syn-python-selenium-1.")):
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    f"Deprecated runtime {runtime} — upgrade before AWS blocks it",
                    "medium"
                ))
    return findings


def check_drift_rum_no_sampling(account_dir, days_threshold):
    """RUM app monitors that collect nothing (0% sample) — configured but useless."""
    findings = []
    path = find_latest_inventory(account_dir, "rum")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, monitors in data.get("regions", {}).items():
        if not isinstance(monitors, list):
            continue
        for m in monitors:
            rate = m.get("session_sample_rate")
            if rate == 0:
                findings.append(finding(
                    "drift", "RUM", region, m.get("name", "unknown"),
                    "Session sample rate 0% — monitor collects no data",
                    "low"
                ))
    return findings


ALL_CHECKS = [
    # Security
    check_security_ec2_public_ips,
    check_security_rds,
    check_security_redshift,
    check_security_cloudtrail,
    check_security_kms,
    check_security_secrets,
    check_security_iam,
    check_security_guardduty,
    check_security_inspector,
    check_security_hub,
    check_security_documentdb,
    check_security_workspaces_unencrypted,
    check_reliability_security_lake,  # emits security + reliability + cost + drift
    # Cost
    check_cost_ec2_stopped,
    check_cost_nat_gateways,
    check_cost_vpc_endpoints,
    check_cost_sns_unused,
    check_cost_sqs_dead,
    check_cost_lambda_stale,
    check_cost_efs_empty,
    check_cost_ecr_empty,
    check_cost_dynamodb_overprovisioned,
    check_cost_elb_idle,
    check_cost_ebs_waste,
    check_cost_kinesis,
    check_cost_acm_unused,
    check_cost_ecs_scaled_zero,
    check_cost_sagemaker,
    check_cost_bedrock_provisioned,
    check_cost_dms_idle,
    check_cost_msk,
    check_cost_mwaa,
    check_cost_glue_stale,
    check_cost_emr_no_autoterminate,
    check_cost_s3_no_lifecycle,
    check_cost_cloudfront_disabled,
    check_cost_waf_empty,
    check_cost_elasticache,
    check_cost_transit_gateway,
    check_cost_workspaces_idle,
    check_cost_amplify_stale,
    # Reliability
    check_reliability_rds,
    check_reliability_eks_version,
    check_reliability_lambda_runtime,
    check_reliability_opensearch,
    check_reliability_ecs_failing,
    check_reliability_dynamodb_no_protection,
    check_reliability_backup_empty,
    check_reliability_workspaces_unhealthy,
    check_reliability_synthetics,
    # Drift / Hygiene
    check_drift_rum_no_sampling,
    check_drift_untagged_ec2,
    check_drift_eventbridge_disabled,
    check_drift_config_not_recording,
    check_drift_cloudwatch_alarms,
    check_drift_step_functions_no_logging,
    check_drift_cloudtrail_stale,
]


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='AWS Resource Audit — Security, Cost, Reliability & Drift')
    parser.add_argument('--account-id', '-a', default=None,
                        help='Check specific account (default: all in output/)')
    parser.add_argument('--days', '-d', type=int, default=90,
                        help='Staleness threshold in days (default: 90)')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON (for presentations/reports)')
    parser.add_argument('--severity', '-s', default=None,
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Show only this severity and above')
    parser.add_argument('--category', '-c', default=None,
                        choices=['security', 'cost', 'reliability', 'drift'],
                        help='Filter by category')
    parser.add_argument('--live-pricing', action='store_true',
                        help='Use live AWS Pricing API for cost estimates (needs --profile)')
    parser.add_argument('--profile', '-p', default=None,
                        help='AWS profile for --live-pricing (Pricing API is free/read-only)')
    args = parser.parse_args()

    # Optional: live pricing via AWS Pricing API
    if args.live_pricing:
        if not args.profile:
            print("ERROR: --live-pricing requires --profile")
            sys.exit(1)
        global _SESSION
        sys.path.insert(0, str(ROOT_DIR))
        from common import create_session
        _SESSION = create_session(args.profile)
        if _SESSION is None:
            print(f"ERROR: could not create session for profile {args.profile}")
            sys.exit(1)
        print(f"  💲 Live pricing enabled via profile {args.profile}")

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
                if severity_order.get(f.get("severity", "info"), 4) <= min_severity:
                    if args.category and f.get("category") != args.category:
                        continue
                    all_findings.append(f)

    # Calculate estimated savings
    total_est_savings = sum(f.get("est_monthly_waste_usd", 0) for f in all_findings)

    # Always save JSON report to output/audit/
    output_data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "staleness_threshold_days": args.days,
        "total_findings": len(all_findings),
        "estimated_monthly_waste_usd": round(total_est_savings, 2),
        "findings_by_severity": {
            s: sum(1 for f in all_findings if f["severity"] == s)
            for s in severity_order if sum(1 for f in all_findings if f["severity"] == s) > 0
        },
        "findings_by_category": {
            c: sum(1 for f in all_findings if f["category"] == c)
            for c in ["security", "cost", "reliability", "drift"]
            if sum(1 for f in all_findings if f["category"] == c) > 0
        },
        "top_cost_savings": sorted(
            [f for f in all_findings if f.get("est_monthly_waste_usd", 0) > 0],
            key=lambda x: x["est_monthly_waste_usd"], reverse=True
        )[:20],
        "findings": all_findings,
    }

    audit_dir = OUTPUT_DIR / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    audit_file = audit_dir / f"audit-report-{account_id}-{timestamp}.json"
    with open(audit_file, 'w') as f:
        json.dump(output_data, f, indent=2, default=str, ensure_ascii=False)
    print(f"  📄 Saved: {audit_file}")

    if args.json:
        print(json.dumps(output_data, indent=2, default=str))
    else:
        # Console report
        print()
        print("=" * 90)
        print("  AWS RESOURCE AUDIT REPORT")
        print("  Security • Cost • Reliability • Drift")
        print("=" * 90)
        print(f"  Accounts scanned:      {len(account_dirs)}")
        print(f"  Staleness threshold:   {args.days} days")
        print(f"  Total findings:        {len(all_findings)}")
        if total_est_savings > 0:
            print(f"  💰 Est. monthly waste: ${total_est_savings:,.0f}/mo")
        print()

        # Category summary
        category_icons = {"security": "🔒", "cost": "💰", "reliability": "⚙️", "drift": "🧹"}
        print("  📊 BY CATEGORY:")
        for cat in ["security", "cost", "reliability", "drift"]:
            count = sum(1 for f in all_findings if f["category"] == cat)
            if count:
                icon = category_icons[cat]
                print(f"    {icon} {cat.upper():<14} {count:>5} findings")
        print()

        # Severity summary
        print("  📊 BY SEVERITY:")
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in all_findings if f["severity"] == sev)
            if count:
                print(f"    {severity_icons[sev]} {sev.upper():<10} {count:>5}")
        print()

        # Top cost savings
        cost_findings = sorted(
            [f for f in all_findings if f.get("est_monthly_waste_usd", 0) > 0],
            key=lambda x: x["est_monthly_waste_usd"], reverse=True
        )[:10]
        if cost_findings:
            print("  💡 TOP COST REDUCTION OPPORTUNITIES:")
            print(f"  {'─' * 86}")
            for f in cost_findings:
                print(f"    ${f['est_monthly_waste_usd']:>8,.0f}/mo  {f['service']:<18} {f['resource'][:40]:<40} {f['issue'][:40]}")
            print()

        # Details by category + severity
        for cat in ["security", "cost", "reliability", "drift"]:
            items = [f for f in all_findings if f["category"] == cat]
            if not items:
                continue

            icon = category_icons[cat]
            print(f"  {icon} {cat.upper()} ({len(items)} findings)")
            print(f"  {'━' * 86}")

            for sev in ["critical", "high", "medium", "low", "info"]:
                sev_items = [f for f in items if f["severity"] == sev]
                if not sev_items:
                    continue
                print(f"    {severity_icons[sev]} {sev.upper()} ({len(sev_items)})")
                for f in sev_items[:25]:
                    region = f.get("region", "global")[:12]
                    resource = f["resource"][:35]
                    issue = f["issue"][:50]
                    print(f"      [{region:<12}] {f['service']:<16} {resource:<35} {issue}")
                if len(sev_items) > 25:
                    print(f"      ... and {len(sev_items) - 25} more")
            print()

        # Action summary
        print("  " + "=" * 86)
        print("  📋 RECOMMENDED ACTIONS:")
        print("  " + "=" * 86)

        critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
        high_count = sum(1 for f in all_findings if f["severity"] == "high")

        if critical_count:
            print(f"  1. 🔴 Fix {critical_count} CRITICAL issues immediately (security exposure, expired certs)")
        if high_count:
            print(f"  2. 🟠 Address {high_count} HIGH issues this sprint (no HA, stale credentials, deprecated runtimes)")
        if total_est_savings > 100:
            print(f"  3. 💰 Review cost waste — est. ${total_est_savings:,.0f}/mo savings possible")

        stopped_ec2 = sum(1 for f in all_findings if f["service"] == "EC2" and "Stopped" in f["issue"])
        if stopped_ec2:
            print(f"  4. 🛑 {stopped_ec2} stopped EC2 instances — terminate or snapshot+delete EBS")

        print()


if __name__ == "__main__":
    main()
