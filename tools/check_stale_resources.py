#!/usr/bin/env python3
"""
AWS Resource Audit Tool — Security, Cost, Reliability & Drift
Reads inventory JSONs and produces a comprehensive findings report.

Categories:
  🔒 SECURITY      — Exposed resources, missing encryption, stale credentials
  💰 COST          — Waste, idle resources, over-provisioning
  ⚙️  RELIABILITY   — Single points of failure, missing backups, outdated versions
  🧹 DRIFT/HYGIENE — Untagged resources, disabled rules, misconfiguration

Usage:
    python tools/check_stale_resources.py                              # all accounts
    python tools/check_stale_resources.py --account-id 111111111111    # specific account
    python tools/check_stale_resources.py --days 90                    # staleness threshold
    python tools/check_stale_resources.py --category security          # filter by category
    python tools/check_stale_resources.py --json                       # JSON output
    python tools/check_stale_resources.py --json > audit-report.json   # save for presentation
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
            # ponytail: gp3=$0.08, gp2=$0.10, io1=$0.125, st1=$0.045, sc1=$0.015 per GB/mo
            cost_map = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}
            rate = cost_map.get(vol.get("volume_type", "gp3"), 0.08)
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
# ALL CHECKS REGISTRY
# ============================================================

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
    check_security_documentdb,
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
    # Reliability
    check_reliability_rds,
    check_reliability_eks_version,
    check_reliability_lambda_runtime,
    check_reliability_opensearch,
    check_reliability_ecs_failing,
    check_reliability_dynamodb_no_protection,
    check_reliability_backup_empty,
    # Drift / Hygiene
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
    parser.add_argument('--days', '-d', type=int, default=180,
                        help='Staleness threshold in days (default: 180)')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON (for presentations/reports)')
    parser.add_argument('--severity', '-s', default=None,
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Show only this severity and above')
    parser.add_argument('--category', '-c', default=None,
                        choices=['security', 'cost', 'reliability', 'drift'],
                        help='Filter by category')
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
                    if args.category and f.get("category") != args.category:
                        continue
                    all_findings.append(f)

    # Calculate estimated savings
    total_est_savings = sum(f.get("est_monthly_waste_usd", 0) for f in all_findings)

    if args.json:
        output = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "staleness_threshold_days": args.days,
            "accounts_scanned": len(account_dirs),
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
        print(json.dumps(output, indent=2, default=str))
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
