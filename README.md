# AWS Inventory Scanner

Scan AWS resources across multiple accounts and regions. Outputs JSON per-account with incremental writes (crash-safe).

## Features

- 70+ service inventory scripts covering compute, storage, networking, databases, security, analytics, observability, and more
- Multi-account scanning via `accounts.yaml`, or single-account via `--profile`
- Crash-safe: data written to disk after each region/query (nothing lost on interruption)
- Parallel region scanning (ThreadPoolExecutor) for fast multi-region collection
- Standard CLI: `--account`, `--profile`, `--region` across all scripts
- Cost Explorer integration: service-level spend breakdown (MTD, YTD, monthly, by region/usage type/purchase option)
- Output filenames include account ID for easy identification

## Quick Start

```bash
git clone <repo-url> && cd aws-inventory-scanner
python -m venv .venv && source .venv/bin/activate
pip install boto3 pyyaml

# Configure accounts
cp conf/accounts.yaml.example conf/accounts.yaml
# Edit conf/accounts.yaml with your real account IDs and profiles

# Single service using the AWS CLI [default] profile
python inventory/get_ec2_inventory.py

# Single account (by name from accounts.yaml)
python inventory/get_ec2_inventory.py -a "Production"

# Direct profile (bypasses accounts.yaml — scan one account)
python inventory/get_ec2_inventory.py -p my_aws_profile

# Single region
python inventory/get_ec2_inventory.py -p my_aws_profile -r us-east-1
```

### Run all scanners

`run_inventory.sh` runs every scanner for one account, N at a time. A failing
scanner is warned to the console but never stops the run.

```bash
cp conf/.env.example conf/.env     # set AWS_PROFILE, PARALLEL, etc.
./run_inventory.sh                  # uses the AWS CLI [default] profile if omitted

# or override inline (no conf/.env needed)
AWS_PROFILE=123456789012_AdministratorAccess PARALLEL=4 ./run_inventory.sh
```

`AWS_PROFILE` is optional. When omitted or empty, the runner uses the AWS CLI
`[default]` profile. Config lives in `conf/.env` (`AWS_PROFILE`, `AWS_REGION`,
`PARALLEL`, `ONLY`, `SKIP`).
Per-script logs go to `output/_run_logs/`. Full details and the shared-args
reference: [docs/running-all-scanners.md](docs/running-all-scanners.md).

## Services Covered

| Category | Scripts |
|----------|---------|
| **Compute** | EC2, EBS, ECS, EKS, Lambda, EMR, App Runner, WorkSpaces |
| **Storage** | S3, EFS, FSx, Glacier, Backup |
| **Networking** | VPC, ELB, NAT Gateway, Transit Gateway, VPC Endpoints, Direct Connect, Global Accelerator, Route 53, CloudFront |
| **Database** | RDS, DynamoDB, ElastiCache, DocumentDB, Redshift, Timestream |
| **Security** | IAM, KMS, Secrets Manager, WAF, GuardDuty, Security Hub, Inspector, ACM, Security Lake |
| **Analytics** | Athena, Glue, Kinesis (+ Firehose), MSK, QuickSight, SageMaker |
| **Application** | API Gateway, SQS, SNS, SES, Step Functions, EventBridge, Amplify |
| **AI/ML** | Bedrock (models, agents, KBs, guardrails), Bedrock AgentCore |
| **Management** | CloudWatch, CloudTrail, AWS Config, SSM, CodeBuild, AWS Health |
| **Migration** | DMS |
| **Firewall** | Network Firewall |
| **Containers** | ECR, ECS, EKS + K8s workloads |
| **Observability** | CloudWatch (logs/alarms/dashboards), X-Ray, AMP (Managed Prometheus), AMG (Managed Grafana), OpenSearch, Synthetics, RUM, Internet Monitor, Application Signals — see [docs/aws-observability-services.md](docs/aws-observability-services.md) |
| **Cost** | Cost Explorer (MTD/YTD/monthly by service, region, usage type, purchase option) |
| **Orchestration** | MWAA (Managed Airflow) |

## Output Structure

```
output/
├── <account_id>/
│   ├── ec2/
│   │   └── ec2-inventory-<account_id>-<timestamp>.json
│   ├── rds/
│   │   └── rds-inventory-<account_id>-<timestamp>.json
│   └── ...
└── audit/
    ├── audit-report-<account_id>.json
    ├── audit-report-<account_id>.md
    └── audit-report-<account_id>.csv
```

Data is flushed incrementally — if the script crashes mid-run, all previously fetched regions are already on disk.

## Configuration

### conf/accounts.yaml

```yaml
accounts:
  - name: "Production"
    account_id: "111111111111"
    profile: "111111111111_AdministratorAccess"
    alias: "prod"

  - name: "Development"
    account_id: "222222222222"
    profile: "222222222222_AdministratorAccess"
    alias: "dev"
    enabled: false  # skip this account
```

See `conf/accounts.yaml.example` for a full template.

### AWS Credentials

Scripts use AWS profiles from `~/.aws/credentials` or `~/.aws/config`. Configure via:
- AWS SSO: `aws configure sso`
- Access keys: `aws configure --profile <name>`

Required permissions: `ReadOnlyAccess` is sufficient for most scripts. Cost Explorer needs `ce:GetCostAndUsage`.

## Usage Examples

```bash
# EC2 filtered by tag
python inventory/get_ec2_inventory.py --tag Service=nginx

# S3 with CloudWatch size metrics
python inventory/get_s3_inventory.py --metrics

# S3 filtered by name
python inventory/get_s3_inventory.py --filter my-bucket-prefix

# EKS with detailed cluster info
python inventory/get_eks_inventory.py --details

# K8s workloads (deployments, services, cronjobs)
python inventory/get_eks_workloads_inventory.py -p <profile> -r us-east-1
python inventory/get_eks_workloads_inventory.py -p <profile> -r us-east-1 -w deployment service

# Cost Explorer
python inventory/get_cost_inventory.py
python inventory/get_cost_inventory.py -a "Production"
```

## Tools (Post-Processing & Audit)

Offline scripts that read inventory output — no AWS API calls needed.

| Script | Purpose |
|--------|---------|
| `audit_aws_resources.py` | Full resource audit: security, cost, reliability, drift (60+ checks) |
| `check_eks_vpc_connectivity.py` | Maps EKS cluster ↔ VPC connectivity (peering, TGW) |
| `get_eks_unique_deployments.py` | Extracts unique deployment names from K8s workloads inventory |
| `get_eks_unique_namespaces.py` | Extracts unique namespace names with exclude filters |
| `get_eks_workloads_xls.py` | Generates Excel report from K8s workloads inventory |

### Resource Audit

```bash
# Full audit (security + cost + reliability + drift)
python tools/audit_aws_resources.py -a 111111111111

# Filter by category
python tools/audit_aws_resources.py -a 111111111111 --category security
python tools/audit_aws_resources.py -a 111111111111 --category cost

# Custom staleness threshold (default: 90 days)
python tools/audit_aws_resources.py -a 111111111111 --days 30

# Use live AWS Pricing API for accurate per-region cost estimates
python tools/audit_aws_resources.py -a 111111111111 --live-pricing -p my_aws_profile

# Show only critical/high
python tools/audit_aws_resources.py -a 111111111111 --severity high

# JSON output (saved to output/audit/ automatically)
python tools/audit_aws_resources.py -a 111111111111 --json
```

Audit checks include:
- 🔒 **Security**: Public IPs, public databases, disabled logging, stale credentials, missing encryption
- 💰 **Cost**: Stopped EC2, unattached EBS, idle ELBs, unused NAT GWs, over-provisioned DynamoDB, S3 without lifecycle/Glacier
- ⚙️ **Reliability**: No Multi-AZ, outdated EKS, deprecated Lambda runtimes, missing backups
- 🧹 **Drift**: Untagged resources, disabled rules, broken alarms, config not recording

## Architecture

```
aws-inventory-scanner/
├── README.md
├── LICENSE
├── .gitignore
├── run_inventory.sh            ← Batch runner (all scanners, N parallel)
├── conf/
│   ├── accounts.yaml           ← Your accounts (gitignored)
│   ├── accounts.yaml.example   ← Template
│   ├── .env                    ← Runner config (gitignored)
│   └── .env.example            ← Runner config template
├── common/
│   ├── __init__.py             ← Package init (re-exports)
│   └── common.py               ← Shared utilities
├── inventory/                   ← All scanner scripts
│   ├── get_ec2_inventory.py
│   ├── get_cost_inventory.py
│   └── ...
├── tools/                       ← Audit & analysis (reads inventory output)
│   ├── audit_aws_resources.py   ← Full 4-category resource audit
│   ├── check_eks_vpc_connectivity.py
│   ├── get_eks_unique_deployments.py
│   ├── get_eks_unique_namespaces.py
│   └── get_eks_workloads_xls.py
├── docs/
│   ├── aws-observability-services.md   ← Observability service → scanner map
│   └── eks-kubectl-guide.md
└── output/                      ← JSON output (gitignored)
```

## Adding a New Scanner

Follow the pattern in any existing script:

1. Import from `common`: `IncrementalWriter`, `make_output_filename`, `add_common_args`, `scan_regions_parallel`, etc.
2. Write a `scan_region(session, region)` returning `(region_data, counts)`
3. Drive it with `scan_regions_parallel(...)` — parallel regions + per-region incremental flush, for free
4. Use `make_output_filename(service, account_id, timestamp)` for consistent naming
5. Handle `is_region_unsupported_error()` for graceful opt-in region skips

## Requirements

- Python 3.9+
- boto3
- pyyaml
- Valid AWS credentials with appropriate read permissions

## License

MIT
