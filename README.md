# AWS Inventory Scanner

Scan AWS resources across multiple accounts and regions. Outputs JSON per-account with incremental writes (crash-safe).

## Features

- 60+ service inventory scripts covering compute, storage, networking, databases, security, analytics, and more
- Multi-account scanning via `accounts.yaml`
- Crash-safe: data written to disk after each region/query (nothing lost on interruption)
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

# Scan all accounts, all services
python run_all.py

# Single service
python inventory/get_ec2_inventory.py

# Single account
python inventory/get_ec2_inventory.py -a "Production"

# Direct profile (bypasses accounts.yaml)
python inventory/get_ec2_inventory.py -p my_aws_profile

# Single region
python inventory/get_ec2_inventory.py -r us-east-1
```

## Services Covered

| Category | Scripts |
|----------|---------|
| **Compute** | EC2, ECS, EKS, Lambda, EMR, App Runner, Lightsail |
| **Storage** | S3, EFS, FSx, Glacier, Backup |
| **Networking** | VPC, ELB, NAT Gateway, Transit Gateway, VPC Endpoints, Direct Connect, Global Accelerator, Route 53, CloudFront |
| **Database** | RDS, DynamoDB, ElastiCache, DocumentDB, Redshift, Timestream |
| **Security** | IAM, KMS, Secrets Manager, WAF, GuardDuty, Security Hub, Inspector, ACM |
| **Analytics** | Athena, Glue, Kinesis, MSK, QuickSight, SageMaker |
| **Application** | API Gateway, SQS, SNS, SES, Step Functions, EventBridge |
| **AI/ML** | Bedrock (models, agents, knowledge bases, guardrails) |
| **Management** | CloudWatch, CloudTrail, AWS Config, SSM, CodeBuild |
| **Migration** | DMS |
| **Firewall** | Network Firewall |
| **Containers** | ECR, ECS, EKS + K8s workloads |
| **Observability** | AMG (Managed Grafana), CloudWatch Alarms |
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
└── combined/
    └── cost/
        └── cost-inventory-all-accounts-<timestamp>.json
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
# Run all inventory scripts
python run_all.py

# Quick mode (EKS only)
python run_all.py --quick

# Specific services only
python run_all.py --only eks ec2 vpc

# EC2 filtered by tag
python inventory/get_ec2_inventory.py --tag Service=nginx

# S3 with CloudWatch size metrics
python inventory/get_s3_inventory.py --metrics

# S3 filtered by name
python inventory/get_s3_inventory.py --filter my-bucket-prefix

# EKS with detailed cluster info
python inventory/get_eks_inventory.py --details

# K8s workloads (deployments, services, cronjobs)
python inventory/get_k8s_workloads_inventory.py -p <profile> -r us-east-1
python inventory/get_k8s_workloads_inventory.py -p <profile> -r us-east-1 -w deployment service

# Cost Explorer
python inventory/get_cost_inventory.py
python inventory/get_cost_inventory.py -a "Production"
```

## Architecture

```
aws-inventory-scanner/
├── README.md
├── LICENSE
├── .gitignore
├── conf/
│   ├── accounts.yaml           ← Your accounts (gitignored)
│   └── accounts.yaml.example   ← Template
├── common/
│   ├── __init__.py             ← Package init (re-exports)
│   └── common.py               ← Shared utilities
├── inventory/                   ← All scanner scripts
│   ├── get_ec2_inventory.py
│   ├── get_cost_inventory.py
│   └── ...
├── tools/                       ← Analysis scripts (read inventory output)
│   └── eks_vpc_connectivity.py
├── docs/
│   └── eks-kubectl-guide.md
└── output/                      ← JSON output (gitignored)
```

## Adding a New Scanner

Follow the pattern in any existing script:

1. Import from `common`: `IncrementalWriter`, `make_output_filename`, `add_common_args`, etc.
2. Use `IncrementalWriter` — flush after each region
3. Use `make_output_filename(service, account_id, timestamp)` for consistent naming
4. Handle `is_region_unsupported_error()` for graceful region skips

## Requirements

- Python 3.9+
- boto3
- pyyaml
- Valid AWS credentials with appropriate read permissions

## License

MIT
