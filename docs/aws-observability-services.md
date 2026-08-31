# AWS Observability Services

Reference list of AWS services relevant to observability — metrics, logs, traces,
alerting, and the managed open-source stack. The **Inventory** column shows whether
this repo has a scanner for that service (`inventory/get_<name>_inventory.py`).

Observability = the three pillars (**metrics**, **logs**, **traces**) plus the
signals built on them (**alerts**, **dashboards**, **events**).

---

## Core observability

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon CloudWatch** | Metrics, logs, dashboards, Logs Insights, Container/Lambda Insights | ✅ `cloudwatch` |
| **CloudWatch Alarms** | Metric/composite/anomaly-detection alarms → SNS actions | ✅ `cloudwatch_alarms` |
| **AWS X-Ray** | Distributed tracing, service maps, latency analysis | ✅ `xray` |
| **Amazon Managed Service for Prometheus (AMP)** | Managed Prometheus for metrics ingestion/query (PromQL) | ✅ `amp` |
| **Amazon Managed Grafana (AMG)** | Managed Grafana dashboards over AMP/CloudWatch/X-Ray | ✅ `amg` |
| **Amazon OpenSearch Service** | Log search/analytics, OpenSearch Dashboards (Kibana) | ✅ `opensearch` |

## Audit, events & change tracking

| Service | What it does | Inventory script |
|---|---|---|
| **AWS CloudTrail** | API-call audit log — who did what, when | ✅ `cloudtrail` |
| **Amazon EventBridge / CloudWatch Events** | Event bus + rules routing operational events | ✅ `eventbridge` |
| **AWS Config** | Resource configuration history + compliance rules | ✅ `config` |

## Security observability

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon GuardDuty** | Threat detection from VPC/DNS/CloudTrail signals | ✅ `guardduty` |
| **AWS Security Hub** | Aggregated security findings + posture scoring | ✅ `security_hub` |
| **Amazon Inspector** | Continuous vulnerability scanning (EC2/ECR/Lambda) | ✅ `inspector` |
| **Amazon Security Lake** | Central OCSF security-data lake (logs/findings) | ✅ `security_lake` |

## Delivery / notification (observability plumbing)

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon SNS** | Alarm/notification fan-out (email, SMS, HTTP, Lambda) | ✅ `sns` |
| **Amazon Kinesis Data Firehose** | Stream logs/metrics to S3/OpenSearch/3rd-party | ✅ `kinesis` (incl. Firehose) |

---

## Front-end / APM / network monitoring

| Service | What it does | Inventory script |
|---|---|---|
| **CloudWatch Synthetics (Canaries)** | Scripted uptime/endpoint monitoring | ✅ `synthetics` |
| **CloudWatch RUM** | Real User Monitoring for web app front-ends | ✅ `rum` |
| **CloudWatch Internet Monitor** | Internet-path performance/availability | ✅ `internet_monitor` |
| **CloudWatch Application Signals** | APM (SLOs, service map) over ADOT/X-Ray | ✅ `application_signals` |

## Not yet covered by an inventory scanner

Deliberately skipped — either deprecated or no per-resource control-plane API to inventory.

| Service | What it does | Why skipped |
|---|---|---|
| **CloudWatch Evidently** | Feature flags + A/B experiments | Being deprecated by AWS |
| **AWS Distro for OpenTelemetry (ADOT)** | OTel collector distro | Agent, not an API service — nothing to scan |
| **AWS Health / Personal Health Dashboard** | Service events affecting your account | Health API, not resource inventory |
| **AWS Managed Grafana – SAML/data sources** | Auth + data-source wiring detail | Partially covered by `amg_permissions` |

---

## Notes

- **CloudWatch is the hub.** Alarms trigger SNS; Logs feed Logs Insights; Container/Lambda
  Insights and Application Signals are all CloudWatch features, not separate services.
- **Managed OSS stack = AMP + AMG + OpenSearch.** These replace self-hosted
  Prometheus/Grafana/ELK and are the ones with real per-resource cost worth auditing.
- **Security observability** (GuardDuty, Security Hub, Inspector, Security Lake) overlaps
  with the security posture the audit tool already checks (`tools/audit_aws_resources.py`).
- **"CloudWatch Events"** on a bill is the legacy name for **EventBridge** — same service.

## Coverage summary

- **Covered:** 19 observability services have inventory scanners.
- **Gaps:** only Evidently (deprecated), ADOT (agent, no API), and AWS Health
  (event API, not inventory) remain — none are per-resource inventory targets.
