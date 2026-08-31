# AWS Observability Services

Reference list of AWS services relevant to observability — metrics, logs, traces,
alerting, and the managed open-source stack.

- **Inventory** — a scanner exists (`inventory/get_<name>_inventory.py`).
- **Audit** — the anomaly/cost tool (`tools/audit_aws_resources.py`) has a check for it.

Observability = the three pillars (**metrics**, **logs**, **traces**) plus the
signals built on them (**alerts**, **dashboards**, **events**).

---

## Core observability

| Service | What it does | Inventory | Audit |
|---|---|---|---|
| **Amazon CloudWatch** | Metrics, logs, dashboards, Logs Insights, Container/Lambda Insights | ✅ `cloudwatch` | ✅ alarms in INSUFFICIENT_DATA |
| **CloudWatch Alarms** | Metric/composite/anomaly-detection alarms → SNS actions | ✅ `cloudwatch_alarms` | — |
| **AWS X-Ray** | Distributed tracing, service maps, latency analysis | ✅ `xray` | — |
| **Amazon Managed Service for Prometheus (AMP)** | Managed Prometheus for metrics ingestion/query (PromQL) | ✅ `amp` | — |
| **Amazon Managed Grafana (AMG)** | Managed Grafana dashboards over AMP/CloudWatch/X-Ray | ✅ `amg` | — |
| **Amazon OpenSearch Service** | Log search/analytics, OpenSearch Dashboards (Kibana) | ✅ `opensearch` | ✅ reliability |

## Audit, events & change tracking

| Service | What it does | Inventory | Audit |
|---|---|---|---|
| **AWS CloudTrail** | API-call audit log — who did what, when | ✅ `cloudtrail` | ✅ not-logging, no validation, stale delivery |
| **Amazon EventBridge / CloudWatch Events** | Event bus + rules routing operational events | ✅ `eventbridge` | ✅ disabled rules |
| **AWS Config** | Resource configuration history + compliance rules | ✅ `config` | ✅ recorder not recording |

## Security observability

| Service | What it does | Inventory | Audit |
|---|---|---|---|
| **Amazon GuardDuty** | Threat detection from VPC/DNS/CloudTrail signals | ✅ `guardduty` | ✅ detector not enabled |
| **AWS Security Hub** | Aggregated security findings + posture scoring | ✅ `security_hub` | ✅ not enabled, 0 standards |
| **Amazon Inspector** | Continuous vulnerability scanning (EC2/ECR/Lambda) | ✅ `inspector` | ✅ not enabled |
| **Amazon Security Lake** | Central OCSF security-data lake (logs/findings) | ✅ `security_lake` | ✅ weak key, no replication, no retention, dead subs |

## Delivery / notification (observability plumbing)

| Service | What it does | Inventory | Audit |
|---|---|---|---|
| **Amazon SNS** | Alarm/notification fan-out (email, SMS, HTTP, Lambda) | ✅ `sns` | ✅ 0-subscription topics |
| **Amazon Kinesis Data Firehose** | Stream logs/metrics to S3/OpenSearch/3rd-party | ✅ `kinesis` (incl. Firehose) | ✅ idle provisioned streams |

---

## Front-end / APM / network monitoring

| Service | What it does | Inventory | Audit |
|---|---|---|---|
| **CloudWatch Synthetics (Canaries)** | Scripted uptime/endpoint monitoring | ✅ `synthetics` | ✅ failed run, stopped, EOL runtime |
| **CloudWatch RUM** | Real User Monitoring for web app front-ends | ✅ `rum` | ✅ 0% sample rate |
| **CloudWatch Internet Monitor** | Internet-path performance/availability | ✅ `internet_monitor` | — |
| **CloudWatch Application Signals** | APM (SLOs, service map) over ADOT/X-Ray | ✅ `application_signals` | — |

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

- **Inventory:** 19 observability services have scanners.
- **Audit:** 13 have anomaly/cost checks in `tools/audit_aws_resources.py` —
  CloudWatch, OpenSearch, CloudTrail, EventBridge, Config, GuardDuty, Inspector,
  Security Hub, Security Lake, SNS, Kinesis, Synthetics, RUM.
- **Inventory but no audit yet:** CloudWatch Alarms, X-Ray, AMP, AMG,
  Internet Monitor, Application Signals.
- **Gaps (no scanner):** Evidently (deprecated), ADOT (agent, no API), AWS Health
  (event API, not inventory) — none are per-resource inventory targets.
