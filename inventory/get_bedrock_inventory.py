#!/usr/bin/env python3
"""
Amazon Bedrock Inventory Scanner
Scans all configured AWS accounts/regions for Bedrock resources:
  - Custom models
  - Provisioned model throughput
  - Agents (AgentCore)
  - Knowledge bases
  - Guardrails

Usage:
    python get_bedrock_inventory.py
    python get_bedrock_inventory.py -a "TQ Primary"
    python get_bedrock_inventory.py -r us-east-1
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

SERVICE = "bedrock"


def _safe_list(client, method, key, **kwargs):
    """Paginate or single-call a list method, return items or empty list on error."""
    try:
        items = []
        if hasattr(client.get_paginator, '__call__'):
            try:
                paginator = client.get_paginator(method)
                for page in paginator.paginate(**kwargs):
                    items.extend(page.get(key, []))
                return items
            except client.exceptions.from_code('UnknownOperationException'):
                pass
            except Exception:
                pass
        # Fallback: single call
        resp = getattr(client, method)(**kwargs)
        return resp.get(key, [])
    except Exception:
        return []


def scan_bedrock(session, regions, writer):
    """Scan Bedrock resources across all specified regions."""
    total = {"custom_models": 0, "provisioned_throughputs": 0, "agents": 0, "knowledge_bases": 0, "guardrails": 0}

    for region in regions:
        try:
            client = session.client('bedrock', region_name=region, config=BOTO_CONFIG)
            region_data = {}

            # Custom models
            custom_models = []
            try:
                resp = client.list_custom_models()
                for m in resp.get('modelSummaries', []):
                    custom_models.append({
                        "model_name": m.get('modelName', 'N/A'),
                        "model_arn": m.get('modelArn', 'N/A'),
                        "base_model_id": m.get('baseModelIdentifier', 'N/A'),
                        "creation_time": m.get('creationTime', ''),
                    })
            except Exception:
                pass
            region_data["custom_models"] = custom_models
            total["custom_models"] += len(custom_models)

            # Provisioned throughputs
            provisioned = []
            try:
                resp = client.list_provisioned_model_throughputs()
                for pt in resp.get('provisionedModelSummaries', []):
                    provisioned.append({
                        "name": pt.get('provisionedModelName', 'N/A'),
                        "arn": pt.get('provisionedModelArn', 'N/A'),
                        "model_arn": pt.get('modelArn', 'N/A'),
                        "status": pt.get('status', 'N/A'),
                        "model_units": pt.get('desiredModelUnits', 0),
                        "creation_time": pt.get('creationTime', ''),
                    })
            except Exception:
                pass
            region_data["provisioned_throughputs"] = provisioned
            total["provisioned_throughputs"] += len(provisioned)

            # Agents (Bedrock AgentCore)
            agents = []
            try:
                agent_client = session.client('bedrock-agent', region_name=region, config=BOTO_CONFIG)
                resp = agent_client.list_agents()
                for a in resp.get('agentSummaries', []):
                    agents.append({
                        "agent_id": a.get('agentId', 'N/A'),
                        "agent_name": a.get('agentName', 'N/A'),
                        "status": a.get('agentStatus', 'N/A'),
                        "updated_at": a.get('updatedAt', ''),
                    })
            except Exception:
                pass
            region_data["agents"] = agents
            total["agents"] += len(agents)

            # Knowledge bases
            knowledge_bases = []
            try:
                agent_client = session.client('bedrock-agent', region_name=region, config=BOTO_CONFIG)
                resp = agent_client.list_knowledge_bases()
                for kb in resp.get('knowledgeBaseSummaries', []):
                    knowledge_bases.append({
                        "knowledge_base_id": kb.get('knowledgeBaseId', 'N/A'),
                        "name": kb.get('name', 'N/A'),
                        "status": kb.get('status', 'N/A'),
                        "updated_at": kb.get('updatedAt', ''),
                    })
            except Exception:
                pass
            region_data["knowledge_bases"] = knowledge_bases
            total["knowledge_bases"] += len(knowledge_bases)

            # Guardrails
            guardrails = []
            try:
                resp = client.list_guardrails()
                for g in resp.get('guardrails', []):
                    guardrails.append({
                        "guardrail_id": g.get('id', 'N/A'),
                        "name": g.get('name', 'N/A'),
                        "status": g.get('status', 'N/A'),
                        "version": g.get('version', 'N/A'),
                        "created_at": g.get('createdAt', ''),
                    })
            except Exception:
                pass
            region_data["guardrails"] = guardrails
            total["guardrails"] += len(guardrails)

            writer.set_nested("regions", region, value=region_data)

            count = len(custom_models) + len(provisioned) + len(agents) + len(knowledge_bases) + len(guardrails)
            if count:
                logger.info(f"  {region}: {len(custom_models)} models, {len(provisioned)} provisioned, "
                           f"{len(agents)} agents, {len(knowledge_bases)} KBs, {len(guardrails)} guardrails")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total


def main():
    parser = argparse.ArgumentParser(description='Bedrock Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('bedrock')
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

        totals = scan_bedrock(session, regions, writer)
        writer.set("totals", totals)
        writer.set("status", "ok")

        logger.info(f"  Totals: {totals}")

    logger.info("\n" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
