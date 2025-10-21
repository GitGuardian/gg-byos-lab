# Dust Agent Scanner with GitGuardian BYOS

**Scans Dust agent instructions for secrets and sensitive information** using GitGuardian's BYOS (Bring Your Own Source) functionality. 

This tool automatically detects exposed credentials like API keys, database passwords, tokens, and other secrets that might be accidentally included in your Dust agent configurations. Tracks scanned agents by version to avoid rescanning unchanged agents. Uses the GitGuardian Python SDK [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to create security incidents in your GitGuardian dashboard for any secrets found.

## Common Findings in Dust Agents

When scanning Dust agent instructions and configurations, here are typical secrets we discover:

- 🔑 **API Keys & Tokens** OpenAI (`sk-...`), Anthropic, Google AI, Slack, and third-party service tokens embedded in agent instructions or tool configurations
- 🗝️ **Personal Access Tokens (PATs)** GitHub (`ghp_...`), GitLab, Notion, Linear, and Jira tokens included for data source integrations
- 🔐 **Cloud Provider Credentials** AWS access keys (`AKIA...`), Google Cloud service accounts, Azure storage keys for cloud data access
- 🔒 **Authentication Secrets** JWT signing keys, OAuth client secrets, API authentication tokens, and webhook secrets for custom integrations
- 📧 **Email & Communication Credentials** SendGrid (`SG.`), Mailgun, Twilio, and SMTP credentials for notification workflows
- 🛢️ **Database Credentials** MongoDB URIs, PostgreSQL connection strings, Redis passwords, and MySQL credentials in data retrieval examples
- 🔧 **Workspace & Tool Secrets** Airtable API keys, HubSpot tokens, Salesforce credentials, and custom tool authentication secrets

## Why This Matters

**For AI Operations Teams:**
- Dust agents often have **broad access to company data sources**
- Agent configurations may be **exported and shared** across teams
- Instructions are **versioned and stored**, creating a history of exposed secrets
- **Test credentials** in agent development often leak into production

**Security Impact:**
- Exposed secrets provide **unauthorized access** to connected data sources
- **Data exfiltration** from CRMs, databases, and productivity tools
- **Lateral movement** through interconnected services
- **Supply chain risks** via compromised API integrations

**Best Practice:**
Always use **Dust's environment variables** or **secret storage** features:
```text
✅ Good: "Use API key from {env.OPENAI_API_KEY}"
❌ Bad: "Use this API key: sk-proj-Ab3dEf9..."
```

## Setup

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment**
   ```bash
   cp env.example .env
   # Edit .env with your credentials
   source .env
   ```

   **Required credentials:**
   - **DUST_API_KEY**: Create a token from your Dust workspace (`https://dust.tt`)
   - **DUST_WORKSPACE_ID**: Your Dust workspace ID
   - **GITGUARDIAN_API_KEY**: Create a Service Account Token with `scan` and `scan:create-incidents` permissions from your [GitGuardian dashboard](https://dashboard.gitguardian.com/settings/api/service-accounts)
   - **SOURCE_UUID**: Create a custom source in GitGuardian dashboard for BYOS secret scanning - see [BYOS setup guide](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

## Usage

```bash
# Normal scan (skips already scanned agents with same version)
python scan_dust_agents.py

# Force rescan all agents regardless of version
FORCE_RESCAN=true python scan_dust_agents.py

# Or delete scan history to start fresh
rm scanned_agents.json && python scan_dust_agents.py
```

**Output examples:**
- ✅ `No secrets found in AgentName` - Agent is clean
- ⚠️ `Found 2 potential secret(s) in AgentName` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "MongoDB URI")
  - Validity status (valid/invalid/failed_to_check)  
  - Line location in agent instructions
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Files

- `scan_dust_agents.py` - Main secret scanning script for Dust agents
- `requirements.txt` - Python dependencies (pygitguardian, requests)
- `env.example` - Environment variables template
- `scanned_agents.json` - Agent scan history and version tracking (auto-created)
