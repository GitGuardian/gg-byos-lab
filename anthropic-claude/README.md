# Claude Project Scanner with GitGuardian BYOS

**Scans Claude project configurations and instructions for secrets and sensitive information** using GitGuardian's BYOS (Bring Your Own Source) functionality. 

This tool automatically detects exposed credentials like API keys, database passwords, tokens, and other secrets that might be accidentally included in your Claude project files. Tracks scanned projects by content hash to avoid rescanning unchanged projects. Uses the GitGuardian Python SDK [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to create security incidents in your GitGuardian dashboard for any secrets found.

> **📝 Why File-Based Scanning?**  
> Unlike OpenAI's Assistants API or Dust's agent API, there are **no endpoints to list or fetch user projects programmatically**.  
> 
> This integration uses a **file-based approach** where you save your Claude project configurations locally. This is actually quite practical since many users already manage their AI prompts and configurations in files! When/if Anthropic adds project management APIs, we can easily switch to direct API fetching.

## Common Findings in Claude Projects

When scanning Claude project configurations and instructions, here are typical secrets we discover:

- 🔑 **API Keys & Tokens** OpenAI (`sk-...`), Anthropic, Slack, GitHub, and third-party service tokens embedded in example calls or integration instructions
- 🗝️ **Personal Access Tokens (PATs)** GitHub (`ghp_...`), GitLab, Bitbucket, and Azure DevOps tokens included to demonstrate CI/CD or repository integrations
- 🔐 **Cloud Provider Credentials** AWS access keys (`AKIA...`), Google Cloud service accounts, Azure storage keys, and Terraform state tokens in infrastructure examples
- 🔒 **Authentication Secrets** JWT signing keys, OAuth client secrets, webhook validation secrets, and session keys for authentication workflows
- 📧 **Email & Communication Credentials** SendGrid (`SG.`), Mailgun, Twilio, and SMTP credentials for notification and communication examples
- 🛢️ **Database Credentials** MongoDB URIs, PostgreSQL connection strings, Redis passwords, and MySQL credentials in data processing examples
- 🔧 **CI/CD & Deployment Secrets** Docker registry tokens, Kubernetes secrets, Jenkins API tokens, and CircleCI/Travis credentials for deployment automation

## Why This Matters

**For AI Development Teams:**
- Claude projects are often **shared across teams** via exports/imports
- Projects may be **committed to repositories** for version control
- Instructions are **copy-pasted** between projects, spreading credentials
- **Test/example credentials** often become production credentials

**Security Impact:**
- Exposed secrets provide **unauthorized access** to systems
- **Lateral movement** if credentials have broad permissions
- **Data exfiltration** from databases and APIs
- **Supply chain attacks** via compromised CI/CD tokens

**Best Practice:**
Always use **environment variables** or **secret managers** in your Claude instructions:
```text
✅ Good: "Use the API key from environment variable ${OPENAI_API_KEY}"
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
   - **GITGUARDIAN_API_KEY**: Create a Service Account Token with `scan` and `scan:create-incidents` permissions from your [GitGuardian dashboard](https://dashboard.gitguardian.com/settings/api/service-accounts)
   - **SOURCE_UUID**: Create a custom source in GitGuardian dashboard for BYOS secret scanning - see [BYOS setup guide](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

3. **Add your Claude project files**
   ```bash
   mkdir projects
   # Add your Claude project files (.txt, .md, .json) to the projects/ directory
   ```

   **Supported formats:**
   - `.txt` files - Raw text instructions
   - `.md` files - Markdown formatted instructions  
   - `.json` files - Structured project configs (extracts `instructions`, `system_prompt`, `prompt`, `description`, `content` fields)

## Usage

```bash
# Normal scan (skips already scanned projects with same content)
python scan_claude_projects.py

# Force rescan all projects regardless of content hash
FORCE_RESCAN=true python scan_claude_projects.py

# Use custom projects directory
CLAUDE_PROJECTS_DIR=my_projects python scan_claude_projects.py

# Or delete scan history to start fresh
rm scanned_projects.json && python scan_claude_projects.py
```

**Output examples:**
- ✅ `No secrets found in my_project` - Project is clean
- ⚠️ `Found 2 potential secret(s) in my_project` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "MongoDB URI")
  - Validity status (valid/invalid/failed_to_check)  
  - Line location in project file
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Files

- `scan_claude_projects.py` - Main secret scanning script for Claude projects
- `requirements.txt` - Python dependencies (pygitguardian, requests, anthropic)
- `env.example` - Environment variables template
- `scanned_projects.json` - Project scan history and content hash tracking (auto-created)
- `projects/` - Directory for your Claude project files (create manually)
