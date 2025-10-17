# GitLab Snippet Scanner with GitGuardian BYOS

**Scans GitLab snippets for secrets and sensitive information** using GitGuardian's BYOS (Bring Your Own Source) functionality.

This tool automatically detects exposed credentials like API keys, database passwords, tokens, and other secrets that might be accidentally included in GitLab snippets. Supports both GitLab.com (SaaS) and self-hosted GitLab instances. Scans:

- **Authenticated user's snippets** (including private ones)
- **Project snippets** (automatically included with clear project identification)

Tracks scanned snippets by update timestamp to avoid rescanning unchanged snippets. Uses the GitGuardian Python SDK [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to create security incidents in your GitGuardian dashboard for any secrets found.

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

   - **GITLAB_API_KEY**: Create a GitLab Personal Access Token with `read_api`, `read_user`, and `read_repository` scopes from your [GitLab Access Tokens](https://gitlab.com/-/user_settings/personal_access_tokens) page (or your on-premise instance)
   - **GITGUARDIAN_API_KEY**: Create a Service Account Token with `scan` and `scan:create-incidents` permissions from your [GitGuardian dashboard](https://dashboard.gitguardian.com/settings/api/service-accounts)
   - **SOURCE_UUID**: Create a custom source in GitGuardian dashboard for BYOS secret scanning - see [BYOS setup guide](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

   **GitLab configuration:**

   - **GITLAB_BASE_URL**: GitLab instance URL (default: `https://gitlab.com` for SaaS, or `https://gitlab.mycompany.com` for on-premise)

## GitLab Instance Support

### GitLab.com (SaaS)

```bash
GITLAB_BASE_URL=https://gitlab.com
```

### Self-hosted GitLab (On-Premise)

```bash
GITLAB_BASE_URL=https://gitlab.mycompany.com
```

The scanner automatically adapts to any GitLab instance by configuring the base URL. Make sure your GitLab personal access token has the necessary permissions for the target instance.

## Rate Limits & Timeouts

**GitLab.com (SaaS):**

- **Authenticated API Requests**: 2,000 requests per minute per user
- Each snippet requires 2 API calls (list + details), so you can scan ~1,000 snippets per minute

**Self-Managed GitLab:**

- Rate limits are **configurable by administrators** - check with your GitLab admin
- Default limits may differ from GitLab.com

**Scanner behavior:**

- Automatically handles pagination for snippet listing
- Includes small delays between requests to be API-friendly
- **GitGuardian timeout**: Configured to 60 seconds (increased from default 20s) for large snippet scanning

## Usage

```bash
# Scan authenticated user's snippets (including private snippets)
python scan_gitlab_snippets.py

# Force rescan all snippets regardless of update timestamp
FORCE_RESCAN=true python scan_gitlab_snippets.py

# Or delete scan history to start fresh
rm scanned_snippets.json && python scan_gitlab_snippets.py

# Scan on-premise GitLab instance
GITLAB_BASE_URL=https://gitlab.mycompany.com python scan_gitlab_snippets.py
```

**Output examples:**

- ✅ `No secrets found in snippet: Description` - Snippet is clean
- ✅ `No secrets found in snippet: Config (Project: web-app)` - Project snippet is clean
- ⚠️ `Found 2 potential secret(s) in snippet: Database Config (Project: backend)` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "MongoDB URI")
  - Validity status (valid/invalid/failed_to_check)
  - Line location in snippet files
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Files

- `scan_gitlab_snippets.py` - Main secret scanning script for GitLab snippets
- `requirements.txt` - Python dependencies (pygitguardian, requests)
- `env.example` - Environment variables template
- `.gitignore` - Git ignore file (excludes .env and tracking files)
- `scanned_snippets.json` - Snippet scan history with GitLab usernames and timestamp tracking (auto-created)
