# GitHub Gist Scanner (User/Authenticated) with GitGuardian BYOS

**Scans GitHub Gists for secrets and sensitive information** using GitGuardian's BYOS (Bring Your Own Source) functionality.

This tool automatically detects exposed credentials like API keys, database passwords, tokens, and other secrets that might be accidentally included in GitHub Gists. Can scan:
- **Authenticated user's gists** (including private ones)
- **Specific user's public gists** 
- **All public members of GitHub organizations**

Tracks scanned gists by update timestamp to avoid rescanning unchanged gists. Uses the GitGuardian Python SDK [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to create security incidents in your GitGuardian dashboard for any secrets found.

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
   - **GITHUB_API_KEY**: Create a GitHub Personal Access Token with `gist` scope from [GitHub Settings](https://github.com/settings/tokens)
   - **GITGUARDIAN_API_KEY**: Create a Service Account Token with `scan` and `scan:create-incidents` permissions from your [GitGuardian dashboard](https://dashboard.gitguardian.com/settings/api/service-accounts)
   - **SOURCE_UUID**: Create a custom source in GitGuardian dashboard for BYOS secret scanning - see [BYOS setup guide](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

   **Optional:**
   - **GITHUB_USERNAME**: Target specific users' public gists (comma-separated, e.g., `user1` or `user1,user2,user3`)
   - **GITHUB_ORGS**: Scan gists from all public members of GitHub organizations (comma-separated, e.g., `myorg1,myorg2`)
   - If neither is set, scans your own gists including private ones

## Rate Limits & Organization Scanning

- **GitHub API Rate Limit**: 5,000 requests per hour (requires GitHub API token)
- Each gist requires 2 API calls (list + details), so you can scan ~2,500 gists per hour
- **Organization scanning**: Additional API calls needed to fetch member lists
- For large organizations or many gists, the scanner includes small delays to be API-friendly
- Scanner automatically handles pagination for users, organizations, and gists

## Usage

```bash
# Scan authenticated user's gists (including private gists)
python scan_github_gists.py

# Scan specific user's public gists only
GITHUB_USERNAME=user1 python scan_github_gists.py

# Scan multiple users' public gists
GITHUB_USERNAME=user1,user2,user3 python scan_github_gists.py

# Scan all public members of GitHub organizations
GITHUB_ORGS=myorg1,myorg2 python scan_github_gists.py

# Combine multiple users and organization scanning
GITHUB_USERNAME=user1,user2 GITHUB_ORGS=myorg3 python scan_github_gists.py

# Force rescan all gists regardless of update timestamp
FORCE_RESCAN=true python scan_github_gists.py

# Or delete scan history to start fresh
rm scanned_gists.json && python scan_github_gists.py
```

**Output examples:**
- ✅ `No secrets found in gist: Description` - Gist is clean
- ⚠️ `Found 2 potential secret(s) in gist: Description` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "MongoDB URI")
  - Validity status (valid/invalid/failed_to_check)
  - Line location in gist files
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Files

- `scan_github_gists.py` - Main secret scanning script for GitHub Gists
- `requirements.txt` - Python dependencies (pygitguardian, requests)
- `env.example` - Environment variables template
- `.gitignore` - Git ignore file (excludes .env and tracking files)
- `scanned_gists.json` - Gist scan history with GitHub usernames and timestamp tracking (auto-created)