# OpenAI Assistant Scanner with GitGuardian BYOS

**Scans OpenAI GPT Assistant instructions for secrets and sensitive information** using GitGuardian's BYOS (Bring Your Own Source) functionality. 

This tool automatically detects exposed credentials like API keys, database passwords, tokens, and other secrets that might be accidentally included in your OpenAI Assistant configurations. Tracks scanned assistants by modification timestamp to avoid rescanning unchanged assistants. Uses the GitGuardian Python SDK [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) to create security incidents in your GitGuardian dashboard for any secrets found.

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
   - **OPENAI_API_KEY**: Create an API key from [OpenAI Platform](https://platform.openai.com/api-keys)
   - **GITGUARDIAN_API_KEY**: Create a Service Account Token with `scan` and `scan:create-incidents` permissions from your [GitGuardian dashboard](https://dashboard.gitguardian.com/settings/api/service-accounts)
   - **SOURCE_UUID**: Create a custom source in GitGuardian dashboard for BYOS secret scanning - see [BYOS setup guide](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

## Usage

```bash
# Normal scan (skips already scanned assistants with same modification time)
python scan_openai_assistants.py

# Force rescan all assistants regardless of modification time
FORCE_RESCAN=true python scan_openai_assistants.py

# Or delete scan history to start fresh
rm scanned_assistants.json && python scan_openai_assistants.py
```

**Output examples:**
- ✅ `No secrets found in My Assistant` - Assistant is clean
- ⚠️ `Found 2 potential secret(s) in My Assistant` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "MongoDB URI")
  - Validity status (valid/invalid/failed_to_check)  
  - Line location in assistant instructions
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Files

- `scan_openai_assistants.py` - Main secret scanning script for OpenAI Assistants
- `requirements.txt` - Python dependencies (pygitguardian, requests, openai)
- `env.example` - Environment variables template
- `scanned_assistants.json` - Assistant scan history and modification time tracking (auto-created)
