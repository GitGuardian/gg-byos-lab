# GitLab CI Logs Scanner with GitGuardian BYOS

**Automatically detect secrets in GitLab CI/CD pipeline logs** using GitGuardian's BYOS (Bring Your Own Source) functionality.

This solution addresses a critical but often overlooked security gap: **secrets exposure in CI/CD logs**. Your build logs may contain environment variables, API responses, debugging output, and temporary credentials that are stored for weeks or months, accessible to anyone with pipeline visibility.

> **Source**: This implementation is based on the comprehensive guide from [Detect Secrets in GitLab CI Logs using ggshield and Bring Your Own Source](https://blog.gitguardian.com/detect-secrets-in-gitlab-ci-logs/)

## The Hidden Risk in Your CI/CD Pipeline

Your CI/CD pipeline is a treasure trove of sensitive information. While you've probably focused on scanning your source code for secrets, there's another critical attack vector that often goes unnoticed: **CI/CD logs**.

Recent breaches have shown that attackers increasingly target CI/CD environments, not just for supply chain attacks, but for the wealth of credentials and sensitive data flowing through build processes.

### What Gets Exposed in CI Logs

- **Environment variables** leaked in error messages
- **API responses** containing credentials
- **Debug output** revealing internal system details
- **Temporary credentials** in deployment logs
- **Database connection strings** in test outputs
- **Application logs** with sensitive data

## Solution Overview

This implementation provides:

1. **Automated log collection** from all pipeline jobs
2. **Real-time secrets scanning** using ggshield
3. **Incident creation** in the GitGuardian dashboard
4. **Zero-friction integration** with your existing CI/CD workflows

## Prerequisites

- A **GitGuardian Business account** (required for Custom Sources)
- A **HashiCorp Vault server** for secure token storage
- A **GitLab project** with existing CI/CD pipelines
- Vault-GitLab integration configured

## Setup Instructions

### Step 1: Configure GitGuardian Custom Source

1. Navigate to **Settings > Sources** in your GitGuardian dashboard
2. Find the "Custom sources" section and click **"Add Custom Source"**
3. Name it something descriptive like "GitLab CI Logs - [Your Project Name]"
4. **Copy the unique Source ID** – you'll need this for the CI configuration

### Step 2: Generate Service Account Token

Your CI pipeline needs authentication to send scan results to GitGuardian:

1. Go to **Settings > API > Service Accounts**
2. Click **"Create service account"**
3. Name it "GitLab CI Log Scanner"
4. Select the **full scanning scope** with both "scan" and "scan-create-incidents" permissions
5. Click **"Create"** and securely store the generated token

> **Security Note**: This token has powerful permissions – treat it like a production database password.

### Step 3: Configure GitLab API Access

Generate a GitLab Personal Access Token:

1. Go to **GitLab > User Settings > Access Tokens**
2. Create a token with `read_api` scope
3. Set an appropriate expiration date
4. Store this token securely alongside your GitGuardian token

### Step 4: Build Your Custom ggshield Image

The official ggshield Docker image needs additional tools to interact with the GitLab API. Use the provided `Dockerfile`:

```bash
# Build the enhanced image
docker build . --tag enhanced-ggshield:latest

# Tag for your registry
docker tag enhanced-ggshield:latest your-docker-account/enhanced-ggshield:latest

# Push to registry
docker push your-docker-account/enhanced-ggshield:latest
```

### Step 5: Secure Token Storage in Vault

Store both tokens securely in your Vault (we'll use path `ci/[Your Project Name]/scan_logs`):

```json
{
  "GITGUARDIAN_API_KEY": "your-gitguardian-service-account-token",
  "GITLAB_TOKEN": "your-gitlab-api-token"
}
```

### Step 6: Configure the CI Job

Add the provided `job.yaml` configuration to your `.gitlab-ci.yml`.

Add the provided `scan_logs.sh` as well in your repo.

## How It Works

The `scan_logs.sh` script leverages GitLab's built-in CI environment variables:

- `CI_API_V4_URL`: GitLab API base URL
- `CI_PROJECT_ID`: Current project identifier
- `CI_PIPELINE_ID`: Current pipeline identifier

### Process Flow

1. **Every pipeline triggers log scanning** – regardless of success or failure
2. **All job logs are collected and analyzed** using ggshield's advanced detection
3. **Secrets are immediately flagged** and incidents created in GitGuardian
4. **Your security team gets real-time alerts** about CI/CD secrets exposure
5. **Audit trails are maintained** for compliance and incident response

## Files in This Directory

- `scan_logs.sh` - Main script that downloads and scans all job logs in the current pipeline
- `Dockerfile` - Enhanced ggshield image with curl and jq for GitLab API interaction
- `job.yaml` - GitLab CI job configuration template
- `README.md` - This documentation

## Security Benefits

### Catching Runtime Secrets

- Environment variables leaked in error messages
- API responses containing credentials
- Debug output revealing internal tokens
- Temporary credentials in deployment logs

### Compliance & Governance

- Complete audit trail of secrets across your entire CI/CD pipeline
- Automated evidence collection for SOC 2, ISO 27001, and other frameworks
- Real-time compliance monitoring and alerting

### Developer Experience

- Zero friction – no changes to existing development workflows
- Automatic incident creation and notification
- Educational feedback helps teams improve security practices

## Output Examples

The scanner provides clear feedback on scan results:

- ✅ `Scan completed successfully for job: build` - Job logs are clean
- ⚠️ `Found 2 potential secret(s) in job: deploy` - Secrets detected with details:
  - Secret type (e.g., "AWS Keys", "Database URI")
  - Validity status (valid/invalid/failed_to_check)
  - Line location in log files
  - GitGuardian documentation links

All detected secrets automatically create incidents in your GitGuardian dashboard for tracking and remediation.

## Next Steps

This GitLab CI log scanning is just one piece of a comprehensive secrets security strategy. Consider expanding to:

- **Multi-platform coverage**: Apply similar techniques to GitHub Actions, Jenkins, and Azure DevOps
- **Infrastructure scanning**: Monitor Kubernetes logs, server logs, and application logs
- **Real-time monitoring**: Set up webhooks for immediate incident response
- **Policy automation**: Create custom remediation workflows based on secret types

## References

- [Detect Secrets in GitLab CI Logs using ggshield and Bring Your Own Source](https://blog.gitguardian.com/detect-secrets-in-gitlab-ci-logs/) - Original blog post by Philippe Gablain and Soujanya Ain
- [GitGuardian BYOS Documentation](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)
- [GitLab CI/CD Variables](https://docs.gitlab.com/ee/ci/variables/)
- [HashiCorp Vault GitLab Integration](https://developer.hashicorp.com/vault/docs/auth/jwt#gitlab)
