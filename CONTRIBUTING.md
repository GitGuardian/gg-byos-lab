# Contributing to GitGuardian BYOS Integration Hub

We welcome BYOS integrations from the community! Share your examples that scan custom data sources for secrets.

## 🚀 **Quick Start**

1. **Fork this repository**
2. **Create your integration folder** (e.g., `jenkins-logs/`, `sftp-scanner/`)
3. **Follow this structure:**
   ```
   your-integration/
   ├── README.md              # Setup and usage docs
   ├── requirements.txt       # Dependencies
   ├── env.example           # Environment variables
   ├── scanner_script.py     # Main script
   └── .gitignore
   ```
4. **Submit a Pull Request**

## ✅ **Requirements**

- Uses GitGuardian BYOS API:
  - **Python SDK**: `scan_and_create_incidents()` from [py-gitguardian](https://github.com/GitGuardian/py-gitguardian) (recommended)
  - **Direct API**: [`POST /v1/scan/create-incidents`](https://api.gitguardian.com/docs#tag/Scan-Methods/operation/scan_create_incidents)
- Environment variables for API keys (no hardcoded secrets)
- Clear documentation and error handling
- Working integration that creates incidents in GitGuardian dashboard

## 📖 **Integration Examples**

**Python SDK (recommended):**
```python
from pygitguardian import GGClient

client = GGClient(api_key=api_key)
result = client.scan_and_create_incidents(
    documents=[{"document": content, "filename": "file.txt"}],
    source_uuid=source_uuid
)
```

**Direct API:**
```python
requests.post(
    "https://api.gitguardian.com/v1/scan/create-incidents",
    headers={"Authorization": f"Bearer {api_key}"},
    json={"source_uuid": source_uuid, "documents": [{"document": content, "filename": "file.txt"}]}
)
```

## 🛠️ **Setup**

1. Create a custom source in your GitGuardian dashboard
2. Generate a service account token with `scan` and `scan:create-incidents` permissions
3. Test your integration creates incidents properly

## 💡 **Ideas**

- CI logs (Jenkins, GitLab, GitHub Actions)
- File systems (SFTP, NFS, local directories)  
- Documentation (Confluence, wikis, markdown)
- Infrastructure (Terraform, Ansible, K8s configs)
- Chat exports (Slack, Teams)
- Database configs and stored procedures

## 📞 **Get Help**

- **Questions/Issues:** Open an issue with appropriate label
- **Documentation:** [GitGuardian BYOS docs](https://docs.gitguardian.com/internal-monitoring/integrate-sources/bring-your-own-sources)

---

*By contributing, you agree your contributions will be licensed under the same license as this project.*