#!/usr/bin/env python3
"""
Anthropic Claude Project Scanner with GitGuardian BYOS

Scans Claude project configurations and instructions for secrets and sensitive information 
using GitGuardian's BYOS (Bring Your Own Source) functionality.

Tracks scanned projects by configuration hash to avoid rescanning unchanged projects.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from pygitguardian import GGClient


class ClaudeProjectScanner:
    def __init__(self):
        """Initialize the scanner with API credentials from environment variables."""
        env_vars = {
            'GITGUARDIAN_API_KEY': 'gitguardian_api_key',
            'SOURCE_UUID': 'source_uuid'
        }
        
        missing = []
        for env_name, attr in env_vars.items():
            value = os.getenv(env_name)
            if value:
                setattr(self, attr, value)
            else:
                missing.append(env_name)
        
        if missing:
            print("Error: Missing required environment variables:")
            print(*[f"  - {var}" for var in missing], sep='\n')
            print(f"\nAll required: {', '.join(env_vars.keys())}")
            sys.exit(1)
        
        self.gg_client = GGClient(api_key=self.gitguardian_api_key)
        self.scanned_projects_file = "scanned_projects.json"
        self.scanned_projects = self.load_scanned_projects()
        self.force_rescan = os.getenv("FORCE_RESCAN", "false").lower() == "true"
        self.projects_dir = os.getenv("CLAUDE_PROJECTS_DIR", "projects")

    def load_scanned_projects(self) -> Dict:
        """Load previously scanned projects from JSON file."""
        try:
            with open(self.scanned_projects_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_scanned_projects(self):
        """Save scanned projects to JSON file."""
        with open(self.scanned_projects_file, 'w') as f:
            json.dump(self.scanned_projects, f, indent=2)

    def get_content_hash(self, content: str) -> str:
        """Generate hash of content for change detection."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def should_scan_project(self, project_name: str, content_hash: str) -> bool:
        """Check if project should be scanned based on content hash."""
        if self.force_rescan:
            return True
        
        if project_name not in self.scanned_projects:
            return True
        
        return self.scanned_projects[project_name].get('content_hash') != content_hash

    def discover_claude_projects(self) -> List[Dict]:
        """Discover Claude project files in the projects directory."""
        projects = []
        projects_path = Path(self.projects_dir)
        
        if not projects_path.exists():
            print(f"Projects directory '{self.projects_dir}' not found.")
            print("Create the directory and add your Claude project files:")
            print(f"  mkdir {self.projects_dir}")
            print("  # Add your .txt, .md, or .json files with Claude instructions")
            return []
        
        # Support multiple file formats
        patterns = ['*.txt', '*.md', '*.json']
        for pattern in patterns:
            for file_path in projects_path.glob(pattern):
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding='utf-8')
                        
                        # For JSON files, extract relevant fields
                        if file_path.suffix.lower() == '.json':
                            try:
                                data = json.loads(content)
                                # Extract instructions from various possible fields
                                instruction_fields = ['instructions', 'system_prompt', 'prompt', 'description', 'content']
                                extracted_content = []
                                for field in instruction_fields:
                                    if field in data and data[field]:
                                        extracted_content.append(f"# {field.title()}\n{data[field]}")
                                content = '\n\n'.join(extracted_content) if extracted_content else content
                            except json.JSONDecodeError:
                                pass  # Use raw content if JSON parsing fails
                        
                        projects.append({
                            'name': file_path.stem,
                            'file_path': str(file_path),
                            'content': content,
                            'content_hash': self.get_content_hash(content)
                        })
                    except Exception as e:
                        print(f"Warning: Could not read {file_path}: {e}")
        
        return projects

    def scan_project_content(self, project: Dict) -> Optional[Dict]:
        """Scan project content using GitGuardian BYOS."""
        project_name = project['name']
        content = project['content']
        
        if not content.strip():
            print(f"Project {project_name} has no content to scan")
            return None
        
        print(f"Scanning project: {project_name}")
        
        try:
            documents = [{
                "document": content, 
                "filename": f"claude_project_{project_name}.md"
            }]
            multi_scan_result = self.gg_client.scan_and_create_incidents(
                documents, 
                source_uuid=self.source_uuid
            )
            
            if hasattr(multi_scan_result, 'scan_results') and multi_scan_result.scan_results:
                return {
                    'project_name': project_name,
                    'file_path': project['file_path'],
                    'scan_result': multi_scan_result.scan_results[0],
                    'scan_timestamp': datetime.now().isoformat()
                }
            else:
                print(f"Error scanning project {project_name}: {multi_scan_result}")
                return None
                
        except Exception as e:
            print(f"Error scanning project {project_name}: {e}")
            return None

    def process_scan_results(self, scan_data: Dict) -> int:
        """Process and display scan results. Returns number of secrets found."""
        project_name = scan_data['project_name']
        scan_result = scan_data['scan_result']
        
        if not (hasattr(scan_result, 'policy_break_count') and scan_result.policy_break_count > 0):
            print(f"✅ No secrets found in {project_name}")
            return 0
        
        print(f"⚠️  Found {scan_result.policy_break_count} potential secret(s) in {project_name}")
        for i, policy_break in enumerate(scan_result.policy_breaks, 1):
            print(f"  {i}. {policy_break.break_type}")
            print(f"     Validity: {policy_break.validity}")
            print(f"     Detector: {policy_break.detector_name}")
            
            # Show line numbers from matches
            if hasattr(policy_break, 'matches') and policy_break.matches:
                lines = sorted({match.line_start for match in policy_break.matches if hasattr(match, 'line_start')})
                if lines:
                    location = f"Line {lines[0]}" if len(lines) == 1 else f"Lines {', '.join(map(str, lines))}"
                    print(f"     Location: {location}")
            
            # Show documentation link
            if hasattr(policy_break, 'documentation_url') and policy_break.documentation_url:
                print(f"     Info: {policy_break.documentation_url}")
            print()
        
        return scan_result.policy_break_count

    def run_scan(self):
        """Main scanning workflow."""
        print("🧠 Starting Claude Project Scanner with GitGuardian BYOS")
        print(f"Source UUID: {self.source_uuid}")
        print(f"Projects directory: {self.projects_dir}")
        if self.force_rescan:
            print("🔄 Force rescan mode: Will rescan all projects regardless of content hash")
        print()
        
        if not self.gg_client.health_check().success:
            print("❌ GitGuardian API health check failed. Please check your API key.")
            return
        
        print("📁 Discovering Claude projects...")
        projects = self.discover_claude_projects()
        if not projects:
            print("No projects found. Please add project files to the projects directory.")
            return
        
        print(f"Found {len(projects)} project(s)\n")
        
        scanned_count = skipped_count = secrets_found = 0
        
        for project in projects:
            project_name = project['name']
            content_hash = project['content_hash']
            
            if not self.should_scan_project(project_name, content_hash):
                skipped_count += 1
                continue
            
            scan_data = self.scan_project_content(project)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_projects[project_name] = {
                    'file_path': project['file_path'],
                    'content_hash': content_hash,
                    'last_scanned': datetime.now().isoformat(),
                    'source_uuid': self.source_uuid
                }
                scanned_count += 1
            print()
        
        self.save_scanned_projects()
        
        print("📊 Scan Summary:")
        print(f"  • Projects scanned: {scanned_count}")
        print(f"  • Projects skipped: {skipped_count}")
        print(f"  • Total projects: {len(projects)}")
        print(f"  • Secrets found: {secrets_found}")


def main():
    scanner = ClaudeProjectScanner()
    scanner.run_scan()


if __name__ == "__main__":
    main()
