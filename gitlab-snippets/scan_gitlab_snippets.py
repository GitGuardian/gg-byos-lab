#!/usr/bin/env python3
"""
GitLab Snippet Scanner (SaaS & On-Premise) with GitGuardian BYOS

Scans GitLab snippets for a specific user or authenticated user's snippets for secrets 
and sensitive information using GitGuardian's BYOS (Bring Your Own Source) functionality.

Supports both GitLab.com (SaaS) and self-hosted GitLab instances.
Tracks scanned snippets by update timestamp to avoid rescanning unchanged snippets.
"""

import os
import sys
import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional, Set
from pygitguardian import GGClient


class GitLabSnippetScanner:
    def __init__(self):
        """Initialize the scanner with API credentials from environment variables."""
        env_vars = {
            'GITLAB_API_KEY': 'gitlab_api_key',
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
        
        # GitLab configuration
        self.gitlab_base_url = os.getenv('GITLAB_BASE_URL', 'https://gitlab.com').rstrip('/')
        
        # Configure GitGuardian client with increased timeout
        self.gg_client = GGClient(api_key=self.gitguardian_api_key, timeout=60)
        self.scanned_snippets_file = "scanned_snippets.json"
        self.scanned_snippets = self.load_scanned_snippets()
        self.force_rescan = os.getenv("FORCE_RESCAN", "false").lower() == "true"


    def load_scanned_snippets(self) -> Dict:
        """Load previously scanned snippets from JSON file."""
        try:
            with open(self.scanned_snippets_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_scanned_snippets(self):
        """Save scanned snippets to JSON file."""
        with open(self.scanned_snippets_file, 'w') as f:
            json.dump(self.scanned_snippets, f, indent=2)

    def should_scan_snippet(self, snippet_id: str, updated_at: str) -> bool:
        """Check if snippet should be scanned based on update timestamp."""
        if self.force_rescan:
            return True
        
        # Ensure snippet_id is always a string for consistent key lookup
        snippet_key = str(snippet_id)
        
        if snippet_key not in self.scanned_snippets:
            return True
        
        return self.scanned_snippets[snippet_key].get('updated_at') != updated_at

    def get_gitlab_api_headers(self) -> Dict[str, str]:
        """Get GitLab API headers with authentication."""
        # Try PRIVATE-TOKEN first (common for GitLab instances)
        auth_method = os.getenv('GITLAB_AUTH_METHOD', 'PRIVATE-TOKEN').upper()
        
        if auth_method == 'BEARER':
            return {
                "Authorization": f"Bearer {self.gitlab_api_key}",
                "Content-Type": "application/json"
            }
        else:  # Default to PRIVATE-TOKEN
            return {
                "PRIVATE-TOKEN": self.gitlab_api_key,
                "Content-Type": "application/json"
            }


    def get_authenticated_user_snippets(self) -> Optional[List[Dict]]:
        """Fetch snippets for the authenticated user (including private snippets)."""
        url = f"{self.gitlab_base_url}/api/v4/snippets"
        headers = self.get_gitlab_api_headers()
        
        try:
            all_snippets = []
            page = 1
            per_page = 100
            
            while True:
                params = {"page": page, "per_page": per_page}
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()
                
                snippets = response.json()
                if not snippets:
                    break
                    
                all_snippets.extend(snippets)
                page += 1
                
                # GitLab API returns fewer results than per_page when on last page
                if len(snippets) < per_page:
                    break
            
            return all_snippets
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching authenticated user snippets: {e}")
            return None


    def _enhance_snippet_info(self, snippets: List[Dict]) -> List[Dict]:
        """Enhance snippet info with project details for better display."""
        for snippet in snippets:
            # Optional debug mode to see snippet data structure
            debug_mode = os.getenv('DEBUG_SNIPPETS', 'false').lower() == 'true'
            if debug_mode:
                print(f"🔍 Debug snippet data for '{snippet.get('title', 'No title')}':")
                print(f"   web_url: {snippet.get('web_url', 'None')}")
                print(f"   project_id: {snippet.get('project_id', 'None')}")
                print(f"   project: {snippet.get('project', 'None')}")
                print(f"   Raw keys: {list(snippet.keys())}")
                print()
            
            # Determine if this is a project snippet and extract project info
            web_url = snippet.get('web_url', '')
            
            # GitLab project snippets URLs look like:
            # https://gitlab.com/group/project/-/snippets/123 (PROJECT snippet)
            # https://gitlab.com/-/snippets/123 (USER snippet)
            # The key difference: project snippets have path components before /-/snippets/
            is_project_snippet = (
                snippet.get('project_id') is not None or
                snippet.get('project') is not None
            )
            
            # If no explicit project info, check URL pattern
            if not is_project_snippet and '/-/snippets/' in web_url:
                # Split on /-/snippets/ and check what's before it
                url_parts = web_url.split('/-/snippets/')
                if len(url_parts) > 0:
                    before_snippets = url_parts[0]
                    # Extract path after domain (skip protocol and domain)
                    if '://' in before_snippets:
                        path_part = '/'.join(before_snippets.split('/')[3:])  # Skip protocol, domain
                    else:
                        path_part = before_snippets
                    
                    # If there's a path before /-/snippets/, it's a project snippet
                    # User snippets: https://gitlab.com/-/snippets/123 -> path_part = ""
                    # Project snippets: https://gitlab.com/group/project/-/snippets/123 -> path_part = "group/project"
                    is_project_snippet = bool(path_part and path_part != "")
            
            if is_project_snippet:
                # Extract project name from URL or project object
                project_info = snippet.get('project', {})
                if project_info and isinstance(project_info, dict):
                    snippet['_project_name'] = project_info.get('name', 'Unknown Project')
                    snippet['_project_path'] = project_info.get('path_with_namespace', project_info.get('path', ''))
                elif '/-/snippets/' in web_url:
                    # Extract project path from URL like: https://gitlab.com/group/project/-/snippets/123
                    url_parts = web_url.split('/-/snippets/')
                    if len(url_parts) > 0:
                        # Get everything before /-/snippets/ and extract the project part
                        project_url = url_parts[0]
                        # Remove the base GitLab URL to get just the project path
                        if '://' in project_url:
                            project_path = '/'.join(project_url.split('/')[3:])  # Skip protocol and domain
                        else:
                            project_path = project_url
                        
                        snippet['_project_name'] = project_path.split('/')[-1] if '/' in project_path else project_path
                        snippet['_project_path'] = project_path
                
                snippet['_snippet_type'] = 'project'
                
                if debug_mode:
                    print(f"✅ Detected project snippet: {snippet.get('_project_name', 'Unknown')}")
            else:
                snippet['_snippet_type'] = 'user'
                if debug_mode:
                    print(f"👤 Detected user snippet")
                
        return snippets

    def get_gitlab_snippets(self) -> Optional[List[Dict]]:
        """Fetch snippets from GitLab API for authenticated user. Returns None on error."""
        print("📥 Fetching snippets for authenticated user...")
        snippets = self.get_authenticated_user_snippets()
        if snippets is None:
            return None
        
        # Enhance snippets with project information
        enhanced_snippets = self._enhance_snippet_info(snippets)
        print(f"Found {len(snippets)} snippet(s) for authenticated user")
        
        return enhanced_snippets

    def get_snippet_details(self, snippet_id: str, project_id: Optional[str] = None) -> Optional[Dict]:
        """Fetch detailed snippet information including file contents."""
        snippet_id = str(snippet_id)  # Ensure string type
        if project_id:
            url = f"{self.gitlab_base_url}/api/v4/projects/{project_id}/snippets/{snippet_id}"
        else:
            url = f"{self.gitlab_base_url}/api/v4/snippets/{snippet_id}"
            
        headers = self.get_gitlab_api_headers()
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching snippet details for {snippet_id}: {e}")
            return None

    def get_snippet_raw_content(self, snippet_id: str, project_id: Optional[str] = None) -> Optional[str]:
        """Fetch raw content of a snippet."""
        snippet_id = str(snippet_id)  # Ensure string type
        if project_id:
            url = f"{self.gitlab_base_url}/api/v4/projects/{project_id}/snippets/{snippet_id}/raw"
        else:
            url = f"{self.gitlab_base_url}/api/v4/snippets/{snippet_id}/raw"
            
        headers = self.get_gitlab_api_headers()
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching snippet raw content for {snippet_id}: {e}")
            return None

    def get_snippet_content(self, snippet: Dict) -> str:
        """Extract content from a snippet."""
        snippet_id = str(snippet.get('id'))  # Ensure consistent string type
        project_id = snippet.get('_project_id')
        
        # Try to get raw content first
        raw_content = self.get_snippet_raw_content(snippet_id, project_id)
        if raw_content:
            return raw_content
        
        # Fallback to content field in snippet details
        snippet_details = self.get_snippet_details(snippet_id, project_id)
        if snippet_details:
            return snippet_details.get('content', '')
        
        return ""

    def scan_snippet_content(self, snippet: Dict) -> Optional[Dict]:
        """Scan snippet content using GitGuardian BYOS."""
        snippet_id = str(snippet.get('id'))  # Ensure consistent string type
        snippet_title = snippet.get('title', 'No title')
        snippet_filename = snippet.get('file_name', f'snippet_{snippet_id}')
        
        content = self.get_snippet_content(snippet)
        
        if not content.strip():
            print(f"Snippet {snippet_id} ({snippet_title}) has no content to scan")
            return None
        
        # Show project info if this is a project snippet
        project_name = snippet.get('_project_name')
        if project_name:
            print(f"Scanning snippet: {snippet_title or snippet_id} (Project: {project_name})")
        else:
            print(f"Scanning snippet: {snippet_title or snippet_id}")
        
        try:
            # Extract username from snippet author
            author = snippet.get('author', {})
            username = author.get('username', 'authenticated_user') if author else 'authenticated_user'
            
            snippet_type = snippet.get('_snippet_type', 'user')
            project_info = f"_project_{snippet.get('_project_id')}" if snippet_type == 'project' else ""
            
            documents = [{
                "document": content, 
                "filename": f"gitlab_{snippet_type}_snippet_{username}{project_info}_{snippet_id}_{snippet_filename}"
            }]
            multi_scan_result = self.gg_client.scan_and_create_incidents(
                documents, 
                source_uuid=self.source_uuid
            )
            
            if hasattr(multi_scan_result, 'scan_results') and multi_scan_result.scan_results:
                return {
                    'snippet_id': snippet_id,
                    'snippet_title': snippet_title,
                    'snippet_filename': snippet_filename,
                    'snippet_url': snippet.get('web_url', ''),
                    'snippet_type': snippet_type,
                    'project_id': snippet.get('_project_id'),
                    'project_name': snippet.get('_project_name'),
                    'project_path': snippet.get('_project_path'),
                    'scan_result': multi_scan_result.scan_results[0],
                    'scan_timestamp': datetime.now().isoformat()
                }
            else:
                print(f"Error scanning snippet {snippet_id}: {multi_scan_result}")
                return None
                
        except Exception as e:
            print(f"Error scanning snippet {snippet_id}: {e}")
            return None

    def process_scan_results(self, scan_data: Dict) -> int:
        """Process and display scan results. Returns number of secrets found."""
        snippet_title = scan_data['snippet_title']
        snippet_url = scan_data['snippet_url']
        scan_result = scan_data['scan_result']
        
        # Format snippet display with project info if available
        project_name = scan_data.get('project_name')
        snippet_display = f"{snippet_title} (Project: {project_name})" if project_name else snippet_title
        
        if not (hasattr(scan_result, 'policy_break_count') and scan_result.policy_break_count > 0):
            print(f"✅ No secrets found in snippet: {snippet_display}")
            return 0
        
        print(f"⚠️  Found {scan_result.policy_break_count} potential secret(s) in snippet: {snippet_display}")
        print(f"🔗 URL: {snippet_url}")
        
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
        print(f"📋 Starting GitLab Snippet Scanner for authenticated user")
        print(f"GitLab Instance: {self.gitlab_base_url}")
        print(f"Source UUID: {self.source_uuid}")
        if self.force_rescan:
            print("🔄 Force rescan mode: Will rescan all snippets regardless of update timestamp")
        print()
        
        if not self.gg_client.health_check().success:
            print("❌ GitGuardian API health check failed. Please check your API key.")
            return
        
        snippets = self.get_gitlab_snippets()
        if snippets is None:
            print("❌ Failed to fetch snippets. Please check your GitLab API key and permissions.")
            return
        if not snippets:
            print(f"ℹ️  No snippets found for specified target(s).")
            return
        
        print(f"Found {len(snippets)} snippet(s) total\n")
        
        scanned_count = skipped_count = no_content_count = secrets_found = 0
        
        for snippet in snippets:
            snippet_id = str(snippet.get('id'))  # Ensure consistent string type
            updated_at = snippet.get('updated_at')
            snippet_title = snippet.get('title', 'No title')
            snippet_type = snippet.get('_snippet_type', 'user')
            
            if not self.should_scan_snippet(snippet_id, updated_at):
                skipped_count += 1
                continue
            
            scan_data = self.scan_snippet_content(snippet)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_snippets[snippet_id] = {
                    'title': scan_data['snippet_title'],
                    'filename': scan_data['snippet_filename'],
                    'url': scan_data['snippet_url'],
                    'snippet_type': scan_data['snippet_type'],
                    'project_id': scan_data.get('project_id'),
                    'project_name': scan_data.get('project_name'),
                    'project_path': scan_data.get('project_path'),
                    'updated_at': updated_at,
                    'last_scanned': datetime.now().isoformat(),
                    'source_uuid': self.source_uuid,
                    'gitlab_instance': self.gitlab_base_url
                }
                scanned_count += 1
            else:
                # Snippet has no content to scan  
                no_content_count += 1
                self.scanned_snippets[snippet_id] = {
                    'title': snippet_title,
                    'filename': snippet.get('file_name', f'snippet_{snippet_id}'),
                    'url': snippet.get('web_url', ''),
                    'snippet_type': snippet_type,
                    'project_id': snippet.get('_project_id'),
                    'project_name': snippet.get('_project_name'),
                    'project_path': snippet.get('_project_path'),
                    'updated_at': updated_at,
                    'last_scanned': datetime.now().isoformat(),
                    'source_uuid': self.source_uuid,
                    'gitlab_instance': self.gitlab_base_url,
                    'no_content': True
                }
            print()
        
        self.save_scanned_snippets()
        
        print("📊 Scan Summary:")
        print(f"  • Snippets scanned: {scanned_count}")
        print(f"  • Snippets skipped: {skipped_count}")
        print(f"  • No content: {no_content_count}")
        print(f"  • Total snippets: {len(snippets)}")
        print(f"  • Secrets found: {secrets_found}")


def main():
    scanner = GitLabSnippetScanner()
    scanner.run_scan()


if __name__ == "__main__":
    main()
