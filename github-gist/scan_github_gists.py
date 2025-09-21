#!/usr/bin/env python3
"""
GitHub Gist Scanner (User/Authenticated) with GitGuardian BYOS

Scans GitHub Gists for a specific user or authenticated user's gists for secrets 
and sensitive information using GitGuardian's BYOS (Bring Your Own Source) functionality.

Tracks scanned gists by update timestamp to avoid rescanning unchanged gists.
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
from pygitguardian import GGClient


class GitHubGistScanner:
    def __init__(self):
        """Initialize the scanner with API credentials from environment variables."""
        env_vars = {
            'GITHUB_API_KEY': 'github_api_key',
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
        
        self.github_username = os.getenv('GITHUB_USERNAME')
        self.gg_client = GGClient(api_key=self.gitguardian_api_key)
        self.scanned_gists_file = "scanned_gists.json"
        self.scanned_gists = self.load_scanned_gists()
        self.force_rescan = os.getenv("FORCE_RESCAN", "false").lower() == "true"

    def load_scanned_gists(self) -> Dict:
        """Load previously scanned gists from JSON file."""
        try:
            with open(self.scanned_gists_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_scanned_gists(self):
        """Save scanned gists to JSON file."""
        with open(self.scanned_gists_file, 'w') as f:
            json.dump(self.scanned_gists, f, indent=2)

    def should_scan_gist(self, gist_id: str, updated_at: str) -> bool:
        """Check if gist should be scanned based on update timestamp."""
        if self.force_rescan:
            return True
        
        if gist_id not in self.scanned_gists:
            return True
        
        return self.scanned_gists[gist_id].get('updated_at') != updated_at

    def get_github_gists(self) -> Optional[List[Dict]]:
        """Fetch gists from GitHub API. Returns None on error."""
        if self.github_username:
            url = f"https://api.github.com/users/{self.github_username}/gists"
            scan_type = f"user '{self.github_username}'"
        else:
            url = "https://api.github.com/gists"
            scan_type = "authenticated user"
            
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        try:
            print(f"📥 Fetching gists for {scan_type}...")
            all_gists = []
            page = 1
            per_page = 100
            
            while True:
                params = {"page": page, "per_page": per_page}
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()
                
                gists = response.json()
                if not gists:
                    break
                    
                all_gists.extend(gists)
                print(f"Fetched page {page}: {len(gists)} gists")
                page += 1
                
                # GitHub API returns fewer results than per_page when on last page
                if len(gists) < per_page:
                    break
            
            return all_gists
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching GitHub gists: {e}")
            return None

    def get_gist_details(self, gist_id: str) -> Optional[Dict]:
        """Fetch detailed gist information including file contents."""
        url = f"https://api.github.com/gists/{gist_id}"
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching gist details for {gist_id}: {e}")
            return None

    def get_gist_content(self, gist_details: Dict) -> str:
        """Extract all file contents from a detailed gist response."""
        files = gist_details.get('files', {})
        
        if not files:
            return ""
        
        content_parts = []
        for filename, file_info in files.items():
            file_content = file_info.get('content', '')
            if file_content:
                content_parts.append(f"# File: {filename}\n{file_content}")
        
        return '\n\n---\n\n'.join(content_parts)

    def scan_gist_content(self, gist: Dict) -> Optional[Dict]:
        """Scan gist content using GitGuardian BYOS."""
        gist_id = gist.get('id')
        gist_description = gist.get('description', 'No description')
        
        # Fetch detailed gist information with file contents
        gist_details = self.get_gist_details(gist_id)
        if not gist_details:
            return None
            
        content = self.get_gist_content(gist_details)
        
        if not content.strip():
            print(f"Gist {gist_id} ({gist_description}) has no content to scan")
            return None
        
        print(f"Scanning gist: {gist_description or gist_id}")
        
        try:
            documents = [{
                "document": content, 
                "filename": f"github_gist_{gist_id}.md"
            }]
            multi_scan_result = self.gg_client.scan_and_create_incidents(
                documents, 
                source_uuid=self.source_uuid
            )
            
            if hasattr(multi_scan_result, 'scan_results') and multi_scan_result.scan_results:
                return {
                    'gist_id': gist_id,
                    'gist_description': gist_description,
                    'gist_url': gist_details.get('html_url', gist.get('html_url', '')),
                    'file_count': len(gist_details.get('files', {})),
                    'scan_result': multi_scan_result.scan_results[0],
                    'scan_timestamp': datetime.now().isoformat()
                }
            else:
                print(f"Error scanning gist {gist_id}: {multi_scan_result}")
                return None
                
        except Exception as e:
            print(f"Error scanning gist {gist_id}: {e}")
            return None

    def process_scan_results(self, scan_data: Dict) -> int:
        """Process and display scan results. Returns number of secrets found."""
        gist_description = scan_data['gist_description']
        gist_url = scan_data['gist_url']
        scan_result = scan_data['scan_result']
        
        if not (hasattr(scan_result, 'policy_break_count') and scan_result.policy_break_count > 0):
            print(f"✅ No secrets found in gist: {gist_description}")
            return 0
        
        print(f"⚠️  Found {scan_result.policy_break_count} potential secret(s) in gist: {gist_description}")
        print(f"🔗 URL: {gist_url}")
        
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
        scan_target = f"user '{self.github_username}'" if self.github_username else "authenticated user"
        print(f"📋 Starting GitHub Gist Scanner for {scan_target}")
        print(f"Source UUID: {self.source_uuid}")
        if self.force_rescan:
            print("🔄 Force rescan mode: Will rescan all gists regardless of update timestamp")
        print()
        
        if not self.gg_client.health_check().success:
            print("❌ GitGuardian API health check failed. Please check your API key.")
            return
        
        gists = self.get_github_gists()
        if gists is None:
            print("❌ Failed to fetch gists. Please check your GitHub API key and permissions.")
            return
        if not gists:
            print(f"ℹ️  No gists found for {scan_target}.")
            return
        
        print(f"Found {len(gists)} gist(s)\n")
        
        scanned_count = skipped_count = no_content_count = secrets_found = 0
        
        for gist in gists:
            gist_id = gist.get('id')
            updated_at = gist.get('updated_at')
            
            if not self.should_scan_gist(gist_id, updated_at):
                skipped_count += 1
                continue
            
            scan_data = self.scan_gist_content(gist)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_gists[gist_id] = {
                    'description': scan_data['gist_description'],
                    'url': scan_data['gist_url'],
                    'file_count': scan_data['file_count'],
                    'updated_at': updated_at,
                    'last_scanned': datetime.now().isoformat(),
                    'source_uuid': self.source_uuid
                }
                scanned_count += 1
            else:
                # Gist has no content to scan
                no_content_count += 1
                self.scanned_gists[gist_id] = {
                    'description': gist.get('description', 'No description'),
                    'url': gist.get('html_url', ''),
                    'file_count': len(gist.get('files', {})),
                    'updated_at': updated_at,
                    'last_scanned': datetime.now().isoformat(),
                    'source_uuid': self.source_uuid,
                    'no_content': True
                }
            print()
        
        self.save_scanned_gists()
        
        print("📊 Scan Summary:")
        print(f"  • Gists scanned: {scanned_count}")
        print(f"  • Gists skipped: {skipped_count}")
        print(f"  • No content: {no_content_count}")
        print(f"  • Total gists: {len(gists)}")
        print(f"  • Secrets found: {secrets_found}")


def main():
    scanner = GitHubGistScanner()
    scanner.run_scan()


if __name__ == "__main__":
    main()
