#!/usr/bin/env python3
"""
GitHub Gist Scanner (User/Authenticated) with GitGuardian BYOS

Scans GitHub Gists for a specific user
or authenticated user's gists for secrets
and sensitive information using
GitGuardian's BYOS (Bring Your Own Source) functionality.

Tracks scanned gists by update timestamp to avoid rescanning unchanged gists.
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests
from pygitguardian import GGClient


class GitHubGistScanner:
    def __init__(self):
        """
        Initialize the scanner with API credentials from environment variables.
        """
        env_vars = {
            "GITHUB_API_KEY": "github_api_key",
            "GITGUARDIAN_API_KEY": "gitguardian_api_key",
            "SOURCE_UUID": "source_uuid",
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
            print(*[f"  - {var}" for var in missing], sep="\n")
            print(f"\nAll required: {', '.join(env_vars.keys())}")
            sys.exit(1)

        self.github_usernames = self._parse_usernames(
            os.getenv("GITHUB_USERNAME", "")
        )
        self.github_orgs = self._parse_organizations(
            os.getenv("GITHUB_ORGS", "")
        )
        self.gg_client = GGClient(api_key=self.gitguardian_api_key)
        self.scanned_gists_file = "scanned_gists.json"
        self.scanned_gists = self.load_scanned_gists()
        self.force_rescan = os.getenv(
            "FORCE_RESCAN", "false"
        ).lower() == "true"

    def _parse_usernames(self, users_string: str) -> List[str]:
        """Parse comma-separated usernames from environment variable."""
        if not users_string.strip():
            return []
        return [
            user.strip() for user in users_string.split(",") if user.strip()
        ]

    def _parse_organizations(self, orgs_string: str) -> List[str]:
        """
        Parse comma-separated organization names from environment variable.
        """
        if not orgs_string.strip():
            return []
        return [org.strip() for org in orgs_string.split(",") if org.strip()]

    def load_scanned_gists(self) -> Dict:
        """Load previously scanned gists from JSON file."""
        try:
            with open(self.scanned_gists_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_scanned_gists(self):
        """Save scanned gists to JSON file."""
        with open(self.scanned_gists_file, "w") as f:
            json.dump(self.scanned_gists, f, indent=2)

    def should_scan_gist(self, gist_id: str, updated_at: str) -> bool:
        """Check if gist should be scanned based on update timestamp."""
        if self.force_rescan:
            return True

        if gist_id not in self.scanned_gists:
            return True

        return self.scanned_gists[gist_id].get("updated_at") != updated_at

    def get_organization_members(self, org_name: str) -> Optional[List[str]]:
        """Fetch all public members of a GitHub organization."""
        url = f"https://api.github.com/orgs/{org_name}/members"
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        print(f"📥 Fetching members of organization: {org_name}")
        all_members = []
        page = 1
        per_page = 100  # GitHub API max is 100 per page

        while True:
            try:
                params = {"page": page, "per_page": per_page}
                response = requests.get(url, headers=headers, params=params)

                if response.status_code == 404:
                    print(
                        f"❌ Organization '{org_name}'"
                        " not found or not accessible"
                    )
                    return sys.exit(1)
                elif response.status_code == 403:
                    print(
                        f"❌ Access denied to organization '{org_name}'"
                        " (private org or insufficient permissions)"
                    )
                    return sys.exit(1)

                members = response.json()
                if not members:
                    break

                member_logins = [member["login"] for member in members]
                all_members.extend(member_logins)

                print(
                    f"Fetched page {page}: {len(member_logins)} members"
                    f" (total: {len(all_members)})"
                )
                page += 1

                # Stop if GitHub returned fewer results than requested
                # (last page)
                if len(members) < per_page:
                    break

                # Small delay to be respectful to the API
                time.sleep(0.1)

            except requests.exceptions.RequestException as e:
                print(
                    "❌ Error fetching members"
                    f" for organization {org_name}: {e}"
                )
                return sys.exit(1)

        print(
            f"✅ Found {len(all_members)} members in organization '{org_name}'"
        )
        return all_members

    def get_all_target_users(self) -> List[str]:
        """Get all target users to scan based on configuration."""
        target_users = []

        # Specific usernames specified
        if self.github_usernames:
            target_users.extend(self.github_usernames)

        # Organizations specified
        if self.github_orgs:
            for org_name in self.github_orgs:
                members = self.get_organization_members(org_name)
                if members:
                    target_users.extend(members)

        # Remove duplicates while preserving order
        seen = set()
        unique_users = []
        for user in target_users:
            if user not in seen:
                seen.add(user)
                unique_users.append(user)

        return unique_users

    def get_user_gists(self, username: str) -> Optional[List[Dict]]:
        """Fetch gists for a specific user."""
        url = f"https://api.github.com/users/{username}/gists"
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            all_gists = []
            page = 1
            per_page = 100

            while True:
                params = {"page": page, "per_page": per_page}
                response = requests.get(url, headers=headers, params=params)

                if response.status_code == 404:
                    print(f"❌ User '{username}' not found")
                    sys.exit(1)

                response.raise_for_status()

                gists = response.json()
                if not gists:
                    break

                all_gists.extend(gists)
                page += 1

                # GitHub API returns fewer results than per_page
                # when on last page
                if len(gists) < per_page:
                    break

                # Small delay to be respectful to the API
                time.sleep(0.1)

            return all_gists

        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching gists for user {username}: {e}")
            sys.exit(1)

    def get_authenticated_user_gists(self) -> Optional[List[Dict]]:
        """Fetch gists for the authenticated user (including private gists)."""
        url = "https://api.github.com/gists"
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
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
                page += 1

                # GitHub API returns fewer results than per_page
                # when on last page
                if len(gists) < per_page:
                    break

            return all_gists

        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching authenticated user gists: {e}")
            sys.exit(1)

    def get_github_gists(self) -> Optional[List[Dict]]:
        """
        Fetch gists from GitHub API based on configuration.
        Returns None on error.
        """
        all_gists = []

        # If no specific users or orgs specified, scan authenticated user
        if not self.github_usernames and not self.github_orgs:
            print("📥 Fetching gists for authenticated user...")
            gists = self.get_authenticated_user_gists()
            if gists is None:
                return None
            all_gists.extend(gists)
            print(f"Found {len(gists)} gist(s) for authenticated user")
        else:
            # Scan specific users and/or organization members
            target_users = self.get_all_target_users()
            if not target_users:
                print("❌ No target users found to scan")
                return []

            print(f"📥 Fetching gists for {len(target_users)} user(s)...")

            for i, username in enumerate(target_users, 1):
                print(
                    f"[{i}/{len(target_users)}]"
                    f" Fetching gists for user: {username}"
                )
                user_gists = self.get_user_gists(username)
                if user_gists is not None:
                    # Add username to each gist for tracking
                    for gist in user_gists:
                        gist["_scanned_user"] = username
                    all_gists.extend(user_gists)
                    if user_gists:
                        print(f"  └─ Found {len(user_gists)} gist(s)")

        return all_gists

    def get_gist_details(self, gist_id: str) -> Optional[Dict]:
        """Fetch detailed gist information including file contents."""
        url = f"https://api.github.com/gists/{gist_id}"
        headers = {
            "Authorization": f"Bearer {self.github_api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
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
        files = gist_details.get("files", {})

        if not files:
            return ""

        content_parts = []
        for filename, file_info in files.items():
            file_content = file_info.get("content", "")
            if file_content:
                content_parts.append(f"# File: {filename}\n{file_content}")

        return "\n\n---\n\n".join(content_parts)

    def scan_gist_content(self, gist: Dict) -> Optional[Dict]:
        """Scan gist content using GitGuardian BYOS."""
        gist_id = gist.get("id")
        gist_description = gist.get("description", "No description")

        # Fetch detailed gist information with file contents
        gist_details = self.get_gist_details(gist_id)
        if not gist_details:
            return None

        content = self.get_gist_content(gist_details)

        if not content.strip():
            print(
                f"Gist {gist_id} ({gist_description}) has no content to scan"
            )
            return None

        print(f"Scanning gist: {gist_description or gist_id}")

        try:
            # Extract username from scanned_user or gist owner
            username = gist.get("_scanned_user", "unknown")
            if not username or username == "authenticated user":
                # Try to extract from URL as fallback
                gist_url = gist.get("html_url", "")
                if "/gist.github.com/" in gist_url:
                    username = (
                        gist_url.split("/gist.github.com/")[1].split("/")[0]
                        if "/" in gist_url.split("/gist.github.com/")[1]
                        else "unknown"
                    )
                else:
                    username = "authenticated_user"

            documents = [
                {
                    "document": content,
                    "filename": f"github_gist_{username}_{gist_id}.md",
                }
            ]
            multi_scan_result = self.gg_client.scan_and_create_incidents(
                documents, source_uuid=self.source_uuid
            )

            if (
                hasattr(multi_scan_result, "scan_results")
                and multi_scan_result.scan_results
            ):
                return {
                    "gist_id": gist_id,
                    "gist_description": gist_description,
                    "gist_url": gist_details.get(
                        "html_url", gist.get("html_url", "")
                    ),
                    "file_count": len(gist_details.get("files", {})),
                    "scan_result": multi_scan_result.scan_results[0],
                    "scan_timestamp": datetime.now().isoformat(),
                }
            else:
                print(f"Error scanning gist {gist_id}: {multi_scan_result}")
                return None

        except Exception as e:
            print(f"Error scanning gist {gist_id}: {e}")
            return None

    def process_scan_results(self, scan_data: Dict) -> int:
        """
        Process and display scan results. Returns number of secrets found.
        """
        gist_description = scan_data["gist_description"]
        gist_url = scan_data["gist_url"]
        scan_result = scan_data["scan_result"]

        if not (
            hasattr(scan_result, "policy_break_count")
            and scan_result.policy_break_count > 0
        ):
            print(f"✅ No secrets found in gist: {gist_description}")
            return 0

        print(
            f"⚠️  Found {scan_result.policy_break_count}"
            f" secret(s) in gist: {gist_description}"
        )
        print(f"🔗 URL: {gist_url}")

        for i, policy_break in enumerate(scan_result.policy_breaks, 1):
            print(f"  {i}. {policy_break.break_type}")
            print(f"     Validity: {policy_break.validity}")
            print(f"     Detector: {policy_break.detector_name}")

            # Show line numbers from matches
            if hasattr(policy_break, "matches") and policy_break.matches:
                lines = sorted(
                    {
                        match.line_start
                        for match in policy_break.matches
                        if hasattr(match, "line_start")
                    }
                )
                if lines:
                    location = (
                        f"Line {lines[0]}"
                        if len(lines) == 1
                        else f"Lines {', '.join(map(str, lines))}"
                    )
                    print(f"     Location: {location}")

            # Show documentation link
            if (
                hasattr(policy_break, "documentation_url")
                and policy_break.documentation_url
            ):
                print(f"     Info: {policy_break.documentation_url}")
            print()

        return scan_result.policy_break_count

    def run_scan(self):
        """Main scanning workflow."""
        # Determine scan target description
        scan_targets = []
        if self.github_usernames:
            if len(self.github_usernames) == 1:
                scan_targets.append(f"user '{self.github_usernames[0]}'")
            else:
                scan_targets.append(
                    f"{len(self.github_usernames)} users:"
                    f" {', '.join(self.github_usernames)}"
                )
        if self.github_orgs:
            scan_targets.append(
                f"{len(self.github_orgs)} organization(s):"
                f" {', '.join(self.github_orgs)}"
            )

        if scan_targets:
            scan_target = " and ".join(scan_targets)
        else:
            scan_target = "authenticated user"

        print(f"📋 Starting GitHub Gist Scanner for {scan_target}")
        print(f"Source UUID: {self.source_uuid}")
        if self.force_rescan:
            print(
                "🔄 Force rescan mode: "
                "Will rescan all gists regardless of update timestamp"
            )
        print()

        if not self.gg_client.health_check().success:
            print(
                "❌ GitGuardian API health check failed."
                " Please check your API key."
            )
            sys.exit(1)

        gists = self.get_github_gists()
        if gists is None:
            print(
                "❌ Failed to fetch gists."
                " Please check your GitHub API key and permissions."
            )
            return
        if not gists:
            print("ℹ️  No gists found for specified target(s).")
            return

        print(f"Found {len(gists)} gist(s) total\n")

        scanned_count = skipped_count = no_content_count = secrets_found = 0

        for gist in gists:
            gist_id = gist.get("id")
            updated_at = gist.get("updated_at")
            gist_description = gist.get("description", "No description")
            scanned_user = gist.get("_scanned_user", "authenticated user")

            if not self.should_scan_gist(gist_id, updated_at):
                skipped_count += 1
                continue

            scan_data = self.scan_gist_content(gist)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_gists[gist_id] = {
                    "description": scan_data["gist_description"],
                    "url": scan_data["gist_url"],
                    "file_count": scan_data["file_count"],
                    "scanned_user": scanned_user,
                    "github_username": scanned_user,
                    "updated_at": updated_at,
                    "last_scanned": datetime.now().isoformat(),
                    "source_uuid": self.source_uuid,
                }
                scanned_count += 1
            else:
                # Gist has no content to scan
                no_content_count += 1
                self.scanned_gists[gist_id] = {
                    "description": gist_description,
                    "url": gist.get("html_url", ""),
                    "file_count": len(gist.get("files", {})),
                    "scanned_user": scanned_user,
                    "github_username": scanned_user,
                    "updated_at": updated_at,
                    "last_scanned": datetime.now().isoformat(),
                    "source_uuid": self.source_uuid,
                    "no_content": True,
                }
            print()

        self.save_scanned_gists()

        print("📊 Scan Summary:")
        print(f"  • Gists scanned: {scanned_count}")
        print(f"  • Gists skipped: {skipped_count}")
        print(f"  • No content: {no_content_count}")
        print(f"  • Total gists: {len(gists)}")
        print(f"  • Secrets found: {secrets_found}")

        return secrets_found


def main():
    scanner = GitHubGistScanner()
    secrets_found = scanner.run_scan()
    sys.exit(2 if secrets_found else 0)


if __name__ == "__main__":
    main()
