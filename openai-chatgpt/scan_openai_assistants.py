#!/usr/bin/env python3
"""
OpenAI Assistant Scanner with GitGuardian BYOS

Scans OpenAI GPT Assistant instructions for secrets and sensitive information
using GitGuardian's BYOS (Bring Your Own Source) functionality.

Tracks scanned assistants by version to avoid rescanning unchanged assistants.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

import requests
from pygitguardian import GGClient


class OpenAIAssistantScanner:
    def __init__(self):
        """
        Initialize the scanner with API credentials from environment variables.
        """
        env_vars = {
            "OPENAI_API_KEY": "openai_api_key",
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

        self.gg_client = GGClient(api_key=self.gitguardian_api_key)
        self.scanned_assistants_file = "scanned_assistants.json"
        self.scanned_assistants = self.load_scanned_assistants()
        self.force_rescan = os.getenv(
            "FORCE_RESCAN", "false"
        ).lower() == "true"

    def load_scanned_assistants(self) -> Dict:
        """Load previously scanned assistants from JSON file."""
        try:
            with open(self.scanned_assistants_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_scanned_assistants(self):
        """Save scanned assistants to JSON file."""
        with open(self.scanned_assistants_file, "w") as f:
            json.dump(self.scanned_assistants, f, indent=2)

    def should_scan_assistant(
        self, assistant_id: str, modified_at: int
    ) -> bool:
        """
        Check if assistant should be scanned based on last modified timestamp.
        """
        if self.force_rescan:
            return True

        if assistant_id not in self.scanned_assistants:
            return True

        return (
            self.scanned_assistants[assistant_id].get("modified_at", 0)
            != modified_at
        )

    def get_openai_assistants(self) -> Optional[List[Dict]]:
        """
        Fetch assistant configurations from OpenAI API. Returns None on error.
        """
        url = "https://api.openai.com/v1/assistants"
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "OpenAI-Beta": "assistants=v2",
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get("data", [])
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching OpenAI assistants: {e}")
            sys.exit(1)

    def scan_assistant_instructions(self, assistant: Dict) -> Optional[Dict]:
        """Scan assistant instructions using GitGuardian BYOS."""
        assistant_id = assistant.get("id")
        assistant_name = assistant.get("name", "Unnamed Assistant")
        instructions = assistant.get("instructions", "")

        if not instructions:
            print(
                f"Assistant {assistant_name} ({assistant_id})"
                " has no instructions to scan"
            )
            return None

        print(f"Scanning assistant: {assistant_name} ({assistant_id})")

        try:
            documents = [
                {
                    "document": instructions,
                    "filename": (
                        f"openai_assistant_{assistant_id}_instructions.md"
                    ),
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
                    "assistant_id": assistant_id,
                    "assistant_name": assistant_name,
                    "scan_result": multi_scan_result.scan_results[0],
                    "scan_timestamp": datetime.now().isoformat(),
                }
            else:
                print(
                    f"Error scanning assistant {assistant_name}:"
                    f" {multi_scan_result}"
                )
                return None

        except Exception as e:
            print(f"Error scanning assistant {assistant_name}: {e}")
            sys.exit(1)

    def process_scan_results(self, scan_data: Dict) -> int:
        """
        Process and display scan results. Returns number of secrets found.
        """
        assistant_name = scan_data["assistant_name"]
        scan_result = scan_data["scan_result"]

        if not (
            hasattr(scan_result, "policy_break_count")
            and scan_result.policy_break_count > 0
        ):
            print(f"✅ No secrets found in {assistant_name}")
            return 0

        print(
            f"⚠️  Found {scan_result.policy_break_count}"
            f" secret(s) in {assistant_name}"
        )
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
        print("🤖 Starting OpenAI Assistant Scanner with GitGuardian BYOS")
        print(f"Source UUID: {self.source_uuid}")
        if self.force_rescan:
            print(
                "🔄 Force rescan mode: Will rescan all assistants"
                " regardless of modification time"
            )
        print()

        if not self.gg_client.health_check().success:
            print(
                "❌ GitGuardian API health check failed."
                "Please check your API key."
            )
            sys.exit(1)

        print("📥 Fetching OpenAI assistants...")
        assistants = self.get_openai_assistants()
        if assistants is None:
            print(
                "❌ Failed to fetch assistants."
                " Please check your OpenAI API key and connection."
            )
            return
        if not assistants:
            print("ℹ️  No assistants found in your OpenAI account.")
            return

        print(f"Found {len(assistants)} assistant(s)\n")

        scanned_count = skipped_count = no_instructions_count = (
            secrets_found
        ) = 0

        for assistant in assistants:
            assistant_id = assistant.get("id")
            assistant_name = assistant.get("name", "Unnamed Assistant")
            modified_at = assistant.get(
                "modified_at", assistant.get("created_at", 0)
            )

            if not self.should_scan_assistant(assistant_id, modified_at):
                skipped_count += 1
                continue

            scan_data = self.scan_assistant_instructions(assistant)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_assistants[assistant_id] = {
                    "name": assistant_name,
                    "modified_at": modified_at,
                    "last_scanned": datetime.now().isoformat(),
                    "source_uuid": self.source_uuid,
                }
                scanned_count += 1
            else:
                # Assistant has no instructions to scan
                no_instructions_count += 1
                self.scanned_assistants[assistant_id] = {
                    "name": assistant_name,
                    "modified_at": modified_at,
                    "last_scanned": datetime.now().isoformat(),
                    "source_uuid": self.source_uuid,
                    "no_instructions": True,
                }
            print()

        self.save_scanned_assistants()

        print("📊 Scan Summary:")
        print(f"  • Assistants scanned: {scanned_count}")
        print(f"  • Assistants skipped: {skipped_count}")
        print(f"  • No instructions: {no_instructions_count}")
        print(f"  • Total assistants: {len(assistants)}")
        print(f"  • Secrets found: {secrets_found}")

        return secrets_found


def main():
    scanner = OpenAIAssistantScanner()
    secrets_found = scanner.run_scan()
    sys.exit(2 if secrets_found else 0)


if __name__ == "__main__":
    main()
