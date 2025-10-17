#!/usr/bin/env python3
"""
Dust Agent Scanner using GitGuardian BYOS

This script fetches Dust agent configurations and scans their instructions
for secrets using GitGuardian's BYOS (Bring Your Own Source) functionality.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

import requests
from pygitguardian import GGClient


class DustAgentScanner:
    def __init__(self):
        """
        Initialize the scanner with API credentials from environment variables.
        """
        # Get and validate required environment variables
        env_vars = {
            "DUST_API_KEY": "dust_api_key",
            "DUST_WORKSPACE_ID": "dust_workspace_id",
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
        self.scanned_agents_file = "scanned_agents.json"
        self.scanned_agents = self.load_scanned_agents()
        self.force_rescan = os.getenv(
            "FORCE_RESCAN", "false"
        ).lower() == "true"

    def load_scanned_agents(self) -> Dict:
        """Load previously scanned agents from file."""
        try:
            with open(self.scanned_agents_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_scanned_agents(self):
        """Save scanned agents to file."""
        with open(self.scanned_agents_file, "w") as f:
            json.dump(self.scanned_agents, f, indent=2)

    def get_dust_agents(self) -> Optional[List[Dict]]:
        """Fetch agent configurations from Dust API. Returns None on error."""
        url = (
            f"https://dust.tt/api/v1/w/{self.dust_workspace_id}"
            "/assistant/agent_configurations"
        )
        headers = {"Authorization": f"Bearer {self.dust_api_key}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get("agentConfigurations", [])
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching Dust agents: {e}")
            sys.exit(1)

    def should_scan_agent(self, agent_id: str, version: int) -> bool:
        """Check if agent should be scanned based on ID and version."""
        if self.force_rescan:
            return True
        if agent_id not in self.scanned_agents:
            return True
        return self.scanned_agents[agent_id].get("version", 0) < version

    def scan_agent_instructions(self, agent: Dict) -> Optional[Dict]:
        """Scan agent instructions using GitGuardian BYOS."""
        agent_id, agent_name = agent.get("sId"), agent.get("name", "Unknown")
        instructions = agent.get("instructions", "")

        if not instructions:
            print(
                f"Agent {agent_name} ({agent_id}) has no instructions to scan"
            )
            return None

        print(f"Scanning agent: {agent_name} ({agent_id})")

        try:
            documents = [
                {
                    "document": instructions,
                    "filename": f"dust_agent_{agent_id}_instructions.md",
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
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "scan_result": multi_scan_result.scan_results[0],
                    "scan_timestamp": datetime.now().isoformat(),
                }
            else:
                print(
                    f"Error scanning agent {agent_name}: {multi_scan_result}"
                )
                return None

        except Exception as e:
            print(f"Error scanning agent {agent_name}: {e}")
            return None

    def process_scan_results(self, scan_data: Dict) -> int:
        """
        Process and display scan results. Returns number of secrets found.
        """
        agent_name, scan_result = (
            scan_data["agent_name"],
            scan_data["scan_result"],
        )

        if not (
            hasattr(scan_result, "policy_break_count")
            and scan_result.policy_break_count > 0
        ):
            print(f"✅ No secrets found in {agent_name}")
            return 0

        print(
            f"⚠️  Found {scan_result.policy_break_count}"
            f" potential secret(s) in {agent_name}"
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
        print("🔍 Starting Dust Agent Scanner with GitGuardian BYOS")
        print(f"Source UUID: {self.source_uuid}")
        if self.force_rescan:
            print(
                "🔄 Force rescan mode:"
                " Will rescan all agents regardless of version"
            )
        print()

        if not self.gg_client.health_check().success:
            print(
                "❌ GitGuardian API health check failed."
                " Please check your API key."
            )
            sys.exit(1)

        print("📥 Fetching Dust agents...")
        agents = self.get_dust_agents()
        if agents is None:
            print(
                "❌ Failed to fetch agents."
                " Please check your Dust API key and workspace ID."
            )
            return
        if not agents:
            print("ℹ️  No agents found in your Dust workspace.")
            return

        print(f"Found {len(agents)} agent(s)\n")

        scanned_count = skipped_count = secrets_found = 0

        for agent in agents:
            agent_id, agent_name, version = (
                agent.get("sId"),
                agent.get("name", "Unknown"),
                agent.get("version", 0),
            )

            if not self.should_scan_agent(agent_id, version):
                skipped_count += 1
                continue

            scan_data = self.scan_agent_instructions(agent)
            if scan_data:
                secrets_found += self.process_scan_results(scan_data)
                self.scanned_agents[agent_id] = {
                    "name": agent_name,
                    "version": version,
                    "last_scanned": datetime.now().isoformat(),
                    "source_uuid": self.source_uuid,
                }
                scanned_count += 1
            print()

        self.save_scanned_agents()

        print("📊 Scan Summary:")
        print(f"  • Agents scanned: {scanned_count}")
        print(f"  • Agents skipped: {skipped_count}")
        print(f"  • Total agents: {len(agents)}")
        print(f"  • Secrets found: {secrets_found}")

        return secrets_found


def main():
    """Main entry point."""
    scanner = DustAgentScanner()
    secrets_found = scanner.run_scan()
    sys.exit(2 if secrets_found else 0)


if __name__ == "__main__":
    main()
