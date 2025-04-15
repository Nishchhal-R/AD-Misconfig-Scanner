import subprocess
import re
import os


class ldapScanner:
    def __init__(self):
        self.findings = []

    def check_enable_trusted_for_delegation(self):
        """Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC Only)."""
        
        # Export security policy settings to a text file
        command_export = ['powershell', '-Command', 'secedit /export /cfg C:\\ldap_policy.txt']
        subprocess.run(command_export, capture_output=True, text=True, shell=False)

        # Read and search for the delegation setting
        command_check = ['powershell', '-Command', 'Select-String "SeEnableDelegationPrivilege" C:\\ldap_policy.txt']
        result = subprocess.run(command_check, capture_output=True, text=True, shell=False)

        # Debugging: Print raw output for verification
        #print("Raw Output:\n", result.stdout, result.stderr)

        # Remove exported file after checking
        if os.path.exists("C:\\ldap_policy.txt"):
            os.remove("C:\\ldap_policy.txt")

        # Extract the delegation privilege setting
        match = re.search(r"SeEnableDelegationPrivilege\s+=\s+(.+)", result.stdout)

        if match:
            delegation_value = match.group(1).strip()

            # CIS Recommended Value: Administrators
            if delegation_value.lower() != "administrators":
                self.findings.append({
                    "id": "2.2.28",
                    "description": "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'",
                    "status": "Failed",
                    "mitre_attack": "T1550.001 (Pass-the-Ticket Attack via Unconstrained Delegation)",
                    "severity": "High",
                    "current_value": delegation_value,
                    "recommendation": "Set 'Enable computer and user accounts to be trusted for delegation' to 'Administrators' using Group Policy."
                })
            else:
                self.findings.append({
                    "id": "2.2.28",
                    "description": "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'",
                    "status": "Passed",
                    "mitre_attack": "T1550.001 (Pass-the-Ticket Attack via Unconstrained Delegation)",
                    "severity": "None",
                    "current_value": delegation_value,
                    "recommendation": "No action needed."
                })
        else:
            self.findings.append({
                "id": "2.2.28",
                "description": "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'",
                "status": "Failed",
                "mitre_attack": "T1550.001 (Pass-the-Ticket Attack via Unconstrained Delegation)",
                "severity": "High",
                "current_value": "Not Found",
                "recommendation": "Set 'Enable computer and user accounts to be trusted for delegation' to 'Administrators' using Group Policy."
            })


    def get_checks(self):
        """Return a list of all checks in this module."""
        return [
            (self.check_enable_trusted_for_delegation,"LDAP","Check Trust Delegation"),
        ]

    def run_all_checks(self):
        """Run all ldap-related checks."""
        self.check_enable_trusted_for_delegation()

        return self.findings
