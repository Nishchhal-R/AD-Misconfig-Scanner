import subprocess
import yaml

class CustomScanner:
    def __init__(self):
        self.findings = []
        with open("config/custom_rules.yaml", "r") as file:
            self.custom_rules = yaml.safe_load(file)

    def run_custom_checks(self):
        """Run all user-defined security checks."""
        for check in self.custom_rules:
            command = check["command"]
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            output = result.stdout.strip()

            if output != check["expected_output"]:
                self.findings.append({
                    "id": check["id"],
                    "description": check["name"],
                    "status": "Failed",
                    "mitre_attack": check.get("mitre_attack", "N/A"),
                    "severity": check["severity"],
                    "recommendation": check["recommendation"]
                })

    
    def run_all_checks(self):
        self.run_custom_checks()
        return self.findings
