import subprocess
import re

class NTLMScanner:
	def __init__(self):
		self.findings = []



	def check_no_lm_hash_storage(self):
	    """Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'."""
	    command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name NoLMHash']
	    result = subprocess.run(command, capture_output=True, text=True, shell=False)

	    # Debugging: Print raw output for verification
	    #print("Raw Output:\n", result.stdout, result.stderr)

	    # Extract NoLMHash value using regex
	    match = re.search(r"NoLmHash\s+:\s+(\d+)", result.stdout)

	    if match:
	        lm_hash_value = int(match.group(1))  # Convert extracted value to integer

	        # CIS Recommended Value: 1 (Enabled)
	        if lm_hash_value != 1:
	            self.findings.append({
	                "id": "2.3.11.5",
	                "description": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'",
	                "status": "Failed",
	                "mitre_attack": "T1075 (Pass-the-Hash)",
	                "severity": "High",
	                "current_value": lm_hash_value,
	                "recommendation": "Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' (1) using Group Policy or registry settings."
	            })
	        else:
	            self.findings.append({
	                "id": "2.3.11.5",
	                "description": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'",
	                "status": "Passed",
	                "mitre_attack": "T1075 (Pass-the-Hash)",
	                "severity": "None",
	                "current_value": lm_hash_value,
	                "recommendation": "No action needed."
	            })
	    else:
	        self.findings.append({
	            "id": "2.3.11.5",
	            "description": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'",
	            "status": "Failed",
	            "mitre_attack": "T1075 (Pass-the-Hash)",
	            "severity": "High",
	            "current_value": "Not Found",
	            "recommendation": "Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' (1) using Group Policy or registry settings."
	        })



	def check_lan_manager_authentication_level(self):
	    """Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'."""
	    command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name LmCompatibilityLevel']
	    result = subprocess.run(command, capture_output=True, text=True, shell=False)

	    # Debugging: Print raw output for verification
	    #print("Raw Output:\n", result.stdout, result.stderr)

	    # Check if the registry key exists
	    if "Property LmCompatibilityLevel does not exist" in result.stderr:
	        self.findings.append({
	            "id": "2.3.11.7",
	            "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay)",
	            "severity": "High",
	            "current_value": "Not Configured",
	            "recommendation": "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (5) using Group Policy."
	        })
	        return

	    # Extract LmCompatibilityLevel setting
	    match = re.search(r"LmCompatibilityLevel\s+:\s+(\d+)", result.stdout)

	    if match:
	        lm_compatibility_value = int(match.group(1))

	        # CIS Recommended Value: 5 (Send NTLMv2 response only. Refuse LM & NTLM)
	        if lm_compatibility_value != 5:
	            self.findings.append({
	                "id": "2.3.11.7",
	                "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
	                "status": "Failed",
	                "mitre_attack": "T1557.001 (NTLM Relay)",
	                "severity": "High",
	                "current_value": lm_compatibility_value,
	                "recommendation": "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (5) using Group Policy."
	            })
	        else:
	            self.findings.append({
	                "id": "2.3.11.7",
	                "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
	                "status": "Passed",
	                "mitre_attack": "T1557.001 (NTLM Relay)",
	                "severity": "None",
	                "current_value": lm_compatibility_value,
	                "recommendation": "No action needed."
	            })
	    else:
	        self.findings.append({
	            "id": "2.3.11.7",
	            "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay)",
	            "severity": "High",
	            "current_value": "Not Found",
	            "recommendation": "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (5) using Group Policy."
	        })


	def check_ntlm_minimum_session_security_clients(self):
	    """Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set correctly."""
	    command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name NtlmMinClientSec']
	    result = subprocess.run(command, capture_output=True, text=True, shell=False)

	    # Debugging: Print raw output for verification
	    #print("Raw Output:\n", result.stdout, result.stderr)

	    # Check if the registry key exists
	    if "Cannot find path" in result.stderr or "Property NtlmMinClientSec does not exist" in result.stderr:
	        self.findings.append({
	            "id": "2.3.11.9",
	            "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set correctly",
	            "status": "Failed",
	            "mitre_attack": "T1557.002 (NTLM Session Hijacking)",
	            "severity": "High",
	            "current_value": "Not Configured",
	            "recommendation": "Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security, Require 128-bit encryption' (0x20080000) using Group Policy."
	        })
	        return

	    # Extract NtlmMinClientSec setting (case-sensitive fix)
	    match = re.search(r"NtlmMinClientSec\s+:\s+(\d+)", result.stdout)

	    if match:
	        ntlm_min_client_sec = int(match.group(1))

	        # CIS Recommended Value: 0x20080000 (537395200 in decimal)
	        if ntlm_min_client_sec != 537395200:
	            self.findings.append({
	                "id": "2.3.11.9",
	                "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set correctly",
	                "status": "Failed",
	                "mitre_attack": "T1557.002 (NTLM Session Hijacking)",
	                "severity": "High",
	                "current_value": ntlm_min_client_sec,
	                "recommendation": "Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security, Require 128-bit encryption' (0x20080000) using Group Policy."
	            })
	        else:
	            self.findings.append({
	                "id": "2.3.11.9",
	                "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set correctly",
	                "status": "Passed",
	                "mitre_attack": "T1557.002 (NTLM Session Hijacking)",
	                "severity": "None",
	                "current_value": ntlm_min_client_sec,
	                "recommendation": "No action needed."
	            })
	    else:
	        self.findings.append({
	            "id": "2.3.11.9",
	            "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set correctly",
	            "status": "Failed",
	            "mitre_attack": "T1557.002 (NTLM Session Hijacking)",
	            "severity": "High",
	            "current_value": "Not Found",
	            "recommendation": "Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security, Require 128-bit encryption' (0x20080000) using Group Policy."
	        })



	def check_ntlm_audit_incoming_traffic(self):
	    """Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'."""
	    command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name AuditReceivingNTLMTraffic']
	    result = subprocess.run(command, capture_output=True, text=True, shell=False)

	    # Debugging: Print raw output for verification
	    #print("Raw Output:\n", result.stdout, result.stderr)

	    # Check if the registry key exists
	    if "Cannot find path" in result.stderr or "Property AuditReceivingNTLMTraffic does not exist" in result.stderr:
	        self.findings.append({
	            "id": "2.3.11.11",
	            "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay Attack Detection)",
	            "severity": "High",
	            "current_value": "Not Configured",
	            "recommendation": "Set 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' to 'Enable auditing for all accounts' (2) using Group Policy."
	        })
	        return

	    # Extract AuditReceivingNTLMTraffic setting
	    match = re.search(r"AuditReceivingNTLMTraffic\s+:\s+(\d+)", result.stdout)

	    if match:
	        ntlm_audit_value = int(match.group(1))

	        # CIS Recommended Value: 2 (Enable auditing for all accounts)
	        if ntlm_audit_value != 2:
	            self.findings.append({
	                "id": "2.3.11.11",
	                "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
	                "status": "Failed",
	                "mitre_attack": "T1557.001 (NTLM Relay Attack Detection)",
	                "severity": "High",
	                "current_value": ntlm_audit_value,
	                "recommendation": "Set 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' to 'Enable auditing for all accounts' (2) using Group Policy."
	            })
	        else:
	            self.findings.append({
	                "id": "2.3.11.11",
	                "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
	                "status": "Passed",
	                "mitre_attack": "T1557.001 (NTLM Relay Attack Detection)",
	                "severity": "None",
	                "current_value": ntlm_audit_value,
	                "recommendation": "No action needed."
	            })
	    else:
	        self.findings.append({
	            "id": "2.3.11.11",
	            "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay Attack Detection)",
	            "severity": "High",
	            "current_value": "Not Found",
	            "recommendation": "Set 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' to 'Enable auditing for all accounts' (2) using Group Policy."
	        })


	def check_ntlm_restrict_outgoing_traffic(self):
	    """Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher."""
	    command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name RestrictSendingNTLMTraffic']
	    result = subprocess.run(command, capture_output=True, text=True, shell=False)

	    # Debugging: Print raw output for verification
	    #print("Raw Output:\n", result.stdout, result.stderr)

	    # Check if the registry key exists
	    if "Cannot find path" in result.stderr or "Property RestrictSendingNTLMTraffic does not exist" in result.stderr:
	        self.findings.append({
	            "id": "2.3.11.13",
	            "description": "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay Attack Prevention)",
	            "severity": "High",
	            "current_value": "Not Configured",
	            "recommendation": "Set 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' to 'Audit all' (2) or 'Deny all' (3) using Group Policy."
	        })
	        return

	    # Extract RestrictSendingNTLMTraffic setting
	    match = re.search(r"RestrictSendingNTLMTraffic\s+:\s+(\d+)", result.stdout)

	    if match:
	        restrict_ntlm_value = int(match.group(1))

	        # CIS Recommended Values: 2 (Audit all) or 3 (Deny all)
	        if restrict_ntlm_value not in [2, 3]:
	            self.findings.append({
	                "id": "2.3.11.13",
	                "description": "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher",
	                "status": "Failed",
	                "mitre_attack": "T1557.001 (NTLM Relay Attack Prevention)",
	                "severity": "High",
	                "current_value": restrict_ntlm_value,
	                "recommendation": "Set 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' to 'Audit all' (2) or 'Deny all' (3) using Group Policy."
	            })
	        else:
	            self.findings.append({
	                "id": "2.3.11.13",
	                "description": "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher",
	                "status": "Passed",
	                "mitre_attack": "T1557.001 (NTLM Relay Attack Prevention)",
	                "severity": "None",
	                "current_value": restrict_ntlm_value,
	                "recommendation": "No action needed."
	            })
	    else:
	        self.findings.append({
	            "id": "2.3.11.13",
	            "description": "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher",
	            "status": "Failed",
	            "mitre_attack": "T1557.001 (NTLM Relay Attack Prevention)",
	            "severity": "High",
	            "current_value": "Not Found",
	            "recommendation": "Set 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' to 'Audit all' (2) or 'Deny all' (3) using Group Policy."
	        })
	
	def get_checks(self):
		"""Return a list of all checks in this module."""
		return [
            (self.check_no_lm_hash_storage, "NTLM", "Audit NTLM Hash storage"),
            (self.check_lan_manager_authentication_level, "NTLM", "Audit NTLM LAN authentication"),
            (self.check_ntlm_minimum_session_security_clients, "NTLM", "Audit NTLM Hash storage"),
            (self.check_ntlm_audit_incoming_traffic,"NTLM","Audit NTLM incoming traffic") ,
            (self.check_ntlm_restrict_outgoing_traffic,"NTLM","Audit NTLM outgoing traffic"),
        ]

	def run_all_checks(self):
		"""Run all NTLM-related checks."""
		self.check_no_lm_hash_storage()
		self.check_lan_manager_authentication_level()
		self.check_ntlm_minimum_session_security_clients()
		self.check_ntlm_audit_incoming_traffic()
		self.check_ntlm_restrict_outgoing_traffic()

		return self.findings
