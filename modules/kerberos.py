import subprocess
import re

class KerberosScanner:
    def __init__(self):
        self.findings = []

    def check_kerberos_auth_service_audit(self):
        """Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'."""
        command = ['powershell', '-Command', 'auditpol /get /subcategory:"Kerberos Authentication Service"']
        result = subprocess.run(command, capture_output=True, text=True, shell=False)

        # Debugging: Print raw output for verification
        #print("Raw Output:\n", result.stdout)

        # Extracting the actual setting using regex
        match = re.search(r"Kerberos Authentication Service\s+([A-Za-z\s]+)", result.stdout)
        if match:
            current_value = match.group(1).strip()
            if current_value != "Success":
                self.findings.append({
                    "id": "17.1.2",
                    "description": "Ensure 'Audit Kerberos Authentication Service' is set to 'Success'",
                    "status": "Failed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "High",
                    "current_value": current_value,
                    "recommendation": "Set 'Audit Kerberos Authentication Service' to 'Success and Failure' using Group Policy or auditpol."
                })
            else:
                self.findings.append({
                    "id": "17.1.2",
                    "description": "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'",
                    "status": "Passed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "None",
                    "current_value": current_value,
                    "recommendation": "No action needed."
                })
        else:
            self.findings.append({
                "id": "17.1.2",
                "description": "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'",
                "status": "Failed",
                "mitre_attack": "T1558.003 (Kerberoasting)",
                "severity": "High",
                "current_value": "Not Found",
                "recommendation": "Set 'Audit Kerberos Authentication Service' to 'Success and Failure' using Group Policy or auditpol."
            })

    def check_kerberos_service_ticket_audit(self):
        """Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'."""
        command = ['powershell', '-Command', 'auditpol /get /subcategory:"Kerberos Service Ticket Operations"']
        result = subprocess.run(command, capture_output=True, text=True, shell=False)

        # Debugging: Print raw output for verification
        #print("Raw Output:\n", result.stdout)

        # Extract the audit setting using regex
        match = re.search(r"Kerberos Service Ticket Operations\s+([A-Za-z\s]+)", result.stdout)
        if match:
            current_value = match.group(1).strip()
            if current_value != "Success":
                self.findings.append({
                    "id": "17.1.3",
                    "description": "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'",
                    "status": "Failed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "High",
                    "current_value": current_value,
                    "recommendation": "Set 'Audit Kerberos Service Ticket Operations' to 'Success and Failure' using Group Policy or auditpol."
                })
            else:
                self.findings.append({
                    "id": "17.1.3",
                    "description": "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'",
                    "status": "Passed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "None",
                    "current_value": current_value,
                    "recommendation": "No action needed."
                })
        else:
            self.findings.append({
                "id": "17.1.3",
                "description": "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'",
                "status": "Failed",
                "mitre_attack": "T1558.003 (Kerberoasting)",
                "severity": "High",
                "current_value": "Not Found",
                "recommendation": "Set 'Audit Kerberos Service Ticket Operations' to 'Success and Failure' using Group Policy or auditpol."
            })

    def check_kerberos_encryption_types(self):
        """Ensure 'Network security: Configure encryption types allowed for Kerberos' is set correctly."""
        command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters" -Name SupportedEncryptionTypes']
        result = subprocess.run(command, capture_output=True, text=True, shell=False)
    
        # Debugging: Print raw output for verification
        #print("Raw Output:\n", result.stdout, result.stderr)
    
        # Check if the registry key exists
        if "Cannot find path" in result.stderr:
            self.findings.append({
                "id": "2.3.11.4",
                "description": "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set correctly",
                "status": "Failed",
                "mitre_attack": "T1558.003 (Kerberoasting)",
                "severity": "High",
                "current_value": "Not Configured",
                "recommendation": "Set 'Network security: Configure encryption types allowed for Kerberos' to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' using Group Policy."
            })
            return
    
        # Extract encryption setting
        match = re.search(r"SupportedEncryptionTypes\s+:\s+(\d+)", result.stdout)
        
        if match:
            encryption_value = int(match.group(1))
    
            # Expected CIS value
            cis_expected_value = 2147483640  # As per CIS Benchmark
    
            # Check if current value matches expected value
            if encryption_value != cis_expected_value:
                self.findings.append({
                    "id": "2.3.11.4",
                    "description": "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set correctly",
                    "status": "Failed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "High",
                    "current_value": encryption_value,
                    "recommendation": "Set 'Network security: Configure encryption types allowed for Kerberos' to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' using Group Policy."
                })
            else:
                self.findings.append({
                    "id": "2.3.11.4",
                    "description": "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set correctly",
                    "status": "Passed",
                    "mitre_attack": "T1558.003 (Kerberoasting)",
                    "severity": "None",
                    "current_value": encryption_value,
                    "recommendation": "No action needed."
                })
        else:
            self.findings.append({
                "id": "2.3.11.4",
                "description": "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set correctly",
                "status": "Failed",
                "mitre_attack": "T1558.003 (Kerberoasting)",
                "severity": "High",
                "current_value": "Not Found",
                "recommendation": "Set 'Network security: Configure encryption types allowed for Kerberos' to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' using Group Policy."
            })

    def check_audit_credential_validation(self):
        """Ensure 'Audit Credential Validation' is set to 'Success and Failure'."""
        command = ['powershell', '-Command', 'auditpol /get /subcategory:"Credential Validation"']
        result = subprocess.run(command, capture_output=True, text=True, shell=False)
    
        # Debugging: Print raw output for verification
        #print("Raw Output:\n", result.stdout)
    
        # Extract the audit setting using regex
        match = re.search(r"Credential Validation\s+([A-Za-z\s]+)", result.stdout)
        if match:
            current_value = match.group(1).strip()
            if current_value != "Success":
                self.findings.append({
                    "id": "17.1.1",
                    "description": "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
                    "status": "Failed",
                    "mitre_attack": "T1110 (Brute Force)",
                    "severity": "High",
                    "current_value": current_value,
                    "recommendation": "Set 'Audit Credential Validation' to 'Success and Failure' using Group Policy or auditpol."
                })
            else:
                self.findings.append({
                    "id": "17.1.1",
                    "description": "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
                    "status": "Passed",
                    "mitre_attack": "T1110 (Brute Force)",
                    "severity": "None",
                    "current_value": current_value,
                    "recommendation": "No action needed."
                })
        else:
            self.findings.append({
                "id": "17.1.1",
                "description": "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
                "status": "Failed",
                "mitre_attack": "T1110 (Brute Force)",
                "severity": "High",
                "current_value": "Not Found",
                "recommendation": "Set 'Audit Credential Validation' to 'Success and Failure' using Group Policy or auditpol."
            })

    # def check_ldap_client_signing(self):  when clients werent being considered
    #     """Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher."""
    #     command = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP" -Name LDAPClientIntegrity']
    #     result = subprocess.run(command, capture_output=True, text=True, shell=False)
    
    #     # Debugging: Print raw output for verification
    #     #print("Raw Output:\n", result.stdout, result.stderr)
    
    #     # Check if the registry key exists
    #     if "Cannot find path" in result.stderr:
    #         self.findings.append({
    #             "id": "2.3.11.8",
    #             "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
    #             "status": "Failed",
    #             "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
    #             "severity": "High",
    #             "current_value": "Not Configured",
    #             "recommendation": "Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' (2) or 'Require signing' (3) using Group Policy or registry settings."
    #         })
    #         return
    
    #     # Extract LDAPClientIntegrity setting
    #     match = re.search(r"LDAPClientIntegrity\s+:\s+(\d+)", result.stdout)
        
    #     if match:
    #         ldap_value = int(match.group(1))
    
    #         # CIS Recommended Values
    #         if ldap_value < 2:
    #             self.findings.append({
    #                 "id": "2.3.11.8",
    #                 "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
    #                 "status": "Failed",
    #                 "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
    #                 "severity": "High",
    #                 "current_value": ldap_value,
    #                 "recommendation": "Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' (2) or 'Require signing' (3) using Group Policy or registry settings."
    #             })
    #         else:
    #             self.findings.append({
    #                 "id": "2.3.11.8",
    #                 "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
    #                 "status": "Passed",
    #                 "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
    #                 "severity": "None",
    #                 "current_value": ldap_value,
    #                 "recommendation": "No action needed."
    #             })
    #     else:
    #         self.findings.append({
    #             "id": "2.3.11.8",
    #             "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
    #             "status": "Failed",
    #             "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
    #             "severity": "High",
    #             "current_value": "Not Found",
    #             "recommendation": "Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' (2) or 'Require signing' (3) using Group Policy or registry settings."
    #         })
    
    


    def check_ldap_client_signing(self):
        """Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher."""
        # First, check the setting on the Domain Controller (DC)
        command_dc = ['powershell', '-Command', 'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP" -Name LDAPClientIntegrity']
        result_dc = subprocess.run(command_dc, capture_output=True, text=True, shell=False)

        # Debugging: Print raw output for verification
        #print("DC Raw Output:\n", result_dc.stdout, result_dc.stderr)

        # If registry key doesn't exist on DC
        if "Cannot find path" in result_dc.stderr:
            self.findings.append({
                "id": "2.3.11.8",
                "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
                "status": "Failed",
                "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
                "severity": "High",
                "current_value": "Not Configured on DC",
                "recommendation": "Enable 'Negotiate signing' (2) or 'Require signing' (3) using Group Policy."
            })

        # Get list of all clients from AD
        command_clients = ['powershell', '-Command', 'Get-ADComputer -Filter {OperatingSystem -Like \'*Windows*\'} | Select-Object -ExpandProperty Name']
        result_clients = subprocess.run(command_clients, capture_output=True, text=True, shell=False)
        client_list = result_clients.stdout.strip().split("\n")
        # Now, run the check on each client
        client_results = []
        for client in client_list:
            client = client.strip()
            if not client:
                continue
            command_client = f'powershell -Command "Invoke-Command -ComputerName {client} -ScriptBlock {{ Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP\' -Name LDAPClientIntegrity }}"'
            result_client = subprocess.run(command_client, capture_output=True, text=True, shell=False)
            # Debugging: Print raw output for verification
            #print(f"Client ({client}) Raw Output:\n", result_client.stdout, result_client.stderr)
            if "Cannot find path" in result_client.stderr:
                client_results.append({"name": client, "status": "Not Configured"})
            else:
                match = re.search(r"LDAPClientIntegrity\s+:\s+(\d+)", result_client.stdout)
                if match:
                    ldap_value = int(match.group(1))
                    if ldap_value < 2:
                        client_results.append({"name": client, "status": "Failed", "current_value": ldap_value})
                    else:
                        client_results.append({"name": client, "status": "Passed", "current_value": ldap_value})
        # Add findings for clients
        self.findings.append({
            "id": "2.3.11.8",
            "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
            "status": "Partially Passed" if any(c["status"] == "Failed" for c in client_results) else "Passed",
            "mitre_attack": "T1185 (Man-in-the-Middle - LDAP Relaying)",
            "severity": "High" if any(c["status"] == "Failed" for c in client_results) else "None",
            "affected_clients": client_results,
            "recommendation": "Ensure 'Negotiate signing' (2) or 'Require signing' (3) is enabled on all domain clients via Group Policy."
        })

    def get_checks(self):
        """Return a list of all checks in this module."""
        return [
            (self.check_kerberos_auth_service_audit, "Kerberos", "Audit Kerberos Authentication Service"),
            (self.check_kerberos_service_ticket_audit, "Kerberos", "Audit Kerberos Service Ticket Operations"),
            (self.check_kerberos_encryption_types, "Kerberos", "Kerberos Encryption Types"),
            (self.check_audit_credential_validation,"Kerberos","Ensure Credential Validation") ,
            (self.check_ldap_client_signing,"Kerberos","Ensure Network Security"),
        ]
    
    def run_all_checks(self):
        """Run all Kerberos-related checks."""
        self.check_kerberos_auth_service_audit()
        self.check_kerberos_service_ticket_audit()
        self.check_kerberos_encryption_types()
        self.check_audit_credential_validation()
        self.check_ldap_client_signing()

        return self.findings
