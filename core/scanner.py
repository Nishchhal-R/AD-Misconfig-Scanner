from modules.kerberos import KerberosScanner
from modules.ntlm import NTLMScanner
from modules.ldap import ldapScanner
from modules.custom import CustomScanner
from tqdm import tqdm
import time

class ADScanner:
    def __init__(self, modules_to_run=None):
        """
        Initialize the ADScanner with the specific modules to run.
        
        :param modules_to_run: List of modules to run (e.g., ['kerberos', 'ntlm']).
        """
        self.modules_to_run = modules_to_run or ["kerberos", "ntlm", "ldap", "custom"]
        self.kerberos_scanner = KerberosScanner()
        self.ntlm_scanner = NTLMScanner()
        self.ldap_scanner = ldapScanner()
        self.custom_scanner = CustomScanner()
        self.findings = []

    def run_all_checks(self):
        """Run security checks based on the specified modules."""
        if "kerberos" in self.modules_to_run:
            print("Running Kerberos checks...")
            self.findings.extend(self.kerberos_scanner.run_all_checks())
        
        if "ntlm" in self.modules_to_run:
            print("Running NTLM checks...")
            self.findings.extend(self.ntlm_scanner.run_all_checks())
        
        if "ldap" in self.modules_to_run:
            print("Running LDAP checks...")
            self.findings.extend(self.ldap_scanner.run_all_checks())
        
        if "custom" in self.modules_to_run:
            print("Running Custom checks...")
            self.findings.extend(self.custom_scanner.run_all_checks())

        return self.findings
