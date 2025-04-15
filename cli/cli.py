import argparse
import json
from core.scanner import ADScanner
from output.report_generator import generate_html_report

def main():
    parser = argparse.ArgumentParser(description="Active Directory Misconfiguration Scanner")
    parser.add_argument("--output", type=str, choices=["json", "html"], default="html", help="Output format for report")
    parser.add_argument("--modules", type=str, nargs="*", choices=["kerberos", "ntlm", "ldap", "custom", "all"], default=["all"],
                        help="Specify which modules to run (e.g., kerberos, ntlm, ldap, custom, or all for all modules). Default is 'all'.")

    args = parser.parse_args()

    # If the user chooses 'all', we can pass all modules as the default
    if "all" in args.modules:
        modules_to_run = ["kerberos", "ntlm", "ldap", "custom"]
    else:
        modules_to_run = args.modules

    scanner = ADScanner(modules_to_run=modules_to_run)
    findings = scanner.run_all_checks()

    if args.output == "json":
        # Pretty print to console
        print(json.dumps(findings, indent=4))
        
        # Save the findings to a JSON file
        with open("security_findings.json", "w") as json_file:
            json.dump(findings, json_file, indent=4)
        
        print("Findings saved as security_findings.json")
    else:
        generate_html_report(findings)

if __name__ == "__main__":
    main()
