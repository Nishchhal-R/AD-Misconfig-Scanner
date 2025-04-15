import json
import datetime

def generate_html_report(json_data, output_file="security_report.html"):
    """Generate an HTML report with a dark theme (without charts)."""
    if not json_data:
        print("⚠️ Warning: No findings recorded. The HTML report will be empty.")
        return

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Active Directory Security Report</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #121212;
                color: #e0e0e0;
                margin: 20px;
                text-align: center;
            }}
            h2 {{
                color: #ffffff;
            }}
            .container {{
                width: 90%;
                margin: auto;
                overflow: hidden;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background: #1c1c1c;
                color: #e0e0e0;
                box-shadow: 0px 0px 10px rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                overflow: hidden;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #333;
            }}
            th {{
                background-color: #1e3a8a;
                color: white;
            }}
            .passed {{
                background-color: #28a745;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                text-align: center;
            }}
            .failed {{
                background-color: #dc3545;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                text-align: center;
            }}
            .container input {{
                width: 100%;
                padding: 10px;
                margin-top: 10px;
                border: 1px solid #444;
                border-radius: 5px;
                background-color: #1c1c1c;
                color: #e0e0e0;
            }}
        </style>
    </head>
    <body>
        <h2>Active Directory Security Scan Report</h2>
        <p><strong>Generated on:</strong> {timestamp}</p>

        <div class="container">
            <input type="text" id="searchInput" onkeyup="searchTable()" placeholder="Search for checks...">
            <table id="reportTable">
                <tr>
                    <th>Check ID</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>MITRE ATT&CK</th>
                    <th>Severity</th>
                    <th>Recommendation</th>
                </tr>
    """

    for check in json_data:
        status_class = "passed" if check["status"] == "Passed" else "failed"
        html_content += f"""
        <tr>
            <td>{check['id']}</td>
            <td>{check['description']}</td>
            <td class="{status_class}">{check['status']}</td>
            <td>{check.get('mitre_attack', 'N/A')}</td>
            <td>{check['severity']}</td>
            <td>{check['recommendation']}</td>
        </tr>
        """

    html_content += """
            </table>
        </div>

        <script>
            function searchTable() {
                let input = document.getElementById("searchInput");
                let filter = input.value.toLowerCase();
                let table = document.getElementById("reportTable");
                let rows = table.getElementsByTagName("tr");

                for (let i = 1; i < rows.length; i++) {
                    let txtValue = rows[i].textContent || rows[i].innerText;
                    rows[i].style.display = txtValue.toLowerCase().indexOf(filter) > -1 ? "" : "none";
                }
            }
        </script>
    </body>
    </html>
    """

    with open(output_file, "w") as f:
        f.write(html_content)

    print(f" Report generated: {output_file}")
